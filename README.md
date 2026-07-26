# pickle-proxy-agent

Pickle(피클)은 부산대학교 구성원을 위한 셀프서비스 클라우드 플랫폼이다. 사용자가 웹 콘솔에서
VM을 신청하면 관리자 승인 후 Proxmox VE에 자동 프로비저닝되며, SSH 접속과 도메인 기반
HTTP(S) 공개까지 제공한다. 이 저장소는 그중 리버스 프록시 제어 에이전트를 담당한다.

## 역할

pickle-api가 밀어주는 "원하는 상태"(라우트와 인증서)를 받아 nginx 리버스 프록시를 그 상태에
맞게 유지하는 작은 Go 데몬이다. 요청마다 다음을 수행한다.

1. nginx vhost 설정을 렌더한다.
2. `nginx -t`로 후보 설정을 검증한다.
3. 검증을 통과하면 nginx를 reload한다.
4. 적용 결과와 인증서 상태를 보고한다.

라우팅의 진실(source of truth)은 API 서버의 데이터베이스이며, nginx 설정은 그로부터 파생된
산출물이다. 모든 변경은 단일 직렬 큐를 통해 한 번에 하나씩(render → `nginx -t` → 원자적 교체
→ reload) 처리되고, 어떤 단계라도 실패하면 직전 파일 상태로 롤백하므로 실패한 적용이 살아 있는
설정을 훼손하지 않는다.

인증서는 두 갈래로 구분한다.

- **플랫폼 서브도메인**: 플랫폼 와일드카드 인증서(Cloudflare Origin CA)를 사용한다.
- **사용자 커스텀 도메인**: 도메인별 Let's Encrypt 인증서를 certbot(HTTP-01, webroot)으로
  발급/갱신한다. 발급 전에는 챌린지 전용 vhost를 먼저 올리고, 인증서가 준비되면 정식 HTTPS
  vhost로 전환하는 2단계 렌더를 쓴다. 발급 실패는 적용을 실패시키지 않고 `/status`에 노출된다.

에이전트는 자신이 관리하는 vhost 파일(FQDN당 한 개)만 소유하며 nginx 트리의 다른 부분은 절대
건드리지 않는다.

## 계약 표면

에이전트는 `172.30.1.10:9443`(내부 vmbr1 주소, 평문 HTTP)에 바인드한다. 이 주소로 향하는
DNAT은 없으므로 외부에서는 도달할 수 없고, 내부 브리지 전용으로만 다음 세 개의 엔드포인트를
제공한다.

- `POST /apply` — 단일 FQDN의 원하는 상태 전체를 받아 vhost를 렌더/삭제한다. FQDN별 단조
  증가 `generation`을 영속화하여, 이미 적용된 세대 이하의 요청은 no-op(`409`)으로 처리한다.
- `POST /sync-all` — 전체 스냅샷을 받아 세트를 통째로 다시 렌더하고, 매니페스트에 없는
  에이전트 관리 vhost는 정리(prune)한다.
- `GET /status` — 헬스, 마지막 apply/sync, FQDN별 적용 세대, 커스텀 도메인 인증서 상태.

모든 라우트는 fail-closed로 보호된다. 공유 bearer 토큰(`PICKLE_PROXY_AGENT_TOKEN`)과
소스 IP 허용 목록(`PICKLE_PROXY_AGENT_ALLOWED_SRC`)을 모두 통과해야 하며, 내부 브리지에서만
접근할 수 있다. 토큰이 비어 있으면 부팅이 거부되고, 템플릿 자리표시자 값
(`CHANGEME` / 과거 deploy 스크립트가 남긴 오타 `CHANGME`)도 같은 이유로 거부된다.
잘 알려진 토큰은 토큰이 없는 것과 다름없기 때문이다.

## 스택

- Go 1.26 (`go.mod` 참고)
- 표준 라이브러리만 사용, 외부 의존성 0

## 레이아웃

```
cmd/proxy-agent/      진입점 (env 설정 → 조립 → 서비스)
internal/config/      env 기반 설정 (토큰이 비어 있으면 fail-closed)
internal/model/       pickle-api와 공유하는 wire 타입 (고정된 계약 형태)
internal/render/      vhost 템플릿 렌더 + 입력 검증 (타깃은 사용자 VM 네트워크 내부만 허용)
internal/nginx/       `nginx -t` / `nginx -s reload` 러너 (인터페이스 + exec 구현)
internal/certbot/     webroot HTTP-01 발급 (인터페이스 + certbot exec 구현)
internal/state/       FQDN별 세대 + 인증서 상태, JSON 영속화
internal/manager/     직렬화된 apply/sync-all: render→test→swap→reload→rollback
internal/server/      HTTP 서버, fail-closed 인증, 키별 레이트 리밋
internal/fake/        nginx/certbot 테스트 더블 (데몬 빌드에는 포함되지 않음)
scripts/              verify.sh, deploy.sh, systemd 유닛, nginx 베이스 설정
```

## 빌드 & 검증

```bash
scripts/setup-hooks.sh   # 최초 1회: git 훅 설치
scripts/verify.sh        # shellcheck → gofmt → go vet → go build → go test
```

`verify.sh`가 `gofmt -l`을 하드 게이트로 실행하므로 코드는 항상 gofmt 정렬 상태로 유지된다.

## 배포

배포는 `scripts/deploy.sh`로 수행한다. 자동 실행되지 않으며, 대상 호스트에 SSH로 닿을 수 있는
빌드 호스트에서 의도적으로 실행한다. 정적 linux/amd64 바이너리를 크로스 컴파일해
`/usr/local/bin/pickle-proxy-agent`에 설치하고, systemd 유닛과 베이스 nginx 설정
(`scripts/nginx/pickle-base.conf` → `/etc/nginx/conf.d/`)을 함께 배치한다. 멱등이므로
재실행하면 바이너리를 교체하고 서비스를 재시작한다.

**환경 파일과 토큰**: 유닛은 `/etc/pickle-proxy-agent/agent.env`(모드 0600, root)를
`EnvironmentFile`로 읽는다. 이 파일이 없으면 배포 스크립트가 **대상 호스트에서**
`openssl rand -hex 32`로 토큰을 생성해 새로 쓴다(기존 파일은 절대 덮어쓰지 않는다). 최초
설치라면 생성된 `PICKLE_PROXY_AGENT_TOKEN` 값을 **직접 API 쪽 환경으로 복사해야** 하며,
그러지 않으면 pickle-api의 호출이 전부 401로 거부된다. 토큰 보관 위치는 운영 시크릿 저장소에
기록한다.

**와일드카드 인증서 경로 오버라이드는 필수다.** 코드 기본값은
`/etc/nginx/certs/origin/{fullchain,privkey}.pem`이지만 실제 배포 경로는
`/etc/nginx/pickle-certs/origin.{crt,key}`다. 오버라이드 없이 뜨면 렌더된 vhost가 존재하지
않는 인증서 파일을 가리켜 `nginx -t`가 실패한다. 그래서 배포 스크립트가 생성하는 `agent.env`는
`PICKLE_PROXY_AGENT_WILDCARD_CERT`/`_KEY`를 실제 경로로 함께 써 준다. `agent.env`를 손으로
만든다면 이 두 줄을 반드시 포함해야 한다.

**certbot 갱신 훅**: 배포 스크립트는
`/etc/letsencrypt/renewal-hooks/deploy/pickle-nginx-reload.sh`도 설치한다. certbot의 타이머가
인증서를 갱신해도 nginx는 reload 전까지 옛 파일을 계속 서빙하므로, 갱신 성공 후에만 도는
deploy-hook에서 `systemctl reload nginx`를 실행해 갱신된 커스텀 도메인 인증서가 즉시
반영되게 한다.

### 대상 호스트 사전 조건

배포 스크립트가 만들어 주지 않는, 운영자가 미리 갖춰야 하는 것들이다.

- **nginx**가 설치돼 있고, `http{}` 컨텍스트에서 `/etc/nginx/conf.d/pickle-base.conf`를
  읽어 `include /etc/nginx/pickle.d/*.conf`가 유효해야 한다(베이스 설정 자체가 이 include를
  담고 있다).
- **`$pickle_client_ip`** 변수가 `http{}` 컨텍스트에 정의돼 있어야 한다. `$connection_upgrade`는
  베이스 설정이 제공하지만 이 변수는 운영자가 정의한다(정의 예시와 이유는
  `scripts/nginx/pickle-base.conf`의 주석 참고). TLS를 종단하는 스트림 계층이 PROXY 헤더로
  실제 피어를 전달하므로 vhost는 `real_ip_header proxy_protocol`로 원 클라이언트 주소를
  복원하고, `$pickle_client_ip`가 그 피어의 CDN 클라이언트 IP 헤더를 신뢰할지 결정한다.
  두 변수 중 하나라도 없으면 첫 렌더에서 `nginx -t`가 실패한다.
- **certbot** 설치. 커스텀 도메인의 HTTP-01 발급·갱신에 쓰인다.
- nginx의 **`worker_shutdown_timeout`** 설정. reload 시 옛 워커가 무한정 남지 않게 한다.
- Origin CA 와일드카드 인증서가 `/etc/nginx/pickle-certs/origin.{crt,key}`에 있을 것.

## 환경 변수 (`/etc/pickle-proxy-agent/agent.env`)

시크릿 값은 이 저장소에 포함되지 않는다. 토큰을 제외한 모든 값은 as-built 배포 레이아웃에
맞는 기본값을 가진다.

| 변수 | 의미 | 기본값 |
|---|---|---|
| `PICKLE_PROXY_AGENT_TOKEN` | 공유 bearer 토큰. 빈 값과 자리표시자(`CHANGEME`/`CHANGME`)는 부팅 거부 | 없음 (**필수**) |
| `PICKLE_PROXY_AGENT_LISTEN` | HTTP 제어 서버 바인드 주소 | `172.30.1.10:9443` |
| `PICKLE_PROXY_AGENT_ALLOWED_SRC` | 호출을 허용할 소스 IP 목록(쉼표 구분). 빈 집합은 전원 거부(fail-closed) | `172.30.1.20` (pickle-api) |
| `PICKLE_PROXY_AGENT_NGINX_DIR` | 에이전트가 소유하는 include 디렉터리. 이 안의 `*.conf`만 건드린다 | `/etc/nginx/pickle.d` |
| `PICKLE_PROXY_AGENT_STATE_FILE` | FQDN별 마지막 적용 세대와 인증서 상태의 JSON 영속 파일 | `/var/lib/pickle-proxy-agent/state.json` |
| `PICKLE_PROXY_AGENT_NGINX_BIN` | `nginx -t` / `nginx -s reload`에 쓸 바이너리 | `nginx` |
| `PICKLE_PROXY_AGENT_WILDCARD_CERT` | 플랫폼 와일드카드(Origin CA) 인증서 체인. **실배포에서는 오버라이드 필수** | `/etc/nginx/certs/origin/fullchain.pem` |
| `PICKLE_PROXY_AGENT_WILDCARD_KEY` | 플랫폼 와일드카드 개인키. **실배포에서는 오버라이드 필수** | `/etc/nginx/certs/origin/privkey.pem` |
| `PICKLE_PROXY_AGENT_HTTPS_LISTEN` | 종단된 vhost의 내부 HTTPS 리슨 주소(`stream{}`이 :443을 소유하고 비-passthrough SNI를 여기로 넘긴다) | `127.0.0.1:8443` |
| `PICKLE_PROXY_AGENT_CERTBOT_BIN` | certbot 바이너리 | `certbot` |
| `PICKLE_PROXY_AGENT_WEBROOT` | HTTP-01 챌린지 webroot | `/var/www/certbot` |
| `PICKLE_PROXY_AGENT_LE_DIR` | Let's Encrypt live 디렉터리(`<fqdn>/{fullchain,privkey}.pem`) | `/etc/letsencrypt/live` |
| `PICKLE_PROXY_AGENT_CERTBOT_EMAIL` | certbot 등록 이메일 | 빈 값 |

## 커밋 규약

커밋 메시지는 `type: subject` 형식(영어 명령형, 72자 이내, 마침표 없음)을 따르며 git 훅이
이를 강제한다. type은 `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`,
`build`, `style`, `ci`, `revert`, `merge` 중 하나다.
