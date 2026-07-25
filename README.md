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

내부 브리지 전용으로만 도달 가능한 세 개의 엔드포인트를 제공한다.

- `POST /apply` — 단일 FQDN의 원하는 상태 전체를 받아 vhost를 렌더/삭제한다. FQDN별 단조
  증가 `generation`을 영속화하여, 이미 적용된 세대 이하의 요청은 no-op(`409`)으로 처리한다.
- `POST /sync-all` — 전체 스냅샷을 받아 세트를 통째로 다시 렌더하고, 매니페스트에 없는
  에이전트 관리 vhost는 정리(prune)한다.
- `GET /status` — 헬스, 마지막 apply/sync, FQDN별 적용 세대, 커스텀 도메인 인증서 상태.

모든 라우트는 fail-closed로 보호된다. 공유 bearer 토큰(`PICKLE_PROXY_AGENT_TOKEN`,
미설정 시 부팅이 fail-closed)과 소스 IP 허용 목록을 모두 통과해야 하며, 내부 브리지에서만
접근할 수 있다.

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
scripts/verify.sh        # shellcheck → go vet → go build → go test
```

배포는 `scripts/deploy.sh`로 수행한다(빌드 후 대상 호스트에 바이너리/유닛/베이스 nginx 설정
설치). 코드는 항상 gofmt 정렬 상태를 유지한다.

렌더된 vhost는 nginx `http{}` 컨텍스트에 `$connection_upgrade`와 `$pickle_client_ip`
두 변수가 정의돼 있어야 한다. 전자는 `scripts/nginx/pickle-base.conf`가 제공하고 후자는
운영자가 정의한다(정의 예시와 이유는 같은 파일의 주석 참고). TLS를 종단하는 스트림 계층이
PROXY 헤더로 실제 피어를 전달하므로 vhost는 `real_ip_header proxy_protocol`로 원 클라이언트
주소를 복원하고, `$pickle_client_ip`가 그 피어의 CDN 클라이언트 IP 헤더를 신뢰할지 결정한다.
둘 중 하나라도 없으면 첫 렌더에서 `nginx -t`가 실패한다.

## 커밋 규약

커밋 메시지는 `type: subject` 형식(영어 명령형, 72자 이내, 마침표 없음)을 따르며 git 훅이
이를 강제한다. type은 `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`,
`build`, `style`, `ci`, `revert`, `merge` 중 하나다.
