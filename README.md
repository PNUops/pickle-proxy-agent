# pickle-proxy-agent

**Pickle(피클)** 은 부산대학교 구성원을 위한 셀프서비스 클라우드 플랫폼입니다.
사용자가 신청하고 관리자가 승인한 VM을 Proxmox VE 위에 자동 프로비저닝하고,
SSH·웹 터미널 접속과 도메인 기반 HTTP(S) 게시를 제공합니다.

이 저장소는 그중 **HTTP(S) 게시를 담당하는 리버스 프록시 제어 에이전트**입니다.
리버스 프록시 호스트 안에서 동작하는 작은 Go 데몬으로, pickle-api가 푸시하는
원하는 라우팅 상태(desired state)를 실제 nginx vhost와 TLS 인증서로 반영합니다.
라우팅의 진실은 PostgreSQL에 있고, nginx 설정은 파생 산출물입니다.

## pickle-api와의 내부 계약

세 엔드포인트 모두 공유 Bearer 토큰(`PICKLE_PROXY_AGENT_TOKEN`)과 소스 IP
허용목록(기본: pickle-api)을 요구하며, 전부 fail-closed입니다. 내부 브리지에서만
접근 가능합니다.

- `POST /apply`: FQDN 하나의 전체 원하는 상태
  `{fqdn, desiredState: PRESENT|ABSENT, generation, targetIp, targetPort, certRef}`.
  vhost를 렌더링/제거하고 `nginx -t` 검증 후 reload합니다. FQDN별 단조 증가
  `generation`을 영속화해 `generation ≤ applied`인 요청은 `409` no-op으로
  처리하므로, 늦게 도착한 재시도가 재사용된 IP 위에 옛 vhost를 되살릴 수
  없습니다. `200 {applied, generation}` / `409`(stale) / `422 {applied:false, error}`.
- `POST /sync-all`: 권위 있는 전체 스냅샷 `{snapshotGeneration, routes[]}`.
  전체 셋을 렌더링하고 `nginx -t` 후 원자적으로 교체하며, 매니페스트에 없는
  에이전트 관리 vhost 파일을 **정리(prune)**하고 reload합니다.
- `GET /status`: 헬스, 마지막 apply/sync, FQDN별 적용 generation,
  커스텀 도메인 인증서 상태(발급/갱신 실패가 여기로 표면화).

에이전트는 정확히 `/etc/nginx/pickle.d/*.conf`(FQDN당 1파일)만 소유하며 nginx
트리의 다른 어떤 것도 건드리지 않습니다. 모든 변경은 단일 직렬화 큐를 통과해 한 번에 하나의 렌더 → `nginx -t` → 교체 → reload 사이클만 수행하며, 실패하면
이전 파일 상태로 복원하므로 실패한 apply는 라이브 설정을 그대로 남깁니다.

## 템플릿과 인증서

vhost 형태는 두 가지입니다:

- **플랫폼 서브도메인** (`certRef == origin-wildcard`): Cloudflare Origin CA
  와일드카드 인증서를 사용하는 내부 `127.0.0.1:8443` HTTPS 계층.
- **커스텀 도메인** (그 외 `certRef`): 도메인별 Let's Encrypt 인증서. 렌더링은
  2단계입니다. certbot(webroot HTTP-01)이 인증서를 발급할 때까지 challenge 전용 `:80`
  vhost, 발급 후 `:80` 리다이렉트 + `:8443` HTTPS vhost. 발급 실패는 `/status`로
  보고되며 apply를 실패시키지 않습니다. 갱신은 certbot systemd 타이머로 돌고,
  `scripts/deploy.sh`가 갱신 성공 시 nginx를 reload하는 deploy-hook을 설치해
  갱신된 인증서가 즉시 반영됩니다.

두 형태 모두 `http://<vm-ip>:<port>`로 proxy_pass하며, websocket 업그레이드를
지원하는 공유 프록시 스니펫(`Connection $connection_upgrade` 맵)을 사용합니다.

## 레이아웃

```
cmd/proxy-agent/      엔트리포인트 (env 설정 → 조립 → serve)
internal/config/      환경변수 설정 (토큰 비어 있으면 fail-closed)
internal/model/       pickle-api와 공유하는 와이어 타입 (계약 형태 고정)
internal/render/      vhost 템플릿 렌더링 + 입력 검증
internal/nginx/       `nginx -t` / `nginx -s reload` 러너 (인터페이스 + exec 구현)
internal/certbot/     webroot HTTP-01 발급 (인터페이스 + certbot exec 구현)
internal/state/       FQDN별 generation + 인증서 상태, JSON 영속화
internal/manager/     직렬화 apply/sync-all: render→test→swap→reload→rollback
internal/server/      HTTP 서버, fail-closed 인증, 키별 레이트 리밋
internal/fake/        nginx/certbot 테스트 더블 (데몬에는 컴파일되지 않음)
scripts/deploy.sh     바이너리/유닛/기본 nginx 설정 설치 스크립트
```

## 빌드와 검증

```bash
scripts/setup-hooks.sh   # 최초 1회: git hook 설치
scripts/verify.sh        # shellcheck + go vet + go build + go test
```

Go 1.26, 표준 라이브러리만 사용(서드파티 의존성 없음).

## Pickle 저장소 구성

| 저장소 | 역할 |
|---|---|
| [pickle-api](https://github.com/PNUops/pickle-api) | 백엔드 REST API, 프로비저닝 파이프라인, 접속 인가 |
| [pickle-console](https://github.com/PNUops/pickle-console) | 웹 콘솔 (사용자·관리자 SPA) |
| [pickle-sshgw](https://github.com/PNUops/pickle-sshgw) | SSH 게이트웨이 + 웹 터미널 브리지 |
| [pickle-proxy-agent](https://github.com/PNUops/pickle-proxy-agent) | HTTP(S) 게시용 리버스 프록시 제어 에이전트 |
| [pickle-infra](https://github.com/PNUops/pickle-infra) | 인프라 프로비저닝 스크립트·런북 |
