#!/usr/bin/env bash
# 로컬 소스로 빌드한 바이너리(./build.sh 의 결과물)를 실행합니다. → http://localhost:8787
#
# 사용법:
#   ./build.sh && ./run.sh                               빌드 후 실행(Ctrl-C 로 중지)
#   ARTEX_PORT=18787 ARTEX_PROXY_PORT=18788 ./run.sh     Docker 의 artex 와 나란히 실행
#   ./run.sh -data ./data                                추가 인자는 artex 로 그대로 전달
#
# .env 의 LLM 키 등을 읽습니다. ARTEX_PG_DSN 이 없으면 개발용 Postgres 컨테이너(artex-dev-pg,
# 127.0.0.1:5433)를 띄워 씁니다. docker compose 의 DB 와 데이터는 건드리지 않습니다.
# 데이터 디렉터리는 바이너리 옆(dist/artex-<os>-<arch>/data)입니다.
set -euo pipefail
cd "$(dirname "$0")"

die() { printf '[run] %s\n' "$*" >&2; exit 1; }

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

BIN="dist/artex-$(go env GOOS)-$(go env GOARCH)/artex"
[ -x "$BIN" ] || die "실행 파일이 없습니다: $BIN (먼저 ./build.sh 를 실행하세요)"

ARTEX_PORT="${ARTEX_PORT:-8787}"
ARTEX_PROXY_PORT="${ARTEX_PROXY_PORT:-8788}"
for port in "$ARTEX_PORT" "$ARTEX_PROXY_PORT"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    die "포트 $port 가 사용 중입니다. Docker 의 artex 라면 docker compose stop artex 로 중지하거나, ARTEX_PORT / ARTEX_PROXY_PORT 로 다른 포트를 지정하세요"
  fi
done

if [ -z "${ARTEX_PG_DSN:-}" ]; then
  PG_CONTAINER=artex-dev-pg
  docker info >/dev/null 2>&1 || die "Docker 가 실행 중이 아닙니다(개발용 Postgres 에 필요합니다)"
  if ! docker container inspect "$PG_CONTAINER" >/dev/null 2>&1; then
    echo "[run] 개발용 Postgres 를 만듭니다: $PG_CONTAINER (127.0.0.1:5433)"
    docker run -d --name "$PG_CONTAINER" \
      -e POSTGRES_USER=artex -e POSTGRES_PASSWORD=artex -e POSTGRES_DB=artex \
      -v artex-dev-pgdata:/var/lib/postgresql/data \
      -p 127.0.0.1:5433:5432 postgres:16-alpine >/dev/null
  else
    docker start "$PG_CONTAINER" >/dev/null
  fi

  ready=0
  for _ in $(seq 1 30); do
    if docker exec "$PG_CONTAINER" pg_isready -U artex -d artex -h 127.0.0.1 >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [ "$ready" -eq 1 ] || die "Postgres 가 30초 안에 준비되지 않았습니다: docker logs $PG_CONTAINER"

  export ARTEX_PG_DSN='postgres://artex:artex@127.0.0.1:5433/artex?sslmode=disable'
fi

export ARTEX_SKILL_DIR="${ARTEX_SKILL_DIR:-$PWD/skills}"

echo "[run] http://localhost:$ARTEX_PORT (Ctrl-C 로 중지)"
exec "$BIN" -addr "127.0.0.1:$ARTEX_PORT" -proxy "127.0.0.1:$ARTEX_PROXY_PORT" "$@"
