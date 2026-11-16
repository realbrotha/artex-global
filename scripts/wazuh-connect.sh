#!/usr/bin/env bash
# Thaki-Siem runner 가 쓰던 Wazuh 접속 환경을 ARTEX 의 Wazuh 연결로 등록한다.
#
#   scripts/wazuh-connect.sh [연결 이름]          (기본 이름: wazuh)
#
# 하는 일 (Thaki-Siem 의 SIEM Assessment 워크플로와 같은 경로):
#   1. kubectl port-forward 로 manager API(55000) · indexer(9200) 를 로컬에 연다
#   2. 읽기 전용 계정의 비밀번호를 클러스터 Secret 에서 읽는다
#        manager API : Secret siem-api-reader  (username/password)
#        indexer     : Secret siem-llm-reader  (password, 계정명 = Secret 이름)
#   3. `artex -wazuh-import` 로 연결 테스트 후 암호화 저장한다
#   4. port-forward 를 유지한다 (Ctrl-C 로 종료). ARTEX 서버는 5분마다 동기화한다
#
# 비밀번호는 환경 변수로만 전달하고 화면·로그·파일에 남기지 않는다.
#
# 환경 변수:
#   KUBE_CONTEXT   kubectl context (기본: 현재 context)
#   WAZUH_NS       namespace (기본: wazuh)
#   API_PORT       로컬 manager API 포트 (기본: 55000)
#   IX_PORT        로컬 indexer 포트 (기본: 9200)
#   API_SECRET     manager API 계정 Secret (기본: siem-api-reader)
#   IX_SECRET      indexer 계정 Secret (기본: siem-llm-reader)
#   NO_INDEXER=1   indexer 없이 agent 목록만 연결
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-wazuh}"
NS="${WAZUH_NS:-wazuh}"
API_PORT="${API_PORT:-55000}"
IX_PORT="${IX_PORT:-9200}"
API_SECRET="${API_SECRET:-siem-api-reader}"
IX_SECRET="${IX_SECRET:-siem-llm-reader}"
K=(kubectl ${KUBE_CONTEXT:+--context "$KUBE_CONTEXT"} -n "$NS")

die() { printf '[wazuh-connect] %s\n' "$*" >&2; exit 1; }
secret() { "${K[@]}" get secret "$1" -o "jsonpath={.data.$2}" | base64 -d; }

command -v kubectl >/dev/null || die "kubectl 이 없습니다"
"${K[@]}" get pod wazuh-manager-master-0 >/dev/null 2>&1 || die "wazuh-manager-master-0 조회 실패 — kube context · namespace($NS) 확인"
"${K[@]}" get secret "$API_SECRET" >/dev/null 2>&1 || die "Secret $API_SECRET 없음 (Thaki-Siem assess/create-api-reader.sh 로 생성)"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

wait_port() {
  for _ in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  die "포트 $1 port-forward 가 열리지 않았습니다"
}

"${K[@]}" port-forward pod/wazuh-manager-master-0 "$API_PORT:55000" >/dev/null 2>&1 &
PIDS+=($!)
wait_port "$API_PORT"

export ARTEX_WAZUH_NAME="$NAME"
export ARTEX_WAZUH_MANAGER_URL="https://localhost:$API_PORT"
# port-forward 뒤의 클러스터 내부 인증서는 localhost 이름과 맞지 않는다.
export ARTEX_WAZUH_TLS_SKIP_VERIFY=true
ARTEX_WAZUH_MANAGER_USER="$(secret "$API_SECRET" username)"
ARTEX_WAZUH_MANAGER_PASSWORD="$(secret "$API_SECRET" password)"
export ARTEX_WAZUH_MANAGER_USER ARTEX_WAZUH_MANAGER_PASSWORD

if [ "${NO_INDEXER:-}" != "1" ]; then
  "${K[@]}" get secret "$IX_SECRET" >/dev/null 2>&1 || die "Secret $IX_SECRET 없음 (indexer 없이 연결하려면 NO_INDEXER=1)"
  "${K[@]}" port-forward svc/indexer "$IX_PORT:9200" >/dev/null 2>&1 &
  PIDS+=($!)
  wait_port "$IX_PORT"
  export ARTEX_WAZUH_INDEXER_URL="https://localhost:$IX_PORT"
  export ARTEX_WAZUH_INDEXER_USER="$IX_SECRET"
  ARTEX_WAZUH_INDEXER_PASSWORD="$(secret "$IX_SECRET" password)"
  export ARTEX_WAZUH_INDEXER_PASSWORD
fi

go run ./cmd/artex -wazuh-import

unset ARTEX_WAZUH_MANAGER_PASSWORD ARTEX_WAZUH_INDEXER_PASSWORD
printf '[wazuh-connect] port-forward 유지 중 — manager API :%s' "$API_PORT"
[ "${NO_INDEXER:-}" = "1" ] || printf ' · indexer :%s' "$IX_PORT"
printf ' (Ctrl-C 로 종료)\n'
wait
