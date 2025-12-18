#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
ADMIN_GATEWAY_URL="${ADMIN_GATEWAY_URL:-http://localhost:9090}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-30}"
DEBUG="${DEBUG:-0}"
MISMATCHES_OUT="${MISMATCHES_OUT:-}"
STATS_OUT="${STATS_OUT:-}"
CHECKLIST_OUT="${CHECKLIST_OUT:-}"

SERVICE_NAME="ms-go-rbac"

export GATEWAY_URL ADMIN_GATEWAY_URL HTTP_TIMEOUT DEBUG MISMATCHES_OUT STATS_OUT CHECKLIST_OUT

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
NC=$'\033[0m'

append_check() { [[ -n "${CHECKLIST_OUT}" ]] && echo "$1" >>"${CHECKLIST_OUT}"; }

sanitize_evidence() {
  local evidence="$1"
  if [[ "${evidence}" == *"resp=<html"* || "${evidence}" == *"resp=<HTML"* ]]; then
    echo "${evidence%%resp=*}resp=[HTML omitted]"
    return 0
  fi
  echo "${evidence}" | sed -E 's/<[^>]+>//g' | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g'
}

suggest_fixes() {
  local observed="$1"
  if [[ "${observed}" == *"admin gateway"* ]]; then
    cat <<'EOF'
  - В `ms-getway/templates/admin-getway.conf.template` для RBAC переписать rewrite на `/admin/v1` (сейчас `/api/admin/v1`), либо добавить в `ms-go-rbac` алиас `/api/admin/v1`.
EOF
    return 0
  fi
  cat <<'EOF'
  - Сверить пути wiki/реализации и поправить wiki или API.
EOF
}

record_ok() {
  E2E_OK=$((E2E_OK + 1))
  echo "${GREEN}✓${NC} $1"
  append_check "- ✅ [${SERVICE_NAME}/${E2E_SCENARIO:-unknown}] $1"
}

record_mismatch() {
  local wiki_ref="$1" expected="$2" observed="$3" evidence="$4" severity="$5" fix_repo="$6"
  E2E_MISMATCHES=$((E2E_MISMATCHES + 1))
  echo "${RED}✗${NC} (${severity}) ${wiki_ref} | ${expected} → ${observed}"
  append_check "- ❌ [${SERVICE_NAME}/${E2E_SCENARIO:-unknown}] ${wiki_ref} — ${expected} → ${observed}"
  if [[ -n "${MISMATCHES_OUT}" ]]; then
    evidence="$(sanitize_evidence "${evidence}")"
    {
      echo ""
      echo "## $(date +%Y%m%d-%H%M%S). ${SERVICE_NAME}: ${wiki_ref}"
      echo "- Компонент: ${SERVICE_NAME}"
      echo "- Wiki: \`${wiki_ref}\`"
      echo "- Ожидание (wiki): ${expected}"
      echo "- Наблюдение (факт): ${observed}"
      echo "- Доказательство: ${evidence}"
      echo "- Severity: ${severity}"
      echo "- Куда фиксить: ${fix_repo}"
      echo "- Варианты решения:"
      suggest_fixes "${observed}"
    } >>"${MISMATCHES_OUT}"
  fi
}

http_json() {
  local base="$1" method="$2" path="$3" body="${4:-}"
  local tmp code
  tmp="$(mktemp)"
  code="$(curl -sS --max-time "${HTTP_TIMEOUT}" -o "${tmp}" -w "%{http_code}" -X "${method}" -H "Content-Type: application/json" -d "${body}" "${base}${path}" || true)"
  cat "${tmp}"; rm -f "${tmp}"
  echo ""; echo "__HTTP_STATUS__=${code}"
}
http_get() {
  local base="$1" path="$2"
  local tmp code
  tmp="$(mktemp)"
  code="$(curl -sS --max-time "${HTTP_TIMEOUT}" -o "${tmp}" -w "%{http_code}" "${base}${path}" || true)"
  cat "${tmp}"; rm -f "${tmp}"
  echo ""; echo "__HTTP_STATUS__=${code}"
}
extract_status(){ awk -F= '/^__HTTP_STATUS__=/{print $2}'; }
extract_body(){ sed '/^__HTTP_STATUS__=/d'; }

run_scenarios() {
  local failed=0
  for scenario in "${SCRIPT_DIR}/scenarios"/*.sh; do
    [[ -f "${scenario}" ]] || continue
    export E2E_SCENARIO
    E2E_SCENARIO="$(basename "${scenario}")"
    # shellcheck disable=SC1090
    if source "${scenario}"; then :; else failed=$((failed+1)); fi
  done
  return "${failed}"
}

export -f record_ok record_mismatch http_json http_get extract_status extract_body

main() {
  E2E_OK=0
  E2E_MISMATCHES=0

  local failed=0
  if run_scenarios; then failed=0; else failed=$?; fi

  if [[ -n "${STATS_OUT}" ]]; then
    printf "%s ok=%s mismatches=%s\n" "${SERVICE_NAME}" "${E2E_OK}" "${E2E_MISMATCHES}" >>"${STATS_OUT}"
  fi

  [[ "${failed}" -eq 0 ]]
}

main "$@"
