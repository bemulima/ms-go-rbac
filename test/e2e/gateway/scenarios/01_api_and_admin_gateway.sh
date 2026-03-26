#!/usr/bin/env bash
set -euo pipefail

RBAC_API="/api/rbac/v1"
wiki_ref="wiki/RBAC.md"

user_id="11111111-1111-1111-1111-$(printf '%012d' "$((10#$(date +%S)))")"

assign_body="$(jq -nc --arg uid "${user_id}" --arg role "student" '{value:{user_id:$uid,role:$role}}')"
raw="$(http_json "${GATEWAY_URL}" "PATCH" "${RBAC_API}/principal-role/update" "${assign_body}")"
st="$(printf '%s\n' "${raw}" | extract_status)"
resp="$(printf '%s\n' "${raw}" | extract_body)"
if [[ "${st}" != "200" ]]; then
  record_mismatch "${wiki_ref} (principal-role/update)" "HTTP 200" "HTTP ${st}" "PATCH ${RBAC_API}/principal-role/update resp=${resp}" "major" "ms-go-rbac/ms-getway"
  return 0
fi
record_ok "rbac principal-role/update returns 200"

raw="$(http_get "${GATEWAY_URL}" "${RBAC_API}/principal-role/get?user_id=${user_id}")"
st="$(printf '%s\n' "${raw}" | extract_status)"
resp="$(printf '%s\n' "${raw}" | extract_body)"
if [[ "${st}" != "200" ]]; then
  record_mismatch "${wiki_ref} (principal-role/get)" "HTTP 200" "HTTP ${st}" "GET ${RBAC_API}/principal-role/get resp=${resp}" "major" "ms-go-rbac/ms-getway"
  return 0
fi
record_ok "rbac principal-role/get returns 200"

# Admin gateway route check (likely mismatch due to rewrite).
admin_raw="$(http_get "${ADMIN_GATEWAY_URL}" "${RBAC_API}/service-list?page=1&page_size=1")"
admin_st="$(printf '%s\n' "${admin_raw}" | extract_status)"
admin_resp="$(printf '%s\n' "${admin_raw}" | extract_body)"
if [[ "${admin_st}" != "200" ]]; then
  record_mismatch "${wiki_ref} (admin gateway)" "HTTP 200 admin service-list" "HTTP ${admin_st} (admin gateway)" "GET ${ADMIN_GATEWAY_URL}${RBAC_API}/service-list resp=${admin_resp}" "minor" "ms-getway/ms-go-rbac"
else
  record_ok "rbac admin service-list reachable via admin gateway"
fi

return 0
