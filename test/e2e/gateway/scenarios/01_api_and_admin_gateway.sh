#!/usr/bin/env bash
set -euo pipefail

RBAC_API="/api/rbac/v1"
wiki_ref="wiki/RBAC.md"

user_id="e2e-user-$(date +%s)"

assign_body="$(jq -nc --arg uid "${user_id}" --arg role "student" '{value:{user_id:$uid,role:$role}}')"
raw="$(http_json "${GATEWAY_URL}" "POST" "${RBAC_API}/assign_role" "${assign_body}")"
st="$(printf '%s\n' "${raw}" | extract_status)"
resp="$(printf '%s\n' "${raw}" | extract_body)"
if [[ "${st}" != "200" ]]; then
  record_mismatch "${wiki_ref} (assign_role)" "HTTP 200" "HTTP ${st}" "POST ${RBAC_API}/assign_role resp=${resp}" "major" "ms-go-rbac/ms-getway"
  return 0
fi
record_ok "rbac assign_role returns 200"

raw="$(http_get "${GATEWAY_URL}" "${RBAC_API}/get_role_by_user_id?user_id=${user_id}")"
st="$(printf '%s\n' "${raw}" | extract_status)"
resp="$(printf '%s\n' "${raw}" | extract_body)"
if [[ "${st}" != "200" ]]; then
  record_mismatch "${wiki_ref} (get_role_by_user_id)" "HTTP 200" "HTTP ${st}" "GET ${RBAC_API}/get_role_by_user_id resp=${resp}" "major" "ms-go-rbac/ms-getway"
  return 0
fi
record_ok "rbac get_role_by_user_id returns 200"

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
