#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://iam.mfu.ac.th/api/v1}"
X_ACCESS_TOKEN="${X_ACCESS_TOKEN:-}"
MEMBER_ID="${MEMBER_ID:-}"
STATUS_TYPE_ID="${STATUS_TYPE_ID:-}"
APPROVAL_STATUS_ID="${APPROVAL_STATUS_ID:-}"

if [[ -n "${1:-}" ]]; then BASE_URL="$1"; fi
if [[ -n "${2:-}" ]]; then X_ACCESS_TOKEN="$2"; fi
if [[ -n "${3:-}" ]]; then MEMBER_ID="$3"; fi
if [[ -n "${4:-}" ]]; then STATUS_TYPE_ID="$4"; fi
if [[ -n "${5:-}" ]]; then APPROVAL_STATUS_ID="$5"; fi

if [[ -z "$X_ACCESS_TOKEN" ]]; then
  echo "Usage:"
  echo "  X_ACCESS_TOKEN='<token>' $0 [BASE_URL] [X_ACCESS_TOKEN] [MEMBER_ID] [STATUS_TYPE_ID] [APPROVAL_STATUS_ID]"
  exit 1
fi

json_get() {
  node -e "
    const obj = JSON.parse(process.argv[1]);
    const path = process.argv[2].split('.');
    let cur = obj;
    for (const p of path) cur = cur?.[p];
    if (cur === undefined || cur === null) process.exit(2);
    process.stdout.write(String(cur));
  " "$1" "$2"
}

json_first_status_id() {
  node -e "
    const obj = JSON.parse(process.argv[1]);
    const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
    if (!list.length || !list[0]?._id) process.exit(2);
    process.stdout.write(String(list[0]._id));
  " "$1"
}

http_get() {
  curl -sS -w "\n%{http_code}" -X GET "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN"
}

http_post() {
  curl -sS -w "\n%{http_code}" -X POST "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "$2"
}

http_put() {
  curl -sS -w "\n%{http_code}" -X PUT "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "$2"
}

http_delete() {
  curl -sS -w "\n%{http_code}" -X DELETE "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "$2"
}

split_response() {
  local raw="$1"
  HTTP_BODY="$(printf "%s" "$raw" | sed '$d')"
  HTTP_CODE="$(printf "%s" "$raw" | tail -n 1)"
}

today="$(date +%F)"
from_date="$(date -v+60d +%F 2>/dev/null || date -d '+60 day' +%F)"
to_date="$(date -v+70d +%F 2>/dev/null || date -d '+70 day' +%F)"
update_from="$(date -v+71d +%F 2>/dev/null || date -d '+71 day' +%F)"
update_to="$(date -v+80d +%F 2>/dev/null || date -d '+80 day' +%F)"

echo "==> Resolve member id"
if [[ -z "$MEMBER_ID" ]]; then
  ME_RAW="$(http_get "$BASE_URL/auth/me")"
  split_response "$ME_RAW"
  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "Failed /auth/me (HTTP $HTTP_CODE)"
    echo "$HTTP_BODY"
    exit 2
  fi
  MEMBER_ID="$(json_get "$HTTP_BODY" "data._id")"
fi
APPROVER_ID="$MEMBER_ID"
echo "Member/Approver: $MEMBER_ID"

echo "==> Resolve status ids"
if [[ -z "$STATUS_TYPE_ID" || -z "$APPROVAL_STATUS_ID" ]]; then
  STATUS_RAW="$(http_get "$BASE_URL/setting/status?state=true")"
  split_response "$STATUS_RAW"
  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "Failed /setting/status (HTTP $HTTP_CODE)"
    echo "$HTTP_BODY"
    exit 3
  fi
  FIRST_STATUS_ID="$(json_first_status_id "$HTTP_BODY")"
  [[ -z "$STATUS_TYPE_ID" ]] && STATUS_TYPE_ID="$FIRST_STATUS_ID"
  [[ -z "$APPROVAL_STATUS_ID" ]] && APPROVAL_STATUS_ID="$FIRST_STATUS_ID"
fi
echo "statusType: $STATUS_TYPE_ID"
echo "approvalStatus: $APPROVAL_STATUS_ID"

echo "==> 1) Create timeline"
CREATE_BODY="$(cat <<JSON
{
  "member":"$MEMBER_ID",
  "statusType":"$STATUS_TYPE_ID",
  "title":[{"key":"th","value":"Smoke Timeline $today"}],
  "reason":[{"key":"th","value":"Automated test"}],
  "effective":{"from":"$from_date","to":"$to_date"}
}
JSON
)"
CREATE_RAW="$(http_post "$BASE_URL/setting/work-status/timeline" "$CREATE_BODY")"
split_response "$CREATE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Create timeline failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 4
fi
TIMELINE_ID="$(json_get "$HTTP_BODY" "data._id")"
echo "Created timeline: $TIMELINE_ID"

echo "==> 2) Overlap validation (expect non-200)"
OVERLAP_BODY="$(cat <<JSON
{
  "member":"$MEMBER_ID",
  "statusType":"$STATUS_TYPE_ID",
  "title":[{"key":"th","value":"Overlap Test"}],
  "reason":[{"key":"th","value":"Should fail"}],
  "effective":{"from":"$from_date","to":"$to_date"}
}
JSON
)"
OVERLAP_RAW="$(http_post "$BASE_URL/setting/work-status/timeline" "$OVERLAP_BODY")"
split_response "$OVERLAP_RAW"
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "Overlap test failed: expected reject, got HTTP 200"
  echo "$HTTP_BODY"
  exit 5
fi
echo "Overlap validation OK (HTTP $HTTP_CODE)"

echo "==> 3) Update timeline (non-overlap range)"
UPDATE_BODY="$(cat <<JSON
{
  "_id":"$TIMELINE_ID",
  "effective":{"from":"$update_from","to":"$update_to"},
  "reason":[{"key":"th","value":"Updated by smoke test"}]
}
JSON
)"
UPDATE_RAW="$(http_put "$BASE_URL/setting/work-status/timeline" "$UPDATE_BODY")"
split_response "$UPDATE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Update timeline failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 6
fi
echo "Update OK"

echo "==> 4) Decision"
DECISION_BODY="$(cat <<JSON
{
  "id":"$TIMELINE_ID",
  "approverId":"$APPROVER_ID",
  "approvalStatusId":"$APPROVAL_STATUS_ID",
  "note":"approved by smoke test"
}
JSON
)"
DECISION_RAW="$(http_put "$BASE_URL/setting/work-status/timeline/decision" "$DECISION_BODY")"
split_response "$DECISION_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Decision failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 7
fi
echo "Decision OK"

echo "==> 5) Query by member"
QUERY_RAW="$(http_get "$BASE_URL/setting/work-status/timeline?memberId=$MEMBER_ID")"
split_response "$QUERY_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Query failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 8
fi
node -e "
  const obj = JSON.parse(process.argv[1]);
  const id = process.argv[2];
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const found = list.some(x => String(x?._id) === id);
  if (!found) process.exit(2);
" "$HTTP_BODY" "$TIMELINE_ID"
echo "Query OK"

echo "==> 6) Delete timeline"
DELETE_RAW="$(http_delete "$BASE_URL/setting/work-status/timeline" "{\"id\":\"$TIMELINE_ID\"}")"
split_response "$DELETE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Delete failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 9
fi
echo "Delete OK"

echo "==> 7) Audit check"
AUDIT_RAW="$(http_get "$BASE_URL/audit/logs")"
split_response "$AUDIT_RAW"
if [[ "$HTTP_CODE" == "200" ]]; then
  if node -e "
    const obj = JSON.parse(process.argv[1]);
    const id = process.argv[2];
    const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
    const found = list.some(x => x?.module === 'work-status-timeline' && String(x?.resourceId || '') === id);
    process.exit(found ? 0 : 2);
  " "$HTTP_BODY" "$TIMELINE_ID"; then
    echo "Audit OK"
  else
    echo "Audit log not found for this timeline id (non-blocking)"
  fi
else
  echo "Audit endpoint failed (HTTP $HTTP_CODE) - non-blocking"
fi

echo
echo "Smoke work-status-timeline test passed."
