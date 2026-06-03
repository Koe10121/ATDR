#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://iam.mfu.ac.th/api/v1}"
X_ACCESS_TOKEN="${X_ACCESS_TOKEN:-}"
ACTOR_ID="${ACTOR_ID:-}"

if [[ -n "${1:-}" ]]; then BASE_URL="$1"; fi
if [[ -n "${2:-}" ]]; then X_ACCESS_TOKEN="$2"; fi
if [[ -n "${3:-}" ]]; then ACTOR_ID="$3"; fi

if [[ -z "$X_ACCESS_TOKEN" ]]; then
  echo "Usage:"
  echo "  X_ACCESS_TOKEN='<token>' $0 [BASE_URL] [X_ACCESS_TOKEN] [ACTOR_ID]"
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

split_response() {
  local raw="$1"
  HTTP_BODY="$(printf "%s" "$raw" | sed '$d')"
  HTTP_CODE="$(printf "%s" "$raw" | tail -n 1)"
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

http_delete() {
  curl -sS -w "\n%{http_code}" -X DELETE "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "$2"
}

echo "==> Resolve actor"
if [[ -z "$ACTOR_ID" ]]; then
  ME_RAW="$(http_get "$BASE_URL/auth/me")"
  split_response "$ME_RAW"
  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "Failed /auth/me (HTTP $HTTP_CODE)"
    echo "$HTTP_BODY"
    exit 2
  fi
  ACTOR_ID="$(json_get "$HTTP_BODY" "data._id")"
fi
echo "actor: $ACTOR_ID"

stamp="$(date +%s)"
module="smoke-audit-$stamp"
resource="resource-$stamp"

echo "==> 1) Create audit log"
CREATE_BODY="$(cat <<JSON
{
  "module":"$module",
  "action":"manual-create",
  "actorType":"tester",
  "actorId":"$ACTOR_ID",
  "resourceType":"SmokeResource",
  "resourceId":"$resource",
  "meta":{"suite":"smoke-audit","stamp":$stamp}
}
JSON
)"
CREATE_RAW="$(http_post "$BASE_URL/audit/logs" "$CREATE_BODY")"
split_response "$CREATE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Create audit failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 3
fi
AUDIT_ID="$(json_get "$HTTP_BODY" "data._id")"
echo "Audit created: $AUDIT_ID"

echo "==> 2) Query by module + resource"
QUERY_RAW="$(http_get "$BASE_URL/audit/logs?module=$module&resourceId=$resource")"
split_response "$QUERY_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Query audit failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 4
fi
node -e "
  const obj = JSON.parse(process.argv[1]);
  const id = process.argv[2];
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const found = list.some(x => String(x?._id) === id);
  if (!found) process.exit(2);
" "$HTTP_BODY" "$AUDIT_ID"
echo "Query OK"

echo "==> 3) Delete audit"
DELETE_RAW="$(http_delete "$BASE_URL/audit/logs" "{\"id\":\"$AUDIT_ID\"}")"
split_response "$DELETE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Delete audit failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 5
fi
echo "Delete OK"

echo "==> 4) Verify state=false after delete"
VERIFY_RAW="$(http_get "$BASE_URL/audit/logs?module=$module&resourceId=$resource&state=true")"
split_response "$VERIFY_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Verify audit failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 6
fi
node -e "
  const obj = JSON.parse(process.argv[1]);
  const id = process.argv[2];
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const foundActive = list.some(x => String(x?._id) === id);
  if (foundActive) process.exit(2);
" "$HTTP_BODY" "$AUDIT_ID"
echo "Verify OK"

echo
echo "Smoke audit test passed."
