#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://iam.mfu.ac.th/api/v1}"
X_ACCESS_TOKEN="${X_ACCESS_TOKEN:-}"
OWNER_TYPE="${OWNER_TYPE:-training-request}"
OWNER_ID="${OWNER_ID:-smoke-owner-$(date +%s)}"

if [[ -n "${1:-}" ]]; then BASE_URL="$1"; fi
if [[ -n "${2:-}" ]]; then X_ACCESS_TOKEN="$2"; fi
if [[ -n "${3:-}" ]]; then OWNER_TYPE="$3"; fi
if [[ -n "${4:-}" ]]; then OWNER_ID="$4"; fi

if [[ -z "$X_ACCESS_TOKEN" ]]; then
  echo "Usage:"
  echo "  X_ACCESS_TOKEN='<token>' $0 [BASE_URL] [X_ACCESS_TOKEN] [OWNER_TYPE] [OWNER_ID]"
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

stamp="$(date +%s)"

echo "==> 1) Create attachment"
CREATE_BODY="$(cat <<JSON
{
  "ownerType":"$OWNER_TYPE",
  "ownerId":"$OWNER_ID",
  "fileName":"smoke-$stamp.txt",
  "originalName":"ต้นฉบับ-$stamp.txt",
  "mimeType":"text/plain",
  "extension":"txt",
  "size":128,
  "url":"https://example.test/smoke/$stamp"
}
JSON
)"
CREATE_RAW="$(http_post "$BASE_URL/attachments" "$CREATE_BODY")"
split_response "$CREATE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Create attachment failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 2
fi
ATTACHMENT_ID="$(json_get "$HTTP_BODY" "data._id")"
echo "Attachment created: $ATTACHMENT_ID"

echo "==> 2) Query attachment by owner"
QUERY_RAW="$(http_get "$BASE_URL/attachments?ownerType=$OWNER_TYPE&ownerId=$OWNER_ID")"
split_response "$QUERY_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Query attachments failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 3
fi
node -e "
  const obj = JSON.parse(process.argv[1]);
  const id = process.argv[2];
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const found = list.some(x => String(x?._id) === id);
  if (!found) process.exit(2);
" "$HTTP_BODY" "$ATTACHMENT_ID"
echo "Query OK"

echo "==> 3) Update attachment"
UPDATE_BODY="{\"_id\":\"$ATTACHMENT_ID\",\"size\":256,\"url\":\"https://example.test/smoke/$stamp/updated\"}"
UPDATE_RAW="$(http_put "$BASE_URL/attachments" "$UPDATE_BODY")"
split_response "$UPDATE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Update attachment failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 4
fi
echo "Update OK"

echo "==> 4) Delete attachment"
DELETE_RAW="$(http_delete "$BASE_URL/attachments" "{\"id\":\"$ATTACHMENT_ID\"}")"
split_response "$DELETE_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Delete attachment failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 5
fi
echo "Delete OK"

echo "==> 5) Verify audit"
AUDIT_RAW="$(http_get "$BASE_URL/audit/logs?module=attachments&resourceId=$ATTACHMENT_ID")"
split_response "$AUDIT_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Audit query failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 6
fi
node -e "
  const obj = JSON.parse(process.argv[1]);
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const acts = new Set(list.map(x => x?.action));
  const ok = acts.has('create') && acts.has('update') && acts.has('delete');
  if (!ok) process.exit(2);
" "$HTTP_BODY"
echo "Audit OK"

echo
echo "Smoke attachments test passed."
