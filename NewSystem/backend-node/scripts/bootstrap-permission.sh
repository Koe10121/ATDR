#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8084/api/v1}"
X_ACCESS_TOKEN="${X_ACCESS_TOKEN:-}"
TARGET_PATH="${TARGET_PATH:-/security/permission}"

if [[ -n "${1:-}" ]]; then BASE_URL="$1"; fi
if [[ -n "${2:-}" ]]; then X_ACCESS_TOKEN="$2"; fi
if [[ -n "${3:-}" ]]; then TARGET_PATH="$3"; fi

if [[ -z "$X_ACCESS_TOKEN" ]]; then
  echo "Usage:"
  echo "  X_ACCESS_TOKEN='<token>' $0 [BASE_URL] [X_ACCESS_TOKEN] [TARGET_PATH]"
  exit 1
fi

json_get() {
  node -e "
    const obj = JSON.parse(process.argv[1]);
    const path = process.argv[2].split('.');
    let cur = obj;
    for (const k of path) cur = cur?.[k];
    if (cur === undefined || cur === null) process.exit(2);
    process.stdout.write(String(cur));
  " "$1" "$2"
}

json_find_id_by_path() {
  node -e "
    const obj = JSON.parse(process.argv[1]);
    const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
    const path = process.argv[2];
    const found = list.find(x => x && x.path === path);
    if (!found || !found._id) process.exit(2);
    process.stdout.write(String(found._id));
  " "$1" "$2"
}

json_find_id_by_title_value() {
  node -e "
    const obj = JSON.parse(process.argv[1]);
    const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
    const value = process.argv[2];
    const found = list.find(x => Array.isArray(x?.title) && x.title.some(t => t?.value === value));
    if (!found || !found._id) process.exit(2);
    process.stdout.write(String(found._id));
  " "$1" "$2"
}

http_get() {
  curl -sS -X GET "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN"
}

http_post() {
  curl -sS -X POST "$1" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "$2"
}

echo "==> Resolve current account from /auth/me"
ME_JSON="$(http_get "$BASE_URL/auth/me")"
ACCOUNT_ID="$(json_get "$ME_JSON" "data._id")"
echo "Account: $ACCOUNT_ID"

echo "==> Ensure Security Type: SYSTEM"
TYPES_JSON="$(http_get "$BASE_URL/security/type")"
TYPE_ID=""
if TYPE_ID="$(json_find_id_by_title_value "$TYPES_JSON" "SYSTEM" 2>/dev/null)"; then
  echo "Type exists: $TYPE_ID"
else
  CREATED_TYPE="$(http_post "$BASE_URL/security/type" '{"title":[{"key":"en","value":"SYSTEM"}],"description":[{"key":"en","value":"System"}]}' )"
  TYPE_ID="$(json_get "$CREATED_TYPE" "data._id")"
  echo "Type created: $TYPE_ID"
fi

echo "==> Ensure Security Menu path: $TARGET_PATH"
MENUS_JSON="$(http_get "$BASE_URL/security/menu")"
MENU_ID=""
if MENU_ID="$(json_find_id_by_path "$MENUS_JSON" "$TARGET_PATH" 2>/dev/null)"; then
  echo "Menu exists: $MENU_ID"
else
  CREATED_MENU="$(http_post "$BASE_URL/security/menu" "{\"title\":[{\"key\":\"en\",\"value\":\"Permission\"}],\"description\":[{\"key\":\"en\",\"value\":\"Permission Management\"}],\"path\":\"$TARGET_PATH\",\"type\":\"$TYPE_ID\"}")"
  MENU_ID="$(json_get "$CREATED_MENU" "data._id")"
  echo "Menu created: $MENU_ID"
fi

echo "==> Ensure Security Group: ADMIN"
GROUPS_JSON="$(http_get "$BASE_URL/security/group")"
GROUP_ID=""
if GROUP_ID="$(json_find_id_by_title_value "$GROUPS_JSON" "ADMIN" 2>/dev/null)"; then
  echo "Group exists: $GROUP_ID"
else
  CREATED_GROUP="$(http_post "$BASE_URL/security/group" "{\"title\":[{\"key\":\"en\",\"value\":\"ADMIN\"}],\"description\":[{\"key\":\"en\",\"value\":\"Admin Group\"}],\"visibleType\":\"$TYPE_ID\"}")"
  GROUP_ID="$(json_get "$CREATED_GROUP" "data._id")"
  echo "Group created: $GROUP_ID"
fi

echo "==> Ensure permission row (group+menu)"
PERMS_JSON="$(http_get "$BASE_URL/security/permission")"
PERM_ID="$(node -e "
  const obj = JSON.parse(process.argv[1]);
  const gid = process.argv[2];
  const mid = process.argv[3];
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const found = list.find(x => String(x?.group?._id || x?.group) === gid && String(x?.menu?._id || x?.menu) === mid);
  if (!found || !found._id) process.exit(2);
  process.stdout.write(String(found._id));
" "$PERMS_JSON" "$GROUP_ID" "$MENU_ID" 2>/dev/null || true)"

if [[ -n "$PERM_ID" ]]; then
  curl -sS -X PUT "$BASE_URL/security/permission" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "{\"_id\":\"$PERM_ID\",\"group\":\"$GROUP_ID\",\"menu\":\"$MENU_ID\",\"all\":true,\"view\":true,\"edit\":true,\"delete\":true,\"action\":true,\"logs\":true}" >/dev/null
  echo "Permission updated: $PERM_ID"
else
  CREATED_PERMISSION="$(http_post "$BASE_URL/security/permission" "{\"group\":\"$GROUP_ID\",\"menu\":\"$MENU_ID\",\"all\":true,\"view\":true,\"edit\":true,\"delete\":true,\"action\":true,\"logs\":true}")"
  PERM_ID="$(json_get "$CREATED_PERMISSION" "data._id")"
  echo "Permission created: $PERM_ID"
fi

echo "==> Ensure assignment account->group"
ASSIGNMENTS_JSON="$(http_get "$BASE_URL/security/assignment?accountId=$ACCOUNT_ID")"
ASSIGN_ID="$(node -e "
  const obj = JSON.parse(process.argv[1]);
  const gid = process.argv[2];
  const list = Array.isArray(obj?.data) ? obj.data : (obj?.data?.data || []);
  const found = list.find(x => String(x?.group?._id || x?.group) === gid);
  if (!found || !found._id) process.exit(2);
  process.stdout.write(String(found._id));
" "$ASSIGNMENTS_JSON" "$GROUP_ID" 2>/dev/null || true)"

if [[ -n "$ASSIGN_ID" ]]; then
  curl -sS -X PUT "$BASE_URL/security/assignment" \
    -H "Content-Type: application/json" \
    -H "x-access-token: $X_ACCESS_TOKEN" \
    -d "{\"_id\":\"$ASSIGN_ID\",\"account\":\"$ACCOUNT_ID\",\"group\":\"$GROUP_ID\",\"dataScope\":\"org\",\"scopeUnits\":[],\"active\":true}" >/dev/null
  echo "Assignment updated: $ASSIGN_ID"
else
  CREATED_ASSIGNMENT="$(http_post "$BASE_URL/security/assignment" "{\"account\":\"$ACCOUNT_ID\",\"group\":\"$GROUP_ID\",\"dataScope\":\"org\",\"scopeUnits\":[],\"active\":true}")"
  ASSIGN_ID="$(json_get "$CREATED_ASSIGNMENT" "data._id")"
  echo "Assignment created: $ASSIGN_ID"
fi

echo
echo "Bootstrap permission completed."
echo "Now refresh frontend and test: $TARGET_PATH"
