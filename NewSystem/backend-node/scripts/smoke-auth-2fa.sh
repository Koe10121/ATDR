#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://iam.mfu.ac.th/api/v1}"
AUTH_TYPE_ID="${AUTH_TYPE_ID:-689c06d5255db4e56aea8902}"
GOOGLE_ID_TOKEN="${GOOGLE_ID_TOKEN:-}"
OTP_CODE="${OTP_CODE:-}"

if [[ -n "${1:-}" ]]; then BASE_URL="$1"; fi
if [[ -n "${2:-}" ]]; then GOOGLE_ID_TOKEN="$2"; fi
if [[ -n "${3:-}" ]]; then OTP_CODE="$3"; fi

if [[ -z "$GOOGLE_ID_TOKEN" ]]; then
  echo "Usage:"
  echo "  GOOGLE_ID_TOKEN='<google_id_token>' $0 [BASE_URL] [GOOGLE_ID_TOKEN] [OTP_CODE]"
  echo
  echo "Examples:"
  echo "  GOOGLE_ID_TOKEN='xxx' $0"
  echo "  $0 https://iam.mfu.ac.th/api/v1 'xxx' '123456'"
  exit 1
fi

json_get() {
  local json="$1"
  local path="$2"
  node -e "
    const obj = JSON.parse(process.argv[1]);
    const path = process.argv[2].split('.');
    let cur = obj;
    for (const key of path) cur = cur?.[key];
    if (cur === undefined || cur === null) process.exit(2);
    process.stdout.write(String(cur));
  " "$json" "$path"
}

post_json() {
  local url="$1"
  local body="$2"
  local token="${3:-}"
  if [[ -n "$token" ]]; then
    curl -sS -w "\n%{http_code}" \
      -X POST "$url" \
      -H "Content-Type: application/json" \
      -H "x-access-token: $token" \
      -d "$body"
  else
    curl -sS -w "\n%{http_code}" \
      -X POST "$url" \
      -H "Content-Type: application/json" \
      -d "$body"
  fi
}

get_json() {
  local url="$1"
  local token="${2:-}"
  if [[ -n "$token" ]]; then
    curl -sS -w "\n%{http_code}" \
      -X GET "$url" \
      -H "Content-Type: application/json" \
      -H "x-access-token: $token"
  else
    curl -sS -w "\n%{http_code}" \
      -X GET "$url" \
      -H "Content-Type: application/json"
  fi
}

split_response() {
  local raw="$1"
  HTTP_BODY="$(printf "%s" "$raw" | sed '$d')"
  HTTP_CODE="$(printf "%s" "$raw" | tail -n 1)"
}

echo "==> 1) Sign in"
SIGNIN_RAW="$(post_json "$BASE_URL/signin" "{\"token\":\"$GOOGLE_ID_TOKEN\",\"authType\":\"$AUTH_TYPE_ID\"}")"
split_response "$SIGNIN_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "Sign in failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 2
fi
X_ACCESS_TOKEN="$(json_get "$HTTP_BODY" "data.xAccessToken")"
echo "OK: received x-access-token"

echo "==> 2) Request OTP"
REQ_RAW="$(post_json "$BASE_URL/auth/2fa/request" "{}" "$X_ACCESS_TOKEN")"
split_response "$REQ_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "2FA request failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 3
fi
echo "OK: requested OTP"

if [[ -z "$OTP_CODE" ]]; then
  if OTP_CODE="$(json_get "$HTTP_BODY" "data.devCode" 2>/dev/null)"; then
    echo "Using devCode from response"
  else
    echo "OTP_CODE not provided and no data.devCode in response"
    echo "Set OTP_CODE and run again"
    exit 4
  fi
fi

echo "==> 3) Verify OTP"
VERIFY_RAW="$(post_json "$BASE_URL/auth/2fa/verify" "{\"code\":\"$OTP_CODE\"}" "$X_ACCESS_TOKEN")"
split_response "$VERIFY_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "2FA verify failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 5
fi
echo "OK: verified OTP"

echo "==> 4) Fetch profile (/auth/me)"
ME_RAW="$(get_json "$BASE_URL/auth/me" "$X_ACCESS_TOKEN")"
split_response "$ME_RAW"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "auth/me failed (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 6
fi
EMAIL="$(json_get "$HTTP_BODY" "data.email" 2>/dev/null || true)"
echo "OK: auth/me success ${EMAIL:+(email: $EMAIL)}"

echo
echo "Smoke auth+2FA test passed."
