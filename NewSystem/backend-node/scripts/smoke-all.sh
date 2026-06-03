#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://iam.mfu.ac.th/api/v1}"
X_ACCESS_TOKEN="${X_ACCESS_TOKEN:-}"

if [[ -n "${1:-}" ]]; then BASE_URL="$1"; fi
if [[ -n "${2:-}" ]]; then X_ACCESS_TOKEN="$2"; fi

if [[ -z "$X_ACCESS_TOKEN" ]]; then
  echo "Usage:"
  echo "  X_ACCESS_TOKEN='<token>' $0 [BASE_URL] [X_ACCESS_TOKEN]"
  exit 1
fi

run() {
  local name="$1"
  shift
  echo
  echo "=============================="
  echo "RUN: $name"
  echo "=============================="
  "$@"
}

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

run "E: work-status timeline" "$ROOT_DIR/scripts/smoke-work-status-timeline.sh" "$BASE_URL" "$X_ACCESS_TOKEN"
run "I: attachments" "$ROOT_DIR/scripts/smoke-attachments.sh" "$BASE_URL" "$X_ACCESS_TOKEN"
run "H: audit logs" "$ROOT_DIR/scripts/smoke-audit.sh" "$BASE_URL" "$X_ACCESS_TOKEN"

echo
echo "All smoke tests passed."
