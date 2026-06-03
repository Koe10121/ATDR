#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_ENV=${APP_ENV:-prod}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env.$APP_ENV"}
COMPOSE_FILE="$ROOT_DIR/docker-compose.server.yml"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing env file: $ENV_FILE" >&2
  exit 1
fi

ACTION=${1:-deploy}
if [ $# -gt 0 ]; then
  shift
fi

compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

case "$ACTION" in
  deploy|up)
    compose up -d --build "$@"
    ;;
  down|stop)
    compose down "$@"
    ;;
  ps|status)
    compose ps "$@"
    ;;
  logs)
    compose logs -f "$@"
    ;;
  config)
    compose config "$@"
    ;;
  *)
    cat >&2 <<'EOF'
Usage: ./server.sh [deploy|up|down|stop|ps|status|logs|config] [extra docker compose args]

Examples:
  ./server.sh
  APP_ENV=preprod ./server.sh
  ./server.sh ps
  ./server.sh logs frontend
  ENV_FILE=/path/to/.env.prod ./server.sh deploy
EOF
    exit 1
    ;;
esac
