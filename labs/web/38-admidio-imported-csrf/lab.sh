#!/bin/bash
set -e
cd "$(dirname "$0")"
case "$1" in
  start)
    docker compose up --build -d
    ;;
  stop)
    docker compose down
    ;;
  fix-up)
    docker compose -f docker-compose.yml -f docker-compose.fix.yml up --build -d
    ;;
  verify)
    python3 verify/verify.py
    ;;
  *)
    echo "Usage: $0 {start|stop|fix-up|verify}"
    exit 1
    ;;
esac
