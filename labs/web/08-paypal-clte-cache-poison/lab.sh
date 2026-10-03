#!/bin/sh
# lab.sh — Lab 8: CL.TE smuggling -> cache poisoning -> stored XSS
set -eu
cd "$(dirname "$0")"
case "${1:-}" in
  up)
    docker compose up -d --build
    ;;
  down)
    docker compose -f docker-compose.yml -f docker-compose.fix.yml down --remove-orphans
    ;;
  verify)
    python3 verify/verify.py
    ;;
  *)
    echo "pakai: $0 {up|down|verify}" >&2
    exit 1
    ;;
esac
