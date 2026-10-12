#!/bin/sh
# Lab 23 — GitLab Maven traversal to RCE (H1 #733072).
#   ./lab.sh start   — jalankan rakitan rentan (pristine)
#   ./lab.sh stop    — hentikan
#   ./lab.sh verify  — verifikasi 2 fase (butuh Docker)
#   ./lab.sh fix-up  — jalankan dengan fix/ learner (tanpa verifikasi)
set -e
cd "$(dirname "$0")"
case "$1" in
  start)
    docker compose up --build -d
    echo "lab menyala di http://127.0.0.1:8080"
    ;;
  stop)
    docker compose -f docker-compose.yml -f docker-compose.fix.yml down --remove-orphans
    docker compose down --remove-orphans
    ;;
  verify)
    python3 verify/verify.py
    ;;
  fix-up)
    docker compose -f docker-compose.yml -f docker-compose.fix.yml up --build -d
    echo "lab (fix) menyala di http://127.0.0.1:8080"
    ;;
  *)
    echo "pakai: $0 {start|stop|verify|fix-up}"
    exit 1
    ;;
esac
