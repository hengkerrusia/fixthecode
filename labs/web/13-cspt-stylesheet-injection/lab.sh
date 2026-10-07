#!/bin/bash
# lab.sh — start | stop | verify | fix-up
set -e
cd "$(dirname "$0")"

case "$1" in
  start)
    # Selalu build ulang dari file pristine -> lab SELALU kembali rentan.
    docker compose -f docker-compose.yml -f docker-compose.fix.yml down 2>/dev/null || true
    docker compose down 2>/dev/null || true
    docker compose up --build -d
    echo "Lab (RENTAN) jalan di http://localhost:8080 — CSPT stylesheet demo"
    ;;
  stop)
    docker compose -f docker-compose.yml -f docker-compose.fix.yml down 2>/dev/null || true
    docker compose down
    echo "Lab dihentikan."
    ;;
  fix-up)
    # Jalankan lab dengan fix-mu (tanpa verifikasi).
    docker compose -f docker-compose.yml -f docker-compose.fix.yml up --build -d
    echo "Lab (dengan fix-mu) jalan di http://localhost:8080 — CSPT stylesheet demo"
    ;;
  verify)
    python3 verify/verify.py
    ;;
  *)
    echo "pakai: $0 {start|stop|verify|fix-up}"
    exit 1
    ;;
esac
