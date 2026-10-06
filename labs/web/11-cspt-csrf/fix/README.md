# fix/

Fase 2: baca `../app/app.py` dan `../app/static/invite.js`, temukan bagaimana
`code` dari query string digabungkan ke URL fetch tanpa validasi, lalu tulis
perbaikanmu:

1. `app/app.py` (file ini) — handler `/invite` harus **menolak** `code` yang
   tidak sesuai format invite yang sah (9 karakter alfanumerik) dengan `400`.
   Ini gerbang yang diverifikasi otomatis.
2. `app/static/invite.js` — validasi `code` dengan allowlist regex **sebelum**
   fetch (pertahanan lapis pertama, di sisi klien).

Scaffold saat ini identik byte-per-byte dengan pristine — verifier menolaknya
(exit 2, "fase 2 belum dikerjakan").

Uji dengan `./lab.sh verify` (fase 2). Lulus bila serangan referensi gagal total
(`GET /invite?code=<racun>` → 400, kartu tidak terbatalkan) sementara fungsi
normal utuh: login → 200, `GET /invite?code=INV123ABC` → 200,
`POST /api/invite/INV123ABC/check` → 200.
