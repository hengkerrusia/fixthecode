# fix/

Fase 2: baca `../app/app.py` dan `../app/static/profile.js`, temukan bagaimana
`id` dari query string digabungkan ke URL fetch tanpa validasi, lalu tulis
perbaikanmu:

1. `app/app.py` (file ini) — handler `/profile` harus **menolak** `id` yang
   tidak sesuai format user ID yang sah (6–16 karakter huruf kecil/angka)
   dengan `400`. Ini gerbang yang diverifikasi otomatis.
2. `app/static/profile.js` — validasi `id` dengan allowlist regex **sebelum**
   fetch (pertahanan lapis pertama, di sisi klien).

Catatan: pengerasan sisi cache (mis. jangan pernah kirim `Cache-Control:
public` untuk respons terautentikasi; `Vary` pada header auth) adalah defense
in depth yang sah di dunia nyata — tapi kerentanan yang diperbaiki lab ini
adalah CSPT-nya, sehingga gerbang verifier adalah validasi `id`.

Scaffold saat ini identik byte-per-byte dengan pristine — verifier menolaknya
(exit 2, "fase 2 belum dikerjakan").

Uji dengan `./lab.sh verify` (fase 2). Lulus bila serangan referensi gagal total
(`GET /profile?id=<racun>` → 400, token tidak bocor via cache) sementara fungsi
normal utuh: login → 200, `GET /profile?id=user123` → 200,
`GET /v1/users/info/user123` (dengan token) → 200.
