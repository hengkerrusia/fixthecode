# fix/

Fase 2: baca `../app/app.py`, temukan bagaimana `theme` dari query string
direfleksikan ke `href` stylesheet tanpa validasi, lalu tulis perbaikanmu di
`app/app.py` (file ini):

- Handler `/` harus **menolak** `theme` yang tidak sesuai format tema yang
  sah (3–8 huruf kecil, mis. `light`/`dark`) dengan `400`. Ini gerbang yang
  diverifikasi otomatis — tanpa ini, link beracun tetap me-render halaman
  dan rantai serangan tetap hidup.

Catatan: pengerasan open redirect `/api/authorize` (mis. allowlist `state`)
adalah defense in depth yang sah di dunia nyata — tapi kerentanan yang
diperbaiki lab ini adalah CSPT-nya, sehingga gerbang verifier adalah
validasi `theme`.

Scaffold saat ini identik byte-per-byte dengan pristine — verifier menolaknya
(exit 2, "fase 2 belum dikerjakan").

Uji dengan `./lab.sh verify` (fase 2). Lulus bila serangan referensi gagal
total (`GET /?theme=<racun>` → 400, tidak ada CSS penyerang yang dimuat,
tidak ada yang tereksfiltrasi) sementara fungsi normal utuh:
`GET /?theme=light` → 200 dan `/static/theme.light.css` → 200.
