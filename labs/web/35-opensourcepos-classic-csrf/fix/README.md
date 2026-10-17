# fix — Lab 35

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- Setiap request state-changing (`POST /users`) wajib membawa token CSRF yang
  tidak bisa ditebak penyerang dan terikat ke sesi — lewat field form
  `csrf_token` atau header `X-CSRF-Token`. Token hilang/tidak cocok →
  403 (fail-closed), dalam kondisi apa pun.
- Token harus diterbitkan saat login dan tidak bisa diperoleh lintas-origin
  oleh penyerang.

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /login` sebagai admin → 200 + cookie sesi.
- `POST /users` dengan token CSRF yang valid → 200, user tercipta.
- `GET /me` → info sesi yang benar.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
