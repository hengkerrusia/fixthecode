# fix — Lab 37

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix (mengikuti patch upstream):

- Request non-GET ke API **wajib** membawa `Content-Type: application/json`
  (toleransi suffix seperti `; charset=utf-8` boleh). Selain itu → 4xx
  (fail-closed), dalam kondisi apa pun.
- Ini menutup bypass preflight: browser *wajib* mengirim preflight untuk
  `application/json` lintas-origin, dan server tanpa CORS tidak akan
  meloloskannya.

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /api/v1/session` → 200 + cookie.
- `POST /api/v1/applications` dengan `Content-Type: application/json` →
  201, aplikasi tercatat.
- `GET /api/v1/applications` → daftar benar.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
