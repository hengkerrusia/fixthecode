# fix — Lab 34

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- Endpoint setup (`/setup/*`) tidak boleh bisa dijangkau setelah setup selesai
  (fail-closed → 403), dalam kondisi apa pun.
- Status setup tidak boleh bisa diubah lewat endpoint informasi.

Fungsi normal yang harus tetap jalan (dicek verifier):

- `GET /server-info.action` → 200 dengan `setupComplete: true`.
- Login admin yang sudah ada via `POST /dologin.action` → 200 + token.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
