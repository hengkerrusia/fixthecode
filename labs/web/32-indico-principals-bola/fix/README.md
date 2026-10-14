# fix — Lab 32

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- `POST /api/principals` hanya me-resolve principal milik sesi login; ID lain →
  `{"invalid": true}` (fail-closed, sama seperti ID tak dikenal).
- Tidak ada PII user lain yang bocor dalam kondisi apa pun.

Fungsi normal yang harus tetap jalan (dicek verifier):

- Resolve diri sendiri → 200 + data lengkap.
- ID tak dikenal → `{"invalid": true}`.
- Tanpa token → 401.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
