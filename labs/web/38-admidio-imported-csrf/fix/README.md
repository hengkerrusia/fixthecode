# fix — Lab 38

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- Token CSRF wajib divalidasi di **setiap** request state-changing
  (`POST /inventory/item_save`) **tanpa kecuali** — termasuk saat parameter
  `imported=1` dikirim. Token hilang/tidak cocok → 403 (fail-closed), dalam
  kondisi apa pun.
- Validasi form server-side (nama wajib isi, kategori terdaftar, quantity
  integer ≥ 0) wajib berjalan **tanpa kecuali** juga — parameter `imported`
  tidak boleh mematikan validasi.
- Prinsipnya: flag yang nilainya datang dari request tidak boleh mengendalikan
  apakah security check dijalankan. Flag boleh mengatur *alur fitur*, tidak
  boleh mengatur *penegakan keamanan*.

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /login` sebagai manager → 200 + cookie sesi.
- `POST /inventory/item_save` dengan token CSRF valid + field valid → 200.
- `POST /inventory/item_save` dengan token valid tapi quantity invalid → 400.
- `POST /inventory/item_save` dengan `imported=1` + token valid + field
  valid → 200 (jalur impor tetap berfungsi untuk user sah).

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
