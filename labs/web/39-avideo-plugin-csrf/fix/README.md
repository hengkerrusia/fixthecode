# fix — Lab 39

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- Token CSRF wajib divalidasi di `POST /admin/save.json.php` **tanpa kecuali**,
  tepat setelah pemeriksaan sesi admin — ala anjuran advisory
  (`isGlobalTokenValid()` di `save.json.php:10`). Token hilang/tidak cocok →
  403 (fail-closed), dalam kondisi apa pun.
- Validasi berjalan sebelum data apa pun ditulis ke konfigurasi plugin.

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /login` sebagai admin → 200 + cookie sesi.
- `POST /admin/save.json.php` dengan token CSRF valid → 200 + konfigurasi
  tersimpan.
- `POST /admin/save.json.php` dengan `pluginName` tak dikenal → 404.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
