# fix — Lab 40

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix (ala anjuran advisory — perilaku default gorilla/websocket yang aman):

- Fungsi handshake (`_handle_ws`) wajib memvalidasi header `Origin` **sebelum**
  mengirim `101 Switching Protocols`: jika `Origin` ada dan host-nya tidak
  cocok dengan header `Host` → 403 (fail-closed).
- Handshake tanpa header `Origin` tetap diterima (klien non-browser tidak
  mengirim `Origin`).

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /login` sebagai dev → 200 + cookie sesi.
- Handshake dengan cookie valid dan `Origin` yang cocok `Host`
  (`http://127.0.0.1:8080`) → 101, dan event yang disiarkan tetap diterima.
- Handshake dengan cookie valid tanpa `Origin` → 101.
- `POST /api/send-test` dengan sesi valid → 200 + event disiarkan.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
