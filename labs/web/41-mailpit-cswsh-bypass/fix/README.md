# fix — Lab 41

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix (ala perbaikan upstream 1.30.6):

- Cek Origin wajib menilai representasi path yang **sama** dengan yang dipakai
  routing (path hasil percent-decode), bukan URI mentah — atau, lebih kuat,
  handler WebSocket memvalidasi `Origin` sendiri sebelum `101` dikirim.
- Jika `Origin` ada dan host-nya tidak cocok dengan header `Host` → 403
  (fail-closed), pada **semua** representasi path: polos maupun percent-encoded.
- Handshake tanpa header `Origin` tetap diterima (klien non-browser tidak
  mengirim `Origin`).

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /login` sebagai dev → 200 + cookie sesi.
- Handshake dengan cookie valid dan `Origin` yang cocok `Host`
  (`http://127.0.0.1:8080`) → 101, dan event yang disiarkan tetap diterima —
  termasuk bila path-nya ditulis dalam bentuk percent-encoded.
- Handshake dengan cookie valid tanpa `Origin` → 101.
- `POST /api/send-test` dengan sesi valid → 200 + event disiarkan.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
