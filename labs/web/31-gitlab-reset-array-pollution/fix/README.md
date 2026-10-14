# fix — Lab 31

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- `POST /password-reset` menolak (400) bila `email` bukan string — sebelum lookup
  user dan sebelum email apa pun dikirim.
- Fail-closed: request yang ditolak tidak mengirim email ke siapa pun.

Fungsi normal yang harus tetap jalan (dicek verifier):

- Reset dengan string email → 200.
- Reset dengan email tak dikenal → 200 tanpa email terkirim.
- Login victim dengan password lama tetap bisa (tidak ada takeover).

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
