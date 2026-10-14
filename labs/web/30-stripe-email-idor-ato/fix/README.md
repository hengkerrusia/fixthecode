# fix — Lab 30

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- `POST /account/email` menolak (403) bila `user_id` di body bukan milik sesi login.
- Aksi ganti email wajib konfirmasi password; tolak (403) bila password salah/tidak ada.
- Fail-closed: request yang ditolak tidak mengubah email siapa pun.

Fungsi normal yang harus tetap jalan (dicek verifier):

- Ganti email sendiri dengan password benar → 200.
- Login → 200; password-reset untuk email sendiri tetap mengembalikan token.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
