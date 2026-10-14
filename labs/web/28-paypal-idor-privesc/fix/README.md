# fix/

Salin `../app/app.py` ke `fix/app/app.py` (sudah disediakan sebagai scaffold),
lalu tambahkan pemeriksaan kepemilikan di endpoint tambah-user.

Syarat fix yang benar:

- `POST /businessmanage/users/api/v1/users` dengan `account_id` yang bukan
  milik pemanggil → **403**, dan tidak ada user yang tertanam.
- `account_id` milik sendiri → tetap 201 seperti semula.
- Gunakan relasi yang sudah ada di server (`is_member`) — jangan percaya
  klaim apa pun dari client selain identitas sesi.

Jangan ubah perilaku endpoint lain.
