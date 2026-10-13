# fix/

Salin `../app/app.py` ke `fix/app/app.py` (sudah disediakan sebagai scaffold),
lalu perbaiki fungsi validasi redirect-nya (`redirect_allowed`).

Syarat fix yang benar:

- Normalisasi dulu, baru putuskan: tidak ada URL yang lolos hanya karena
  "tidak dikenali" pemeriksa.
- Skema harus `https` (bandingkan case-insensitive — ingat skema URL memang
  case-insensitive menurut standar).
- Host harus yang terdaftar (`app.demo`).
- Selain itu → 400, tanpa token bocor.

Jangan ubah alur normal: `returnUrl=https://app.demo/cb` harus tetap
menghasilkan 302 dengan `#access_token=`, dan `/me` tetap valid.
