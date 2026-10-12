# fix/

Tulis perbaikanmu dengan menimpa file di bawah ini.

Aturan:
- Struktur direktori di sini mirror `app/` — perbaiki file yang rentan di path yang sama.
- Jangan mengubah `docker-compose.yml`, `Dockerfile`, atau file lain di luar `fix/`.
- Verifier me-rebuild lab dengan menukar file `app/` yang rentan dengan versimu,
  lalu memastikan serangan referensi gagal dan fungsi normal tetap utuh.

Perbaikan yang benar bersifat fail-closed: parameter yang tidak tepercaya tidak
boleh lagi menentukan file apa yang di-include. Lihat README lab bagian
"Review & Fix".
