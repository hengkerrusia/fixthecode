# fix/

Tulis perbaikanmu dengan menimpa file di bawah ini.

Aturan:
- Struktur direktori di sini mirror `apache/` — perbaiki file yang rentan di path yang sama.
- Jangan mengubah `docker-compose.yml`, `Dockerfile`, atau file lain di luar `fix/`.
- Verifier me-rebuild lab dengan menukar file `apache/` yang rentan dengan versimu,
  lalu memastikan serangan referensi gagal dan fungsi normal tetap utuh.

Perbaikan yang benar bersifat fail-closed: request yang lolos membaca file di luar
direktori web harus ditolak, sementara halaman utama dan skrip CGI normal tetap
bisa diakses. Lihat README lab bagian "Fase 2 — Review & Fix".
