# Fix — Lab 19

Salin `app/server.js` ke `fix/app/server.js` (sudah disalin sebagai
scaffold), lalu tulis perbaikanmu di file salinan itu. Aturannya:

- Setiap nama entry arsip harus divalidasi sebelum ditulis ke disk:
  hasil penggabungannya dengan direktori target tidak boleh lolos
  keluar dari direktori target.
- Bila ada entry yang lolos, tolak seluruh upload secara fail-closed
  (atau lewati entry tersebut) — yang penting tidak ada satu byte
  pun yang tertulis di luar direktori target.
- Fungsi normal tidak boleh berubah: zip biasa tetap terekstrak dan
  isinya bisa dibaca kembali via `GET /files/<nama>`.

Verifier membangun ulang lab dengan app dari `fix/` dan memastikan
serangan referensi tidak lagi menulis ke luar direktori target,
serta fungsi normal tetap utuh.
