# Fix — Lab 20

Salin `app/index.php` ke `fix/app/index.php` (sudah disalin sebagai
scaffold), lalu tulis perbaikanmu di file salinan itu. Aturannya:

- Input mentah dari user tidak boleh lagi diteruskan ke `include`:
  batasi ke daftar halaman yang diizinkan (allowlist), atau tolak
  input yang bukan nama halaman valid secara fail-closed
  (mis. respons 400).
- Fungsi normal tidak boleh berubah: `GET /` dan
  `GET /?page=templates/about.php` tetap me-render halaman seperti
  semula.

Verifier membangun ulang lab dengan app dari `fix/` dan memastikan
serangan referensi tidak lagi mengeksekusi kode, serta fungsi normal
tetap utuh.
