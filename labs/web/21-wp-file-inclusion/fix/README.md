# Fix — Lab 21

Salin `app/server.py` ke `fix/app/server.py` (sudah disalin sebagai
scaffold), lalu tulis perbaikanmu di file salinan itu. Aturannya:

- File di luar direktori tema tidak boleh lagi bisa di-include lewat
  parameter `pagename`: buktikan path hasil resolusi tetap berada di
  dalam direktori tema yang diizinkan, dan tolak secara fail-closed
  (respons 400) bila tidak.
- Fungsi normal tidak boleh berubah: `GET /`, `POST /page/` dengan
  `pagename=hello-world&page_id=1` tetap me-render halaman dari
  template bawaan tema, dan `page_id` yang tidak valid tetap 404.

Verifier membangun ulang lab dengan app dari `fix/` dan memastikan
serangan referensi digagalkan (400, tanpa marker bocor), serta fungsi
normal tetap utuh.
