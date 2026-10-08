# Fix — Lab 15

Tulis perbaikanmu di `fix/app/app.py` (salinan `app/app.py` yang sudah
dimodifikasi). Syarat lulus fase 2:

- Serangan referensi harus gagal total: request beracun ke `/r/` ditolak
  secara fail-closed — tidak ada header suntikan dalam bentuk apa pun
  yang lolos ke respons.
- Fungsi normal tetap utuh: `/r/<nama-biasa>` tetap 302 ke lokasi yang benar,
  `/login`, `/dashboard`, dan `/files/` berperilaku seperti semula.

Pikirkan di mana trust boundary yang benar untuk menghentikan aliran ini,
dan apa bentuk penolakan yang paling aman untuk input yang tidak valid.
