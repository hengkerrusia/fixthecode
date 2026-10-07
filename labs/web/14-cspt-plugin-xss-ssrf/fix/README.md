# Fix — Lab 14

Tulis perbaikanmu di `fix/app/app.py` (salinan `app/app.py` yang sudah
dimodifikasi). Syarat lulus fase 2:

- Serangan referensi harus gagal total: request beracun ke halaman dashboard
  ditolak secara fail-closed, tidak ada plugin JS penyerang yang dimuat,
  tidak ada secret yang bocor.
- Fungsi normal tetap utuh: dashboard dengan plugin valid, login, dan
  endpoint lain berperilaku seperti semula.

Pikirkan di mana trust boundary yang benar untuk menghentikan rantai ini,
dan apa bentuk penolakan yang paling aman untuk input yang tidak valid.
