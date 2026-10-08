# Fix — Lab 17

Salin `gateway/gateway.py` ke `fix/gateway/gateway.py`, lalu tulis
perbaikanmu di file salinan itu. Aturannya:

- Netralkan karakter kontrol pada filename sebelum diinterpolasi ke
  header `Content-Disposition`: percent-encode `\r` → `%0D`,
  `\n` → `%0A`, dan `"` → `%22` (mengikuti perbaikan upstream
  `form-data` 4.0.6).
- Upload normal tidak boleh berubah: filename biasa tetap diteruskan
  apa adanya.
- Jangan ubah perilaku lain (boundary, struktur part, forwarding).

Verifier membangun ulang lab dengan gateway dari `fix/` dan memastikan
serangan referensi tidak lagi menghasilkan header part suntikan, serta
upload normal tetap utuh.
