# Fix — Lab 18

Salin `app/app.py` ke `fix/app/app.py`, lalu tulis perbaikanmu di file
salinan itu. Aturannya:

- Netralkan karakter kontrol (`\r` dan `\n`) pada username di titik
  penulisan log — ganti dengan placeholder (mis. `_`) atau hapus.
- Satu request harus tetap menghasilkan tepat satu baris log.
- Fungsi normal tidak boleh berubah: login valid tetap 200, format
  log untuk input normal tetap sama.

Verifier membangun ulang lab dengan app dari `fix/` dan memastikan
serangan referensi tidak lagi menambah baris palsu, serta fungsi
normal tetap utuh.
