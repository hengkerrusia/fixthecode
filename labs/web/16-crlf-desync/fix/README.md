# Fix — Lab 16

Salin `gateway/gateway.py` ke `fix/gateway/gateway.py`, lalu tulis
perbaikanmu di file salinan itu. Aturannya:

- Tolak secara fail-closed (respons 400) bila request target yang
  sudah ter-decode mengandung CR atau LF.
- Request yang ditolak **jangan** diteruskan ke backend.
- Fungsi normal tidak boleh berubah: request biasa (termasuk yang
  mengandung karakter ter-encode selain CR/LF) tetap diteruskan.

Verifier membangun ulang lab dengan gateway dari `fix/` dan memastikan
serangan referensi digagalkan (400, tidak ada racun yang lolos) serta
fungsi normal tetap utuh.
