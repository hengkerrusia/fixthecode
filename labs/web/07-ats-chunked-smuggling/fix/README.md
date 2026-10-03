# Kontrak fix — Fase 2

Tulis perbaikanmu di `fix/proxy/`. File-file di sana adalah salinan
pristine dari `proxy/`; ubah yang perlu diubah agar serangan fase 1
gagal total sementara fungsi normal tetap utuh.

File yang relevan untuk lab ini: `fix/proxy/chunked.py` (parser
chunked transfer-coding yang dipakai proxy untuk memvalidasi body).

'Sudah dikerjakan' dinilai dari apakah isi file berbeda dari pristine
(identik = belum dikerjakan).

Verifier fase 2 me-rebuild lab memakai `fix/` lalu memeriksa:

1. Serangan referensi (chunked body malformed + request kedua
   di-pipeline) GAGAL: request pertama dijawab 400 dan koneksi diputus,
   sehingga request kedua tidak pernah dieksekusi backend.
2. `POST /submit` dengan chunked body yang well-formed tetap 200.
3. `GET /` tetap 200.
