# Fix — Lab 43

Tulis perbaikanmu di `app/app.py` di folder ini. File itu saat ini salinan
persis aplikasi rentan; verifier mendeteksi "belum dikerjakan" dari situ —
jadi pastikan isinya berubah.

## Ketentuan

- File harus berisi **satu aplikasi utuh** yang tetap bisa jalan dengan
  Dockerfile & compose yang sama (Python 3 stdlib saja).
- Jangan mengubah kontrak aplikasi: rute, nama cookie sesi (`sess`),
  kredensial demo, dan perilaku redirect setelah login harus tetap sama.
- Perbaikan mengikuti pola upstream (Grafana 8.2.3,
  `sanitizeAngularInterpolation`): sebelum URL yang terefleksi ditulis ke
  tautan navigasi, ganti **seluruh** kemunculan `{{` menjadi `%7B%7B` dan
  `}}` menjadi `%7D%7D`, agar mesin template tidak pernah melihat binding
  yang bisa dievaluasi. URL normal tanpa kurung kurawal tidak berubah.

## Yang diperiksa verifier (mode fix)

- Path berpayload terefleksi dengan kurung kurawal ter-encode di href
  tautan Masuk — tidak ada `{{` utuh yang tersisa.
- Exploit referensi (`solutions/exploit.py`) gagal membuktikan eksekusi:
  tidak ada MARKER.
- Login benar tetap 302 ke tujuan `redirectTo` dan sesi tetap membuka
  dasbor.
- Login salah tetap ditolak tanpa sesi; halaman publik tetap 200.

Acuan lengkap ada di README utama lab (`../README.md`), bagian
"Fase 2 — Review & Fix".
