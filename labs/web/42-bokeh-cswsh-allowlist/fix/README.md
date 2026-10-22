# Fix — Lab 42

Tulis perbaikanmu di `app/app.py` di folder ini. File itu saat ini salinan
persis aplikasi rentan; verifier mendeteksi "belum dikerjakan" dari situ —
jadi pastikan isinya berubah.

## Ketentuan

- File harus berisi **satu aplikasi utuh** yang tetap bisa jalan dengan
  Dockerfile & compose yang sama (Python 3 stdlib saja).
- Jangan mengubah kontrak aplikasi: rute, nama cookie sesi, format event,
  dan perilaku login harus tetap sama.
- Perbaikan mengikuti pola upstream: pola allowlist non-wildcard hanya
  cocok bila jumlah label host **persis sama** dan seluruh label cocok.

## Yang diperiksa verifier (mode fix)

- Handshake WebSocket dengan Origin asing → 403.
- Handshake WebSocket dengan Origin look-alike (host yang diizinkan sebagai
  awalan, diikuti label lain) → 403.
- Login tetap berfungsi.
- Handshake dari Origin `http://portal.corp` → 101 dan tetap menerima
  event.
- Handshake dengan Origin alamat server sendiri → 101.
- Handshake tanpa Origin → 101.
- Exploit referensi (`solutions/exploit.py`) gagal membuktikan CSWSH.

Acuan lengkap ada di README utama lab (`../README.md`), bagian
"Fase 2 — Review & Fix".
