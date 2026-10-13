# fix/

Tulis perbaikanmu di `fix/app/app.py` — mulai dari salinan `app/app.py` ini.

Syarat fix yang benar:

- Parameter `next` divalidasi sebelum dipakai: hanya path relatif yang
  diizinkan. Nilai dengan skema (`javascript:`, `data:`, `http:`, ...),
  protocol-relative (`//host`), atau backslash → tolak dengan `400`.
- Fail-closed: request ambigu ditolak, bukan di-sanitize diam-diam.
- Fungsi normal utuh: `next=/dashboard` tetap redirect dengan benar,
  kredensial salah tetap `401`, halaman lain tidak berubah.

Verifier membangun ulang image app dari direktori ini (overlay
`docker-compose.fix.yml`), lalu memastikan serangan referensi gagal dan
fungsi normal tetap jalan.
