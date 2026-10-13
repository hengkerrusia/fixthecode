# fix/

Salin `../app/app.py` ke `fix/app/app.py` (sudah disediakan sebagai scaffold),
lalu perbaiki `KA_DOMAIN_REGEX`.

Syarat fix yang benar:

- Domain penyerang bentuk `...-uc-a-run.app` (strip) harus DITOLAK (400).
- Yang legitimate tetap lolos: `khanacademy.org` (+ subdomain),
  `kastatic.org`, dan subdomain bertitik asli `...-uc.a.run.app`.
- Perbaikan minimal dan tepat: satu karakter regex yang salah.

Jangan ubah alur normal: login → 302 dengan token transfer → replay →
cookie sesi → `/me` tetap berfungsi.
