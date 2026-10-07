# Lab 14 — CSPT via Plugin Loader → Open Redirect → XSS → SSRF

**Sumber:** Grafana CVE-2025-4123 ("The Grafana Ghost"), ditemukan Alvaro Balada,
diweaponisasi OX Security (2025) —
[advisory Grafana](https://grafana.com/security/security-advisories/cve-2025-4123/),
[riset OX Security](https://www.ox.security/blog/confirmed-critical-the-grafana-ghost-exposes-36-of-public-facing-instances-to-malicious-account-takeover/).
Capstone seri CSPT: CVE real dengan rantai terpanjang.

## Skenario

Aplikasi "DashView" (mini dashboard ala Grafana), satu container:

- `POST /login` (`victim`/`victim123`) → cookie sesi.
- `GET /dashboard?plugin=X` (butuh login) me-render plugin loader:
  `<script src="/public/plugins/X/module.js">` dengan `X` direfleksikan
  **tanpa sanitasi**.
- `GET /go?to=X` → 302 ke `X` tanpa validasi (gadget open redirect;
  tidak eksploitable sendirian).
- `GET /api/render?url=X` (butuh login) → **server men-fetch X dan
  mengembalikan bodinya** (layanan render ala Grafana Image Renderer;
  primitif SSRF).
- Layanan metadata internal di `127.0.0.1:8901` (satu container yang sama,
  **tidak di-map ke host**) → `GET /secret` mengembalikan
  `{"internal_secret": "..."}`. Hanya bisa dijangkau dari dalam server.

Penyerang hanya mengendalikan `plugin` di link yang diklik korban.

## Akar Masalah

**Penyebab umum:** pola yang sama seperti Lab 11–13 — input tak tepercaya
(query string) digabungkan ke URL resource tanpa validasi/normalisasi —
tapi di sini sink-nya adalah **plugin/asset loader**, dan dampaknya
berlipat karena setiap tahap rantai membuka tahap berikutnya:

1. **CSPT di plugin loader** — browser menghitung ulang URL script dari
   dot-segment, persis seperti routing JS Grafana yang menormalisasi URL
   tanpa lewat normalisasi browser.
2. **Open redirect** — gadget yang mengubah traversal menjadi pemuatan
   resource lintas origin.
3. **XSS via plugin jahat** — script penyerang dieksekusi dalam origin
   aplikasi dengan sesi korban (di CVE asli: ganti email → reset password →
   account takeover).
4. **SSRF via layanan render** — kode yang berjalan sebagai korban memakai
   endpoint server-side fetch untuk membaca URL internal (di CVE asli:
   via Grafana Image Renderer → full-read SSRF).

**Bentuk aman:** validasi allowlist untuk nama plugin di trust boundary
server (dan jangan bangun URL resource dari input tak tepercaya);
open redirect diperbaiki dengan allowlist tujuan; endpoint fetch
server-side wajib menolak URL ke alamat internal/loopback/metadata.

## Fase 1 — Hacking

### Metodologi

1. **Baseline:** login, buka `/dashboard?plugin=editor`, amati `<script src>`
   yang di-render. Cek `/go?to=http://example.com/` dan
   `/api/render?url=...` (pakai sesi).
2. **Probe:** selipkan `../` di `plugin` — ke mana URL script dihitung oleh
   browser? Karakter apa yang mengakhiri path di URL?
3. **Diferensial:** script normal (200, JS lokal) vs script hasil traversal
   (302 ke luar).
4. **Eksploitasi:** rangkai traversal → open redirect → plugin JS milikmu.
   Plugin itu "berjalan" sebagai korban: pakai sesi korban untuk memanggil
   `/api/render?url=http://127.0.0.1:8901/secret` dan baca secret-nya.
   Jalankan attacker server sendiri (stdlib).

### Deliverable

`exploit/exploit.py` mencetak ke stdout, baris persis seperti ini:

```text
VICTIM_PLUGIN: <nilai plugin beracun>
STATUS: <kode status HTTP halaman dashboard korban, 3 digit>
LOADED_JS: <URL plugin JS penyerang yang dimuat korban>
EXFILTRATED: <internal secret yang dicuri>
```

`EXFILTRATED` harus sama dengan internal secret milik server.

## Fase 2 — Review & Fix

Baca `app/app.py`. Temukan di mana `plugin` direfleksikan ke `src` tanpa
validasi. Tulis perbaikanmu di `fix/app/app.py`:

- Handler `/dashboard` menolak `plugin` di luar format sah
  (`^[a-z]{3,12}$`) dengan `400`. Ini gerbang yang diverifikasi otomatis —
  tanpa ini, rantai empat tahap tetap hidup.

Lulus bila: serangan referensi gagal total (`GET /dashboard?plugin=<racun>`
→ 400, tidak ada JS penyerang yang dimuat, tidak ada secret bocor)
sementara fungsi normal utuh (`/dashboard?plugin=editor` → 200,
`/go` → 302, `/api/render` tetap bekerja).

## Perintah

```bash
./lab.sh start    # jalankan lab rentan (selalu rebuild dari pristine)
./lab.sh verify   # verifier 2 fase (butuh docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

Lab di `http://localhost:8080`. Restart selalu kembali ke kondisi rentan.

## Referensi

- Grafana security advisory CVE-2025-4123: https://grafana.com/security/security-advisories/cve-2025-4123/
- OX Security — "The Grafana Ghost": https://www.ox.security/blog/confirmed-critical-the-grafana-ghost-exposes-36-of-public-facing-instances-to-malicious-account-takeover/
- Doyensec — "Exploiting Client-Side Path Traversal to Perform Cross-Site Request Forgery": https://blog.doyensec.com/2024/07/02/cspt2csrf.html (fondasi primitif CSPT; dipakai di Lab 11)
