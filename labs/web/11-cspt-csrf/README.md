# Lab 11 — CSPT → CSRF

**Sumber:** Doyensec, "Exploiting Client-Side Path Traversal to Perform Cross-Site Request Forgery — Introducing CSPT2CSRF" (Maxence Schmitt, 2024; [blog](https://blog.doyensec.com/2024/07/02/cspt2csrf.html), whitepaper, talk OWASP AppSec Lisbon 2024). Cerita serangan lab ini mengikuti kasus nyata Erasec ("Client Side Path Manipulation", ~2022): link invite beracun membuat admin yang login membatalkan kartu bank dalam satu klik.

## Skenario

Aplikasi demo invite. Ada satu korban: `victim` / `victim123`, pemilik satu kartu.

- `GET /invite?code=X` — halaman invite. JavaScript-nya (`/static/invite.js`, ikut di-serve ke browser sehingga terlihat secara black-box) membaca `code` dari query string lalu:
  `fetch("/api/invite/" + code + "/check", {method: "POST", headers: {"X-XSRF-Token": ...}})`
- `POST /api/cards/<uuid>/cancel` — endpoint state-changing yang membatalkan kartu. Diamankan berlapis: cookie sesi `SameSite=Lax` + `HttpOnly`, token XSRF synchronizer (header `X-XSRF-Token`), dan cek `Origin`.

Penyerang hanya mengendalikan **path** request — lewat nilai `code` di link yang diklik korban.

## Akar Masalah

**Penyebab umum (bentuk umum polanya):** frontend membangun URL request dari input tak tepercaya (query string, fragment, path param, nilai tersimpan) **tanpa validasi/normalisasi**. Dot-segment (`../`) di path di-resolve oleh browser mengikuti standar WHATWG URL — sehingga request mendarat di endpoint yang sama sekali berbeda dari maksud developer — sementara browser tetap melampirkan **seluruh otoritas ambient korban**: cookie, token CSRF, custom header, dan konteks same-origin.

**Mengapa semua pertahanan CSRF gagal:** SameSite (navigasi top-level korban ke link invite adalah same-site), synchronizer token (JS aplikasi *sendiri* yang melampirkannya ke request yang di-re-target), cek Origin/Referer (request memang same-origin), custom header & Fetch Metadata (fetch same-origin oleh JS halaman). Semuanya berdiri di atas satu asumsi: *aplikasi yang memilih target request*. CSPT mematahkan asumsi itu — penyerang memilih target, browser menyuplai kredensial.

**Bentuk aman dari pola yang sama:** jangan pernah membangun path request dari input tak tepercaya; validasi allowlist di sisi klien sebelum URL dibentuk (mis. regex format kode); allowlist endpoint; dan defense in depth — validasi ulang di trust boundary server (tolak `..`, `/`, dan karakter di luar format yang sah dengan 400).

## Fase 1 — Hacking

### Metodologi

1. **Baseline:** login sebagai victim, buka `/invite?code=INV123ABC`, amati request apa yang dikirim JS (baca `invite.js` — ia di-serve ke browser).
2. **Probe:** ubah-ubah `code`, perhatikan URL fetch yang terbentuk. Coba selipkan `../` — apa yang dilakukan browser terhadap dot-segment di path?
3. **Diferensial:** bandingkan request normal vs request dengan `code` beracun: path tujuan berubah, tetapi cookie/token/Origin tetap menempel.
4. **Eksploitasi:** racun `code` agar request mendarat di `POST /api/cards/<uuid>/cancel`. Ingat JS menempelkan `/check` di belakang — pikirkan cara "menelan" sisa itu (petunjuk: karakter apa yang mengakhiri path di URL?).

Kamu mensimulasikan **browser korban** (Python stdlib): login sebagai victim, "kunjungi" link beracun, tiru persis penggabungan URL ala `invite.js` + normalisasi dot-segment ala browser, kirim dengan sesi korban. Di dunia nyata, langkah 2–4 dikerjakan browser korban saat ia mengklik link — skripmu adalah replika setianya.

### Deliverable

`exploit/exploit.py` mencetak ke stdout, baris persis seperti ini:

```text
VICTIM_CODE: <kode invite beracun>
STATUS: <kode status HTTP, 3 digit>
CANCELLED_CARD: <uuid kartu>
```

Verifier menjalankan skripmu lalu **memeriksa status kartu via API secara independen** — kartu korban harus `cancelled`.

## Fase 2 — Review & Fix

Baca `app/app.py` dan `app/static/invite.js`. Temukan di mana input tak tepercaya mengalir ke konstruksi URL tanpa validasi. Tulis perbaikanmu di dua tempat:

1. `fix/app/static/invite.js` — validasi `code` dengan allowlist regex **sebelum** fetch (lapis pertama, sisi klien).
2. `fix/app/app.py` — handler `/invite` menolak `code` di luar format sah dengan `400` (gerbang yang diverifikasi otomatis; tanpa ini, link beracun tetap me-render halaman dan rantai serangan tetap hidup).

Lulus bila: serangan referensi gagal total (`GET /invite?code=<racun>` → 400, kartu tidak terbatalkan) sementara fungsi normal utuh (login, `/invite?code=INV123ABC` → 200, check → 200).

## Perintah

```bash
./lab.sh start    # jalankan lab rentan (selalu rebuild dari pristine)
./lab.sh verify   # verifier 2 fase (butuh docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

Lab di `http://localhost:8080`. Restart selalu kembali ke kondisi rentan (state kartu di-reset).

## Referensi

- Doyensec — "Exploiting Client-Side Path Traversal to Perform Cross-Site Request Forgery": https://blog.doyensec.com/2024/07/02/cspt2csrf.html
- Doyensec CSPT2CSRF whitepaper: https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf
- Erasec — "Client Side Path Manipulation": https://www.erasec.be/blog/client-side-path-manipulation/
