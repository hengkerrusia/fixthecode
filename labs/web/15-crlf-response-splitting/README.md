# Lab 15 — CRLF Injection → Response Splitting → Session Fixation (Pi-hole CVE-2025-59151)

Layanan shortlink legacy me-redirect `/r/<nama>` ke `/files/<nama>` dengan nilai
`Location` yang dibangun dari input user. Input yang mengandung CR/LF lolos ke
header respons → injeksi header arbitrer → session fixation via `Set-Cookie` suntikan.

## Skenario

Aplikasi demo "Shortlink Service":

- `GET /` — halaman depan (menyebut link legacy di bawah `/r/`).
- `GET /login` — menerbitkan cookie `session` acak.
- `GET /dashboard` — butuh cookie `session` yang valid (401 tanpa sesi).
- `GET /r/<nama>` — redirect 302 legacy ke `/files/<nama>`.
- `GET /files/<nama>` — halaman file generik.

Konteks dunia nyata: Pi-hole web interface < 6.3 me-redirect request ke file `*.lp`
dengan path yang tidak disanitasi direfleksikan ke header `Location`
([GHSA-5v79-p56f-x7c4](https://github.com/pi-hole/web/security/advisories/GHSA-5v79-p56f-x7c4),
CVE-2025-59151, fixed di 6.3). PoC aslinya satu URL:
`/admin/index%0d%0aSet-Cookie:%20sid=INYECTED.lp` — tanpa autentikasi.

## Akar Masalah

**Penyebab umum.** Header HTTP dipisahkan oleh CRLF (`\r\n`). Ketika aplikasi
menaruh input user — setelah di-decode — ke dalam nilai header respons tanpa
menetralkan CR/LF, penyerang bisa menyuntik header arbitrer (`Set-Cookie`,
`Location`, pelemahan `Content-Security-Policy`) atau, dengan CRLF ganda,
mem-split respons menjadi dua. Framework web modern men-strip CR/LF di API
header-nya (`setHeader()` dan sejenisnya), sehingga bug ini punah di jalur
framework — tapi tetap hidup di kode **hand-rolled**: redirect custom, rewrite
manual, dan sink di bawah framework (multipart, log, HTTP client).

**Bentuk aman dari pola yang sama.** Jangan pernah menaruh input user mentah ke
nilai header. Pilih salah satu, secara fail-closed:
- tolak request bila input (setelah decode) mengandung `\r` atau `\n` (400), atau
- strip/percent-encode CR/LF sebelum refleksi.

Yang tidak boleh: "sanitasi" dengan blacklist parsial atau mengandalkan WAF —
keduanya rapuh dan gampang di-bypass (mis. via encoding ganda).

## Fase 1 — Hacking (black-box)

Hanya berbekal README ini, tanpa membaca code.

### Metodologi

1. **Baseline** — petakan perilaku normal tiap endpoint: `/`, `/login`,
   `/dashboard` (dengan/tanpa sesi), `/r/<nama>`, `/files/<nama>`. Catat status
   dan header `Location` pada redirect normal.
2. **Probe** — `/r/` merefleksikan input ke header `Location`. Kirim varian:
   karakter spesial URL (`%0d`, `%0a`, `%0d%0a`), lalu amati *diferensial* pada
   header respons — bukan body-nya.
3. **Diferensial** — temukan input yang membuat header *tambahan* muncul di respons.
   Header apa yang paling bernilai untuk disuntik bila tujuannya membajak sesi?
4. **Eksploitasi** — suntik `Set-Cookie: session=<nilai-pilihanmu>` lewat celah itu
   dan buktikan nilai tersebut muncul sebagai header respons yang sah.

### Deliverable

`exploit/exploit.py` dieksekusi dan harus mencetak, baris persis seperti ini:

```text
STATUS: 302
INJECTED: <nilai session yang kamu suntik, alfanumerik>
```

Verifier menilai:
- `STATUS` harus `302` (redirect yang membawa header suntikan).
- Verifier mengirim ulang racun dengan nilai `INJECTED`-mu dan memastikan
  respons mentah benar-benar mengandung header `Set-Cookie: session=<nilai>`.

Jangan menembak buta: pastikan redirect normal (`/r/<nama-biasa>`) me-render
302 dengan `Location` yang benar *sebelum* mengirim racun.

## Fase 2 — Review & Fix

Alur: baca code aplikasi → temukan di mana input yang sudah di-decode mengalir
ke header respons tanpa netralisasi → tulis perbaikan di `fix/app/app.py`.

Kriteria fix yang benar:
- Request beracun ditolak secara fail-closed (400) — tidak ada header suntikan
  yang lolos, dalam bentuk apa pun.
- Fungsi normal tetap utuh: `/r/<nama-biasa>` tetap 302 ke `/files/<nama-biasa>`,
  `/login`, `/dashboard`, `/files/` berperilaku seperti semula.

Pikirkan: di lapisan mana trust boundary yang benar untuk menghentikan aliran ini —
di titik refleksi, atau di tempat lain?

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi 2 fase
./lab.sh fix-up   # jalankan dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan
```

## Referensi

- Pi-hole web security advisory GHSA-5v79-p56f-x7c4 (CVE-2025-59151) —
  https://github.com/pi-hole/web/security/advisories/GHSA-5v79-p56f-x7c4
- PortSwigger Research, "CRLF-Powered Desync Attacks: Beheading HTTP Streams" (2026) —
  https://portswigger.net/research/crlf-powered-desync-attacks
