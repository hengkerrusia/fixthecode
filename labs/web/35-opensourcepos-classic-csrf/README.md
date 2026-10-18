# Lab 35 — OpenSourcePOS classic CSRF → rogue admin → takeover

Sumber: [vendor advisory OpenSourcePOS GHSA-wjm4-hfwg-5w5r](https://github.com/opensourcepos/opensourcepos/security/advisories/GHSA-wjm4-hfwg-5w5r)
(CVE-2025-68434). Terdampak OpenSourcePOS (PHP/CodeIgniter) **3.4.0–3.4.1**,
diperbaiki di **3.4.2**. CVSS 3.1 **8.8** (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H),
CWE-352. Ini lab pembuka seri CSRF: varian paling murni — tidak ada token
sama sekali.

## Skenario

Mock panel admin POS dengan satu admin bawaan (`admin` / `admin-pw`).
Autentikasi memakai cookie sesi, dan endpoint administratif menerima POST
**hanya bermodal cookie sesi** — persis kondisi OpenSourcePOS 3.4.0/3.4.1 yang
filter CSRF globalnya dikomentari di `app/Config/Filters.php`
(`// 'csrf' => ['except' => 'login'], // TODO: Temporarily disable CSRF…`).

- `GET /` → panel admin (HTML generik)
- `POST /login` (form: `username`, `password`) → 200 + cookie sesi `session`
- `GET /me` (cookie sesi) → info sesi (harness lab)
- `GET /users` (cookie sesi admin) → daftar user (harness lab)
- `POST /users` (form: `username`, `password`, `is_admin`, …; cookie sesi
  admin) → membuat user baru

Catatan: ini mock ringan (OpenSourcePOS asli aplikasi PHP yang berat).
`POST /users` memodelkan endpoint pembuatan akun administratif di advisory —
rantai serangannya setia pada PoC publik: halaman jebakan dengan form
auto-submit, dikunjungi admin yang sedang login → akun administrator baru
tercipta diam-diam → takeover penuh sistem kasir.

## Akar Masalah

**CSRF klasik: server tidak bisa membedakan klik sah dari request tempaan
karena tidak ada rahasia yang hanya diketahui pihak sah.**

Tiga fakta yang dirangkai menjadi serangan:

1. **Browser melampirkan cookie secara otomatis.** Cookie sesi dikirim ke
   setiap request ke origin itu — termasuk request yang dipicu halaman
   *orang lain* (form auto-submit, `img`, fetch). Penyerang tidak perlu
   mencuri cookie; browser korban yang mengantarnya.
2. **Tidak ada token yang tak tertebak.** Satu-satunya kredensial pada
   request adalah cookie — yang justru dikirim otomatis. Tidak ada field
   tersembunyi, header khusus, atau challenge yang hanya bisa dipenuhi oleh
   halaman asli.
3. **POST state-changing tanpa verifikasi asal.** Server memeriksa *siapa*
   (sesi admin valid) tetapi tidak memeriksa *apakah admin yang menghendaki*
   (niat). Akibatnya request tempaan lolos sebagai "perintah admin".

Ini baseline seluruh seri CSRF: lab-lab berikutnya punya token/mekanisme
pertahanan, tetapi gagal dengan cara yang lebih halus (token tidak terikat
sesi, cookie-scoping, validasi kondisional).

Bentuk amannya:

1. Token CSRF per-sesi yang tak tertebak, wajib di setiap request
   state-changing (field form atau header kustom) — penyerang lintas-origin
   tidak bisa membaca maupun menebaknya (SOP melindunginya).
2. Validasi fail-closed: token hilang/tidak cocok → 403, tanpa kecuali.
3. `SameSite=Lax` pada cookie sesi sebagai pertahanan lapis kedua — bukan
   satu-satunya (lihat Lab lanjutan seri ini kenapa ia bisa di-bypass).

Perbaikan kanonis: persis saran advisory — aktifkan kembali filter CSRF
(commit `d575c8da`).

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: `GET /` → 200. `POST /login` sebagai admin → cookie sesi.
   `GET /me` → `is_admin: true`. `POST /users` tanpa sesi → 401
   (autentikasi bekerja — yang rusak bukan itu).
2. **Probe**: `POST /users` sebagai admin, hanya dengan cookie sesi — tanpa
   field/header tambahan apa pun. Apa yang diperiksa server selain cookie?
3. **Diferensial**: request "resmi" dari panel vs request tempaan mentah —
   keduanya diterima identik. Tidak ada pembeda niat di mana pun.
4. **Eksploitasi**: jadilah "browser korban" — kirim POST tempaan persis
   seperti yang dikirim browser admin saat membuka halaman jebakan (cookie
   sesi terlampir otomatis, tanpa token), buat akun admin baru → login
   sebagai akun itu → ATO terbukti via `/me`.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat dua baris:

```text
STATUS: 200
ADMIN_TOKEN: <cookie sesi hasil login sebagai admin barumu>
```

`ADMIN_TOKEN` adalah nilai cookie `session=` milik admin yang kamu buat —
verifier memakainya untuk `GET /me` dan memastikan `is_admin` true.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan titiknya: `POST /users` hanya memeriksa sesi.
Tulis perbaikan di `fix/app/app.py`:

- Terbitkan token CSRF per-sesi yang tak tertebak saat login.
- `POST /users` wajib membawa token yang cocok (field `csrf_token` atau
  header `X-CSRF-Token`); hilang/tidak cocok → 403 (fail-closed).
- Fungsi normal tetap utuh: login → 200 + sesi; pembuatan user dengan token
  valid → 200; `/me` tetap benar.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://github.com/opensourcepos/opensourcepos/security/advisories/GHSA-wjm4-hfwg-5w5r (vendor advisory)
- https://nvd.nist.gov/vuln/detail/CVE-2025-68434 (NVD)
- https://github.com/opensourcepos/opensourcepos/commit/d575c8da9a1d7af8313a1e758e000e243f5614ef (patch: filter CSRF diaktifkan kembali)
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet
