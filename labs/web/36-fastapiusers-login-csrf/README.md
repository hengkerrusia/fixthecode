# Lab 36 — fastapi-users login CSRF → OAuth account linking → ATO

Sumber: [vendor advisory fastapi-users GHSA-5j53-63w8-8625](https://github.com/fastapi-users/fastapi-users/security/advisories/GHSA-5j53-63w8-8625)
(CVE-2025-68481). Terdampak library autentikasi Python/FastAPI **fastapi-users
< 15.0.1**, diperbaiki di **15.0.2** (double-submit cookie). Ini lab kedua seri
CSRF: token-nya *ada* (state JWT bertanda tangan), tetapi tidak terikat ke
sesi browser yang memulai alur.

## Skenario

Mock aplikasi demo dengan login SSO (OAuth), memodelkan `fastapi_users/router/oauth.py`
versi rentan. Ada provider SSO stub di dalam lab (mensimulasikan akun SSO
milik penyerang dan korban).

- `GET /` → panel demo (HTML generik)
- `POST /register` (form: `username`, `password`) → 200
- `POST /login` (form: `username`, `password`) → 200 + cookie sesi `session`
- `GET /me` (cookie sesi) → identitas user (oracle lab)
- `GET /oauth/authorize` (publik, tanpa auth) → 200 + `authorization_url`
- `GET /provider/login?as=attacker|victim` → cookie `psession` (stub: login ke
  provider SSO)
- `GET /provider/authorize?...&state=...` (cookie `psession`) → 302 ke
  `/oauth/callback?code=...&state=...` (stub: user menekan "Authorize")
- `GET /oauth/callback?code=...&state=...` → menukar `code` jadi identitas SSO,
  lalu: kalau request membawa cookie sesi aplikasi → identitas SSO di-link ke
  user yang sedang login; kalau tidak → login/buat user pemilik identitas itu

Catatan: ini mock ringan (library aslinya FastAPI). Rantai serangannya setia
pada advisory: penyerang menyiapkan URL callback yang sudah lengkap
(`code`+`state` miliknya), lalu satu klik korban ("1-click") membuat identitas
SSO penyerang ter-link ke akun korban → penyerang login via SSO sebagai korban.

## Akar Masalah

**Token anti-CSRF yang tidak terikat ke sesi peminta sama saja tidak ada —
penyerang bisa memakai token buatannya sendiri.**

Tiga fakta yang dirangkai menjadi serangan:

1. **State token itu stateless dan generik.** `generate_state_token()`
   dipanggil dengan `state_data` kosong — JWT-nya hanya berisi audience tetap
   dan expiry. Token yang diterbitkan untuk penyerang valid untuk dipakai di
   browser siapa pun.
2. **Callback hanya memverifikasi tanda tangan + expiry.** Tidak ada usaha
   mencocokkan state dengan browser yang memulai alur: tanpa correlation
   cookie, tanpa cache server-side.
3. **Callback yang terautentikasi = operasi linking.** Kalau korban sedang
   login saat mengunjungi URL callback jebakan, identitas SSO penyerang
   di-link ke akun korban. Setelah itu penyerang login via SSO → masuk
   sebagai korban (ATO).

Ini pola umum "login CSRF": yang dicuri bukan sesi korban, melainkan *niat* —
browser korban dipakai untuk menyelesaikan alur yang dimulai penyerang.

Bentuk amannya (persis patch upstream 15.0.2):

1. Nilai acak tak tertebak disematkan ke dalam state token **dan** ke cookie
   (`oauth_csrf`, HttpOnly, SameSite=Lax) saat authorize.
2. Callback membandingkan keduanya dengan `hmac.compare_digest` — hilang /
   tidak cocok → 400 (fail-closed). Cookie tidak bisa dipasang penyerang
   lintas-origin, jadi token curian tidak berguna di browser korban.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: `POST /register` + `POST /login` sebagai korban → cookie
   sesi. `GET /me` → identitas korban. `GET /oauth/authorize` → amati
   `authorization_url` (publik — butuh auth apa?).
2. **Probe**: `GET /provider/login?as=attacker` → `psession`. Kunjungi
   `authorization_url` dengan cookie itu → tangkap URL redirect final ke
   `/oauth/callback`. Apa saja yang dibawa URL itu?
3. **Diferensial**: buka URL callback tersebut dengan cookie sesi korban
   ("browser korban" membuka link jebakan 1-klik). Cek `GET /me` korban —
   apa yang berubah pada akunnya?
4. **Eksploitasi**: dari sesi bersih, jalani alur SSO lengkap sebagai
   penyerang (authorize → provider → callback) → catat cookie sesi yang
   diberikan → `GET /me` → identitas siapa?

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat tiga baris:

```text
STATUS: 200
VICTIM: <username korban yang kamu buat>
ATO_TOKEN: <cookie sesi>
```

`VICTIM` adalah username korban yang kamu daftarkan, `ATO_TOKEN` adalah nilai
cookie `session=` yang kamu peroleh dari login SSO sebagai penyerang —
verifier memakainya untuk `GET /me` (memastikan `username`-nya korban dan
akunnya ter-link ke SSO penyerang) lalu me-replay login SSO sebagai penyerang
secara independen untuk memastikan takeover-nya nyata.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan titiknya: state token tidak terikat ke sesi
pemicu, callback tidak memverifikasi pengikat apa pun. Tulis perbaikan di
`fix/app/app.py`:

- Saat authorize: bangkitkan nilai acak tak tertebak, sematkan ke state token
  dan ke cookie HttpOnly (+SameSite=Lax).
- Saat callback: bandingkan keduanya secara constant-time; hilang/tidak
  cocok → 400 (fail-closed), dalam kondisi apa pun.
- Fungsi normal tetap utuh: register/login lokal; alur SSO lengkap untuk user
  baru maupun linking ke user yang sudah login.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://github.com/fastapi-users/fastapi-users/security/advisories/GHSA-5j53-63w8-8625 (vendor advisory)
- https://nvd.nist.gov/vuln/detail/CVE-2025-68481 (NVD)
- https://github.com/fastapi-users/fastapi-users/commit/7cf413cd766b9cb0ab323ce424ddab2c0d235932 (patch: double-submit cookie di alur OAuth)
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet
