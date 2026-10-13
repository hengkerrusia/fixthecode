# Lab 26 — OAuth Proxy Open Redirect → ATO (CVE-2023-28131)

**Sumber:** Salt Labs, ["A New OAuth Vulnerability That May Impact Hundreds of Online Services"](https://salt.security/blog/a-new-oauth-vulnerability-that-may-impact-hundreds-of-online-services) (Mei 2023) — CVE-2023-28131, CVSS 9.6, [GHSA-wr5g-q49g-548w](https://github.com/advisories/GHSA-wr5g-q49g-548w).

## Skenario

DemoApp adalah aplikasi mobile yang memakai **OAuth proxy** ala Expo `AuthSession`:
aplikasi tidak bisa menerima redirect langsung dari IdP, jadi memakai perantara.

Alur normal:

1. Aplikasi membuka `GET /start?returnUrl=<URL milik aplikasi>`.
   Proxy menyimpan `returnUrl` di cookie `ru`, lalu mengarahkan browser ke IdP.
2. Korban login di IdP (`/idp`) dan menekan **Approve**.
3. IdP mengarahkan kembali ke `/callback?code=...`.
4. Proxy menukar `code` menjadi `access_token`, lalu mengarahkan browser ke
   URL di cookie `ru` **dengan token ditempel di fragment**:
   `302 Location: <ru>#access_token=<TOKEN>`.
5. Token itu adalah kunci akun korban: `GET /me?access_token=<TOKEN>`
   mengembalikan profil pemilik token.

Penyerang mengendalikan parameter `returnUrl`. Proxy memvalidasi `ru`
sebelum redirect — tapi validasinya cacat.

## Akar Masalah

**Pola umum:** parameter redirect yang dilewati **di titik pasca-autentikasi**
bukan sekadar open redirect biasa. Redirect biasa → phishing. Redirect yang
membawa kredensial (token di fragment/query) → **pencurian token → ATO**.
Setiap `returnUrl`/`redirect_uri`/`continue` yang diproses setelah login
wajib diperlakukan sebagai data sensitif, bukan sekadar "URL tujuan".

**Mekanisme spesifik di sini:** diferensial case-sensitivity + fail-open.

- Standar URL (RFC 3986 §3.1, WHATWG URL) menyatakan **skema tidak case-sensitive**:
  `hTTps://` adalah URL HTTPS yang sah, dan browser menanganinya seperti `https://`.
- Pemeriksa proxy hanya mengenali `https://` **lowercase** (`startswith("https://")`),
  memblokir `http://` lowercase, dan **membiarkan lewat** semua yang tidak dikenalinya.
- Akibatnya `hTTps://attacker/...` lolos dari allowlist maupun blocklist,
  mendarat di cabang default yang mengizinkan — lalu token korban dikirim ke sana.

**Bentuk aman dari pola yang sama:** normalisasi dulu, baru putuskan — tanpa
jalur default yang mengizinkan. Lowercase-kan skema, lalu izinkan hanya kombinasi
yang eksplisit terdaftar (skema `https` + host yang di-allowlist). Yang tidak
cocok → tolak (400), bukan "ya sudah redirect saja".

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** Jalani alur normal dengan `returnUrl=https://app.demo/cb`.
   Amati: cookie `ru` di-set di `/start` dan dibaca di `/callback`;
   `Location` di `/callback` memuat `#access_token=`.
2. **Probe.** Coba varian `returnUrl`: `https://evil.com`,
   `http://app.demo/cb`, `HTTPS://app.demo/cb`. Mana yang 302, mana yang 400?
3. **Diferensial.** Lowercase `https://` ke host asing → 400 (ada allowlist host).
   `http://` → 400. Tapi skema campuran case → 302?!
   Rumuskan hipotesis pemeriksaan yang menghasilkan perilaku itu.
4. **Eksploitasi.** Rangkai alur korban memakai URL penyerang:
   `/start` → simpan cookie → `/idp` → `POST /idp/approve` →
   `/callback?code=...` (dengan cookie) → baca `Location`,
   ekstrak token dari fragment, replay ke `/me`.

Catatan: fragment (`#...`) **tidak pernah dikirim ke server** — jadi "server
penyerang" tidak perlu benar-benar dijalankan. Bukti kebocoran adalah header
`Location` itu sendiri: ia mengarah ke host penyerang dengan token korban
di dalamnya. Di browser nyata, token itu mendarat di halaman penyerang.

### Deliverable

`exploit/exploit.py` dieksekusi verifier dan harus mencetak tepat 4 baris:

```
STATUS: 302
LOCATION: hTTps://127.0.0.1:9/cb#access_token=<token>
TOKEN: <token>
ACCOUNT: victim@demo
```

- `STATUS` = status HTTP respons `/callback` (302 = redirect bocor terjadi).
- `LOCATION` = header `Location` dari `/callback`: harus memakai skema
  campuran-case (bukti diferensial dipakai), mengarah ke host penyerang,
  dan memuat `#access_token=`.
- `TOKEN` = token yang bocor, diekstrak dari fragment `LOCATION`.
- `ACCOUNT` = hasil replay `TOKEN` ke `/me`.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan fungsi validasi redirect-nya, tulis perbaikan di
`fix/app/app.py`. Kriteria lolos:

- Serangan referensi (`hTTps://...`) → **400**, tidak ada token yang bocor.
- Alur normal (`returnUrl=https://app.demo/cb`) tetap 302 dengan token,
  dan `/me` tetap mengenali tokennya.
- Tidak ada jalur fail-open: URL yang tidak dikenal → tolak.

## Perintah

```bash
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix (untuk uji manual)
./lab.sh stop     # hentikan & bersihkan container
```

## Referensi

- Salt Labs, "A New OAuth Vulnerability That May Impact Hundreds of Online Services" (2023) — sumber utama, PoC + dampak ATO di Codecademy.
- CVE-2023-28131 (CVSS 9.6), GitHub Advisory GHSA-wr5g-q49g-548w.
- RFC 3986 §3.1 — skema URI case-insensitive; WHATWG URL Standard — skema di-lowercase saat parsing.
