# Lab 12 — CSPT → Web Cache Deception → Account Takeover

**Sumber:** zere.es, "Cache Deception + CSPT: Turning Non Impactful Findings into Account Takeover" (2025, [tulisan asli](https://zere.es/posts/cache-deception-cspt-account-takeover/)) — rantai nyata dari audit program bounty privat.

## Skenario

Dua komponen: `app` (Python) di belakang `cache` (nginx, ala CDN).

- `GET /profile?id=X` — halaman profil. JavaScript-nya (`/static/profile.js`, ikut di-serve ke browser sehingga terlihat secara black-box) membaca `id` dari query string lalu:
  `fetch("/v1/users/info/" + userId, {headers: {"X-Auth-Token": ...}})`
- `GET /v1/token.css` — endpoint "gadget": mengembalikan token korban sebagai JSON **dengan `Cache-Control: public`**, tetapi **butuh `X-Auth-Token`**. Diakses langsung tanpa auth → 401. Sendirian, temuan ini tidak eksploitable.
- nginx meng-cache path berakhiran `.css` (aturan berbasis ekstensi), dengan **cache key yang tidak mencakup header auth**. Keputusan cache mengikuti header `Cache-Control` upstream.

Korban: `victim` / `victim123`. Penyerang hanya mengendalikan `id` di link yang diklik korban, lalu membaca cache tanpa auth.

## Topologi

```
korban/penyerang
      │  (semua request lewat cache)
      ▼
┌───────────┐      ┌───────────┐
│   cache   │─────▶│    app    │
│  (nginx)  │◀─────│ (python)  │
└───────────┘      └───────────┘
  :8080 → :80         :8000
```

## Akar Masalah

**Dua akar yang bertemu di satu rantai:**

1. **CSPT (kerentanan yang diperbaiki lab ini):** bentuk umumnya sama seperti Lab 11 — frontend membangun URL request dari input tak tepercaya tanpa validasi/normalisasi; browser me-resolve dot-segment sehingga request mendarat di endpoint lain sementara otoritas ambient korban (di sini: header `X-Auth-Token`) menempel otomatis.
2. **Web cache deception (gadget skenario):** respons terautentikasi diberi `Cache-Control: public` + path yang terlihat statis (`.css`) + cache key yang tidak mencakup header auth. Masing-masing faktor ini kecil; bersama-sama mereka membuat respons milik korban bisa disajikan ke orang lain.

**Bentuk aman:** (a) jangan bangun path dari input tak tepercaya — validasi allowlist di klien dan di trust boundary server; (b) jangan pernah kirim `Cache-Control: public` untuk respons terautentikasi; (c) `Vary` pada header auth, atau kecualikan endpoint sensitif dari aturan cache berbasis ekstensi. Lab ini menuntut (a); (b)–(c) adalah defense in depth yang sah.

## Fase 1 — Hacking

### Metodologi

1. **Baseline:** login, buka `/profile?id=user123`, amati request JS dan header `X-Cache-Status` di setiap respons (MISS/HIT/BYPASS).
2. **Probe cache:** `GET /v1/token.css` tanpa auth → 401. Dengan auth → 200 + `Cache-Control: public`. Minta dua kali: apa kata `X-Cache-Status`? Mengapa request keduamu (tanpa auth) tidak mendapat HIT?
3. **Probe CSPT:** baca `profile.js`. Racuni `id` agar fetch mendarat di endpoint token. Berapa `../` yang dibutuhkan dari `/v1/users/info/`?
4. **Diferensial:** bandingkan request korban (dengan token → MISS, respons masuk cache) vs request penyerang tanpa auth (HIT, isi milik korban).
5. **Eksploitasi:** rangkai semuanya — simulasi browser korban **melewati cache**, lalu bertukar peran menjadi penyerang tanpa auth yang memanen token dari cache, dan buktikan ATO via `/v1/users/me`.

Kamu mensimulasikan **browser korban** (Python stdlib): login sebagai victim, "kunjungi" link beracun lewat `127.0.0.1:8080`, tiru persis penggabungan URL ala `profile.js` + normalisasi dot-segment ala browser, kirim dengan token korban.

### Deliverable

`exploit/exploit.py` mencetak ke stdout, baris persis seperti ini:

```text
VICTIM_ID: <nilai id beracun>
STATUS: <kode status HTTP, 3 digit>
STOLEN_TOKEN: <token korban>
```

Verifier menjalankan skripmu lalu **memeriksa token di cache via request independen** — token curian harus sama dengan token korban.

## Fase 2 — Review & Fix

Baca `app/app.py` dan `app/static/profile.js`. Temukan di mana input tak tepercaya mengalir ke konstruksi URL tanpa validasi. Tulis perbaikanmu di dua tempat:

1. `fix/app/static/profile.js` — validasi `id` dengan allowlist regex **sebelum** fetch (lapis pertama, sisi klien).
2. `fix/app/app.py` — handler `/profile` menolak `id` di luar format sah dengan `400` (gerbang yang diverifikasi otomatis; tanpa ini, link beracun tetap me-render halaman dan rantai serangan tetap hidup).

Lulus bila: serangan referensi gagal total (`GET /profile?id=<racun>` → 400, penyerang dapat 401, token tidak bocor) sementara fungsi normal utuh (login, `/profile?id=user123` → 200, info → 200).

## Perintah

```bash
./lab.sh start    # jalankan lab rentan (selalu rebuild dari pristine)
./lab.sh verify   # verifier 2 fase (butuh docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

Lab di `http://localhost:8080` (nginx). Restart selalu kembali ke kondisi rentan (state + cache di-reset).

## Referensi

- zere.es — "Cache Deception + CSPT: Turning Non Impactful Findings into Account Takeover": https://zere.es/posts/cache-deception-cspt-account-takeover/
- Doyensec — "Exploiting Client-Side Path Traversal to Perform Cross-Site Request Forgery": https://blog.doyensec.com/2024/07/02/cspt2csrf.html (fondasi primitif CSPT; dipakai di Lab 11)
