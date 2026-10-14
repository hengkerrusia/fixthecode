# Lab 32 — Indico BOLA `/api/principals` → PII exposure

Sumber: [CVE-2025-53640](https://github.com/rafaelcorvino1/CVE-2025-53640) —
researcher **rafaelcorvino1**, ditemukan saat Red Team Residency di RNP (Brasil),
dilaporkan ke maintainer **Indico** (platform event/conference CERN) tahun 2025.
Terdampak Indico 2.2–3.3.6, diperbaiki di **3.3.7**. CWE-639.

## Skenario

Mock API ala Indico. Endpoint `/api/principals` semula dibuat untuk me-resolve ID
user di field form tertentu — tapi bisa dipakai untuk mengambil data pribadi **ID
user arbitrer**. Satu akun attacker tersedia:

| Akun | Email | Password | user_id |
|---|---|---|---|
| analyst | `analyst@lab.test` | `analyst-pw` | `User:100` |

Plus 5 user lain (`User:1` … `User:5`) dengan nama, email, afiliasi, title, avatar.

Endpoint:

- `POST /login` `{"email","password"}` → `{"token"}`
- `GET /me` (Bearer token) → `{"user_id","email"}`
- `POST /api/principals` (auth) `{"values": ["User:1", "User:2"]}` →
  `{"User:1": {"first_name":..., "last_name":..., "email":..., "affiliation":...,
  "title":..., "avatar_url":...}, "User:99": {"invalid": true}}`

Catatan: di kasus asli, kebanyakan instance Indico publik membolehkan self-registration
tanpa verifikasi email — sehingga "butuh auth" praktis setara "siapa pun bisa daftar".
Lab ini memberi akun analyst langsung; tantangannya tetap pada otorisasinya.

## Akar Masalah

**BOLA: endpoint utilitas tanpa otorisasi level objek.** Autentikasi ada (token wajib),
tetapi server tidak memeriksa *apakah pemanggil berhak melihat objek yang diminta* —
ID apa pun yang valid langsung di-resolve ke data pribadi. Diperparah dua faktor:

1. **ID predictable & sequential** (`User:1`, `User:2`, …) → enumerasi massal trivial,
   cukup loop angka sampai `invalid` beruntun.
2. **Field berlebihan** — endpoint utilitas mengembalikan PII lengkap (email, afiliasi)
   padahal kebutuhannya mungkin cuma nama tampilan.

Pola ini berima dengan Lab 29 (Valve): autentikasi ≠ otorisasi. Bedanya, di sini
primitifnya *enumerasi massal PII*, bukan ekstraksi satu objek milik korban.

Bentuk amannya:

1. Otorisasi per objek: resolve hanya principal yang berhak dilihat pemanggil
   (paling ketat: hanya miliknya sendiri).
2. Batasi field yang dikembalikan sesuai kebutuhan.
3. Di dunia nyata (fix Indico 3.3.7): cegah dump massal via ID predictable + flag
   `ALLOW_PUBLIC_USER_SEARCH`.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai analyst → token. `POST /api/principals` dengan
   `{"values": ["User:100"]}` → 200, data diri sendiri. Coba `{"values":
   ["User:999"]}` → 200 dengan `{"invalid": true}`. Tanpa token → 401.
2. **Probe**: minta principal **bukan milikmu**: `{"values": ["User:1"]}`.
   Perhatikan: apakah server menolak, atau mengembalikan PII?
3. **Diferensial**: `User:100` (milikmu) vs `User:1` (orang lain) → respons identik
   berisi PII. Server tidak membedakan kepemilikan — sinyal BOLA.
4. **Eksploitasi**: loop `User:1`, `User:2`, … sampai N respons `invalid` beruntun
   (N=10, ala PoC asli); kumpulkan semua PII yang valid.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat tiga baris:

```text
STATUS: 200
COUNT: <jumlah user valid yang ter-enumerasi>
EMAIL1: <email milik User:1>
```

Verifier memvalidasi secara independen: ia login sendiri, me-resolve `User:1`, dan
membandingkan EMAIL1; ia juga menghitung sendiri jumlah user valid dan
membandingkannya dengan COUNT.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan di mana principal di-resolve tanpa cek kepemilikan.
Tulis perbaikan di `fix/app/app.py`:

- Hanya principal milik sesi yang boleh di-resolve; ID lain → `{"invalid": true}`
  (fail-closed, tak membocorkan keberadaan user).
- Fungsi normal tetap utuh: resolve diri sendiri → 200 + data; ID tak dikenal →
  `invalid`; tanpa token → 401.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://github.com/rafaelcorvino1/CVE-2025-53640 (PoC + analisis teknis)
- NVD: CVE-2025-53640 · CWE-639 (Authorization Bypass Through User-Controlled Key)
- OWASP API Security — API1:2023 Broken Object Level Authorization
