# Lab 29 — Valve Partner CD Keys IDOR (H1 #391217)

**Sumber:** HackerOne report #391217, moskowsky (2018) — severity Critical,
bounty **$20.000** ($15.000 + bonus) terverifikasi di halaman report.

## Skenario

Portal partner ala Steam: tiap studio partner mengelola game-nya sendiri dan
mengunduh CD key produk lewat endpoint internal:

- `POST /login` `{email, password}` → token sesi (`Authorization: Bearer`).
- `GET /games` → direktori game publik (id + nama).
- `GET /me` → identitas + partner-mu.
- `GET /partnercdkeys/assignkeys?game_id=<ID>` → mengembalikan daftar CD key
  sebuah game.

Akun yang tersedia:

| Email | Password | Partner |
|---|---|---|
| `dev@pixelquest.dev` | `devpw` | `partner_2001` (Pixel Quest Studio) |
| `aaa@galaxyempires.com` | `galaxypw` | `partner_2002` (Galaxy Empires Inc) |

Game yang tersedia:

| ID | Nama | Pemilik |
|---|---|---|
| `game_5001` | Pixel Quest | `partner_2001` |
| `game_5002` | Galaxy Empires | `partner_2002` |

Kamu adalah penyerang: login sebagai `dev@pixelquest.dev` (studio kecil),
lalu tarik **seluruh CD key** milik `game_5002` — game studio lain yang
bukan milikmu. Di kasus aslinya, key game = uang: satu endpoint bocor
berarti seluruh katalog key bisa disedot massal.

## Akar Masalah

**Pola umum:** IDOR (*Insecure Direct Object Reference*), di dunia API
disebut BOLA (*Broken Object Level Authorization*). Server memakai identifier
dari request (`game_id`) untuk memilih objek, tapi **tidak memeriksa apakah
pemanggil berhak atas objek itu**. Autentikasi ("siapa kamu") ada, otorisasi
("bolehkah kamu atas objek ini") tidak.

Bentuk umum polanya: setiap endpoint yang menerima ID objek — `?game_id=`,
`/users/{id}`, `?account_id=` — adalah kandidat. Kalau respons untuk ID
milik orang lain sama lancarnya dengan ID milikmu sendiri, otorisasi
objeknya tidak ada.

**Bentuk aman dari pola yang sama:** sebelum mengembalikan/mengubah objek,
server memeriksa relasi kepemilikan dari **state server-side** (bukan dari
klaim client): `pemilik(game_id) == partner(pemanggil)`. Gagal → 403,
fail-closed. ID yang tidak dikenal → 404.

## Fase 1 — Hacking

### Metodologi

1. **Baseline:** login sebagai `dev@pixelquest.dev`, petakan endpoint yang
   ada. Unduh key game-mu sendiri (`game_5001`) — catat status, bentuk
   respons, dan jumlah key normal.
2. **Probe:** minta key `game_5002` dengan sesi yang sama. Bandingkan:
   apakah server menolak, atau mengembalikan key seperti milikmu sendiri?
3. **Diferensial:** uji batasnya — tanpa token (401?), `game_id` ngawur
   (404?), dan `game_id` milik partner lain. Satu dari tiga ini yang
   menentukan ada/tidaknya otorisasi objek.
4. **Eksploitasi:** tarik seluruh key `game_5002` dan buktikan key-nya asli
   (bukan tebakan): verifier membandingkan key pertamamu dengan key yang
   diambil langsung sebagai pemilik sah.

### Deliverable

`exploit/exploit.py` (stdlib-only) mencetak tepat 4 baris:

```
STATUS: 200
GAME: game_5002
KEYS: 5
KEY1: <cd-key pertama dari game korban>
```

`GAME` harus game milik partner lain; `KEY1` harus key asli yang
benar-benar kamu ekstrak — verifier memvalidasinya lewat oracle independen
(key yang diambil sebagai pemilik sah `game_5002`).

## Fase 2 — Review & Fix

Baca `app/app.py`. Temukan di mana endpoint assignkeys memutuskan
mengembalikan key — dan apa yang **tidak** diperiksa sebelum keputusan itu.

Tulis perbaikan di `fix/app/app.py`:

- `game_id` milik partner lain → **403**, tanpa key bocor.
- `game_id` milik sendiri → tetap 200 + key seperti semula.
- Tanpa token → tetap 401; `game_id` tak dikenal → tetap 404.

Gunakan relasi partner ↔ game yang sudah ada di server. Jangan ubah
perilaku endpoint lain.

## Perintah

```bash
cd labs/web/29-valve-cdkeys-idor
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh stop     # hentikan & bersihkan container
```

Baca `README.md` ini sebelum mulai — di sini ada skenario dan kriteria
suksesnya. Detail kontrak ada di `exploit/README.md`.

## Referensi

- HackerOne #391217 — "Getting all the CD keys of any game" (moskowsky, 2018):
  https://hackerone.com/reports/391217
- OWASP API Security Top 10 (2023), API1:2023 Broken Object Level Authorization:
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/
