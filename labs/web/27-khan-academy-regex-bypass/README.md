# Lab 27 — Regex Bypass → 1-Click ATO (HackerOne #3723458)

**Sumber:** HackerOne report #3723458, "1-Click Account Takeover via Open Redirect
through Regex Bypass in Domain Validation" (Khan Academy, 2026).

## Skenario

Demo Academy punya halaman login dengan parameter `continue`: setelah korban
login, aplikasi mengarahkan browser ke URL `continue` **sambil menempelkan
token transfer satu-kali pakai**:

```
POST /login (username, password, continue) → 302
Location: <continue>/transfer_auth?key=<TOKEN>
```

Token itu bisa di-replay ke endpoint resmi: `GET /transfer_auth?key=<TOKEN>`
menerbitkan cookie sesi penuh (KAAS/KAAL/KAAC) — siapa pun yang memegang token
mendapat sesi korban. Inilah primitif ATO-nya.

Agar `continue` tidak bisa diarahkan ke situs penyerang, aplikasi memvalidasi
hostname-nya dengan regex allowlist `KA_DOMAIN_REGEX` (lihat `app/app.py`).
Regex itu cacat.

## Akar Masalah

**Pola umum:** parameter redirect pasca-login yang **membawa kredensial**
(`continue` + token transfer) adalah rantai ATO, bukan sekadar open redirect.
Setiap pengalihan yang terjadi setelah autentikasi dan menempelkan token/session
ke URL tujuan wajib diperlakukan sebagai data sensitif.

**Mekanisme spesifik di sini:** titik yang tidak di-escape di regex.

- Di regex, `.` artinya "karakter apa saja" — untuk mencocokkan titik literal
  harus ditulis `\.`.
- Penulis allowlist bermaksud mengizinkan domain literal `...-uc.a.run.app`
  (titik-titik itu nama host asli), tapi menuliskannya tanpa escape.
- Akibatnya pola juga cocok dengan `...-uc-a-run.app` (strip), sehingga
  domain milik penyerang lolos validasi.

**Bentuk aman dari pola yang sama:** escape setiap titik literal (`\.`);
lebih baik lagi, hindari regex untuk daftar host — parse hostname lalu
bandingkan dengan daftar suffix yang eksplisit. Defense-in-depth: token
transfer harus satu-kali pakai, berumur pendek, dan terikat sesi.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** `POST /login` dengan `continue=https://www.khanacademy.org/`
   → 302 ke `/transfer_auth?key=...`. Replay `key` ke `/transfer_auth`
   → cookie sesi. Buka `/me` dengan cookie itu → identitas korban.
2. **Probe.** Coba `continue` ke host asing (`https://evil.com/`) → 400.
   Coba varian host yang mirip pola allowlist. Pola mana yang lolos?
3. **Diferensial.** Baca `KA_DOMAIN_REGEX` di `app/app.py` (fase 2 baru baca
   code — di fase 1, simpulkan dari perilaku). Satu karakter regex membuat
   domain penyerang yang "hampir sama" lolos.
4. **Eksploitasi.** Rangkai 1-klik: `POST /login` dengan `continue` milik
   penyerang → ambil token dari `Location` → replay ke `/transfer_auth`
   → ambil cookie sesi → `/me` → akun korban.

Catatan: server penyerang tidak perlu benar-benar dijalankan — bukti
kebocorannya adalah header `Location` yang mengarah ke host penyerang
dengan token transfer di dalamnya.

### Deliverable

`exploit/exploit.py` dieksekusi verifier dan harus mencetak tepat 4 baris:

```
STATUS: 302
LOCATION: https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<token>
TOKEN: <token>
ACCOUNT: victim@khan.demo
```

- `STATUS` = status HTTP respons `POST /login` (302 = redirect bocor terjadi).
- `LOCATION` = header `Location`-nya: host penyerang yang lolos regex
  (bukan bentuk bertitik yang legitimate), memuat `/transfer_auth?key=`.
- `TOKEN` = token transfer, diekstrak dari query `LOCATION`.
- `ACCOUNT` = hasil replay `TOKEN` ke `/transfer_auth` + buka `/me`.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan cacat di `KA_DOMAIN_REGEX`, tulis perbaikan di
`fix/app/app.py`. Kriteria lolos:

- Domain penyerang (`...-uc-a-run.app`) → **400**, tidak ada token yang bocor.
- Host legitimate tetap lolos: `khanacademy.org`, `kastatic.org`, dan
  subdomain bertitik asli (`...-uc.a.run.app`).
- Token transfer tetap satu-kali pakai.

## Perintah

```bash
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix (untuk uji manual)
./lab.sh stop     # hentikan & bersihkan container
```

## Referensi

- HackerOne #3723458 — "1-Click Account Takeover via Open Redirect through
  Regex Bypass in Domain Validation" (Khan Academy; laporan lengkap butuh login).
- Catatan riset: `~/workspace/research_notes/open-redirect-writeups-20261011-1619/report.md`
  (§ sub-teknik 3).
