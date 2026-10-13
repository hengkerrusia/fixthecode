# Lab 28 — PayPal IDOR → Cross-Merchant Privilege Escalation (H1 #415081)

**Sumber:** HackerOne report #415081, born2hack (2018) — severity High 7.1,
bounty **$10.500** terverifikasi di halaman report.

## Skenario

Demo Merchant API meniru manajemen akun bisnis ala PayPal:

- `POST /login` `{email, password}` → token sesi (`Authorization: Bearer`).
- `GET /businessmanage/merchants` → direktori merchant publik (id + nama).
- `GET /businessmanage/users?account_id=<ID>` → daftar user sebuah akun bisnis.
  **Terotorisasi benar**: hanya member akun itu yang boleh baca (401/403).
- `POST /businessmanage/users/api/v1/users` `{account_id, email, role}` →
  menambahkan user ke akun bisnis. **Inilah endpoint yang cacat.**

Akun yang tersedia:

| Email | Password | Akun |
|---|---|---|
| `alice@tokoberkah.com` | `alicepw` | `acct_1001` (Toko Berkah, owner) |
| `attacker@evil.com` | `attacker_pw` | `acct_1001` (Toko Berkah, member) |
| `bob@victimcorp.com` | `bobpw` | `acct_1002` (Victim Corp, owner) |

Kamu adalah penyerang: login sebagai `attacker@evil.com` (member Toko Berkah),
lalu jadikan dirimu `admin` di `acct_1002` (Victim Corp) — akun yang bukan
milikmu.

## Akar Masalah

**Pola umum:** IDOR = Insecure Direct Object Reference. Server memakai
identifier dari request (`account_id`) untuk memilih objek, tapi **tidak
memeriksa apakah pemanggil berhak atas objek itu**. Autentikasi ("siapa kamu")
ada, otorisasi ("bolehkah kamu atas objek ini") tidak. Setiap endpoint yang
menerima ID milik orang lain wajib menjawab: *apakah sesi ini memiliki
relasi dengan objek tersebut?*

**Mekanisme spesifik di sini:** endpoint tambah-user memercayai `account_id`
dari body request sepenuhnya. Tidak ada pengecekan kepemilikan/keanggotaan
sebelum menulis. Sekali penyerang tercatat sebagai `admin` di akun korban,
endpoint baca yang *sudah benar* pun akan melayaninya — karena ia kini
"member yang sah". Kerusakan terjadi di tulis, dampaknya permanen di baca.

**Bentuk aman dari pola yang sama:** setiap operasi tulis (dan baca) yang
menerima object ID harus memvalidasi relasi pemanggil → objek *di server*,
sebelum aksi dijalankan. ID dari client tidak pernah dipercaya untuk
otorisasi. Kegagalan → 403, bukan "ya sudah tulis saja".

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** Login sebagai `attacker@evil.com`. Baca direktori merchant,
   baca daftar user `acct_1001` (akunmu sendiri) → 200. Coba baca
   `acct_1002` → 403. Petakan mana yang dijaga, mana yang tidak.
2. **Probe.** `POST /businessmanage/users/api/v1/users` dengan
   `account_id` = `acct_1001` (milikmu) → 201. Sekarang coba dengan
   `account_id` = `acct_1002` (bukan milikmu). Apa yang terjadi?
3. **Diferensial.** Endpoint baca menolak akses silang (403), tapi endpoint
   tulis tidak. Itulah celahnya: otorisasi hanya di satu sisi.
4. **Eksploitasi.** Tambahkan `attacker@evil.com` sebagai `admin` ke
   `acct_1002`, lalu buktikan: baca daftar user `acct_1002` — namamu kini
   tercantum sebagai admin. Eskalasi privilege lintas merchant terbukti.

### Deliverable

`exploit/exploit.py` dieksekusi verifier dan harus mencetak tepat 4 baris:

```
STATUS: 201
TARGET: acct_1002
ADDED: attacker@evil.com
ROLE: admin
```

- `STATUS` = status HTTP dari `POST .../users/api/v1/users`.
- `TARGET` = `account_id` korban (bukan akunmu sendiri).
- `ADDED` / `ROLE` = email dan role yang kamu tanam di akun korban.
- Verifier akan login ulang sebagai penyerang dan membaca daftar user
  `TARGET` untuk memastikan `ADDED` benar-benar tercantum sebagai `ROLE`.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan endpoint yang tidak memeriksa kepemilikan,
tulis perbaikan di `fix/app/app.py`. Kriteria lolos:

- Tambah-user lintas merchant → **403**, tidak ada user yang tertanam.
- Tambah-user di akun sendiri tetap 201.
- Endpoint baca dan `/me` tidak berubah perilakunya.

## Perintah

```bash
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix (untuk uji manual)
./lab.sh stop     # hentikan & bersihkan container
```

## Referensi

- HackerOne #415081 — born2hack (2018), "PayPal IDOR → cross-merchant
  privilege escalation" ($10.500).
- OWASP API Security Top 10 — API1: Broken Object Level Authorization (BOLA).
