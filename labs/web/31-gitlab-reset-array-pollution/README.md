# Lab 31 — GitLab password reset array pollution → ATO

Sumber: [HackerOne #2293343](https://hackerone.com/reports/2293343) — researcher
**asterion04**, dilaporkan ke **GitLab** tahun 2023, severity **Critical 10.0**,
bounty **$35.000**.

## Skenario

Mock password-reset API ala GitLab. Form "Forgot your password?" mengirim
`user[email]`; server mencari akun, membuat reset token, dan mengirim link via email.
Satu akun tersedia:

| Akun | Email | Password | user_id |
|---|---|---|---|
| victim | `victim@lab.test` | `victim-pw` | `user_3101` |

Attacker tidak butuh akun — hanya butuh email victim, dan "menguasai" alamat email
`evil@attacker.lab`.

Endpoint:

- `POST /password-reset` `{"user": {"email": ...}}` → `{"ok": true}` (selalu 200,
  tanpa enumerasi — persis perilaku aman terhadap user enumeration)
- `GET /inbox/<email>` → `{"messages": [...]}` — mock mail server; hanya bisa membaca
  inbox untuk domain **`@attacker.lab`** (email milikmu); selain itu 403
- `POST /reset/confirm` `{"token": ..., "new_password": ...}` → `{"ok": true}`
- `POST /login` `{"email","password"}` → `{"token"}`
- `GET /me` (Bearer token) → `{"user_id","email"}`

Catatan: di kasus asli, request-nya form-encoded (`user[email]=...`) yang diubah jadi
JSON via plugin Burp (Content-Type Converter) — Rails menerima `{"user": {"email":
[...]}}`. Lab ini memakai JSON langsung; **mekanisme intinya sama**: array di posisi
yang seharusnya string.

## Akar Masalah

**Type confusion pada input: array diterima di posisi yang seharusnya string.**
Framework nested-param (Rails `user[email]`) bisa menghidrasi satu field menjadi array
bila klien mengirim JSON berbentuk array. Kode yang mengasumsikan string lalu
mengoper nilai itu ke mailer — mailer mengiterasi array dan mengirim reset link ke
**semua** alamat di dalamnya. Satu request, tanpa interaksi victim, attacker memegang
reset link akun victim.

Bentuk umumnya: setiap input yang "bentuknya" bisa berubah (string ↔ array ↔ object)
namun kode hanya menangani satu bentuk — parameter pollution / mass assignment /
deserialisasi longgar. Titik parahnya selalu di *sink* yang mengiterasi: mailer,
query `IN`, dsb.

Bentuk amannya: **validasi tipe yang ketat (fail-closed)** — tolak request bila
`email` bukan string (400), sebelum lookup maupun pengiriman. Validasi "ada isinya"
tidak cukup; yang dicek adalah *bentuknya*.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: `POST /password-reset` dengan `{"user": {"email": "victim@lab.test"}}`
   (string normal) → 200. Cek `GET /inbox/evil@attacker.lab` → kosong: tidak ada email
   nyasar ke alamatmu. Coba `GET /inbox/victim@lab.test` → 403 (bukan milikmu).
   Login sebagai victim dengan kredensial awal → bisa (catat sebagai kontrol).
2. **Probe**: ulangi `/password-reset`, tapi `email`-nya kirim sebagai **array**:
   `{"user": {"email": ["victim@lab.test", "evil@attacker.lab"]}}`. Lalu cek inbox-mu
   lagi.
3. **Diferensial**: string → inbox-mu kosong; array → inbox-mu berisi email. Satu-satunya
   yang berubah adalah *bentuk* parameter — server meng-fanout kiriman ke array.
4. **Eksploitasi**: ambil reset token dari email di inbox-mu (itu link untuk akun
   victim!) → `POST /reset/confirm` dengan password baru → `POST /login` sebagai
   victim → ATO.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat tiga baris:

```text
STATUS: 200
VICTIM: user_3101
TOKEN: <token sesi hasil login sebagai victim>
```

Verifier memvalidasi secara independen: `GET /me` dengan TOKEN harus mengembalikan
`user_id == user_3101`; login dengan password lama victim harus sudah gagal.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan di mana `email` dipakai tanpa validasi tipe. Tulis
perbaikan di `fix/app/app.py`:

- Tolak (400) bila `email` bukan string — sebelum lookup user maupun pengiriman email.
- Fail-closed: tidak ada email yang terkirim pada request yang ditolak.

Fungsi normal harus tetap utuh: reset dengan string email → 200; email tak dikenal →
200 tanpa email terkirim (tanpa enumerasi); login victim dengan password lama tetap
bisa (artinya tidak ada takeover).

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://hackerone.com/reports/2293343 (langkah reproduksi publik)
- Pola umum: OWASP — Mass Assignment / Parameter Pollution; Rails Strong Parameters
