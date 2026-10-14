# Lab 30 — Stripe email change IDOR → ATO

Sumber: [HackerOne #1250037](https://hackerone.com/reports/1250037) — researcher **dk82hg**,
dilaporkan ke **Stripe** (flow email-change di indiehackers.com, properti Stripe) tahun 2021,
severity medium → **critical**. Fix upstream: *"confirm authentication on account actions"*.

## Skenario

Mock account-settings API ala indiehackers.com: user bisa login, melihat profil, mengganti
email akun, dan me-reset password lewat email. Dua akun tersedia:

| Akun | Email | Password | user_id |
|---|---|---|---|
| attacker | `attacker@lab.test` | `attacker-pw` | `user_9001` |
| victim | `victim@lab.test` | `victim-pw` | `user_9002` |

Endpoint:

- `POST /login` `{"email","password"}` → `{"token"}`
- `GET /me` (Bearer token) → `{"user_id","email"}`
- `GET /users` → direktori publik `[{"user_id","name"}]` (tanpa email)
- `POST /account/email` (auth) `{"user_id","email"}` → ganti email akun
- `POST /account/password-reset` `{"email"}` → `{"reset_token"}` (mock: token dikembalikan
  langsung sebagai simulasi inbox pemilik email)
- `POST /account/password-reset/confirm` `{"reset_token","new_password"}` → `{"ok": true}`

Catatan: bentuk request persis indiehackers tidak dipublikasikan di report; lab ini
mereproduksi **mekanismenya** (IDOR pada email-change → ATO), bukan salinan verbatim API-nya.

## Akar Masalah

**Identifier dari klien dipercaya untuk aksi mutasi akun.** Endpoint ganti email menerima
`user_id` dari body request dan langsung mengeksekusi perubahan pada user tersebut —
tanpa memastikan `user_id` itu milik sesi yang sedang login. Autentikasi ada (token wajib),
tetapi **otorisasi level objek tidak ada**: server tidak menurunkan identitas target dari
sesi.

Bentuk umumnya: setiap endpoint yang menerima ID objek (user_id, account_id, dsb.) dari
klien untuk aksi sensitif — ganti email, ganti password, ganti data pribadi — wajib
mengikat target ke identitas sesi, bukan ke parameter request.

Bentuk amannya:

1. Target mutasi diturunkan dari sesi (`me`), parameter `user_id` diabaikan/ditolak bila
   tidak cocok.
2. Aksi sensitif akun wajib **konfirmasi autentikasi** (step-up): minta password ulang
   sebelum perubahan dieksekusi — persis fix yang di-ship Stripe.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai attacker → token. `GET /me` → identitas sendiri.
   `GET /users` → direktori user (catat user_id victim). Coba `POST /account/email`
   dengan `user_id` sendiri → 200, email berubah (kembalikan lagi setelahnya).
   Coba `POST /account/password-reset` dengan email sendiri → dapat `reset_token`.
2. **Probe**: ulangi `POST /account/email`, tapi `user_id`-nya **milik victim**
   (`user_9002`), email baru ke alamat yang kamu "kuasai". Perhatikan status respons.
3. **Diferensial**: bandingkan respons ganti email untuk `user_id` sendiri vs milik orang
   lain. Bila keduanya 200 dengan pola identik, server tidak membedakan kepemilikan —
   itulah sinyal IDOR.
4. **Eksploitasi**: rangkai rantai penuh sampai **account takeover**:
   ganti email victim → minta password-reset ke email baru itu (token kembali ke kamu
   karena kamu pemilik alamatnya) → set password baru → login sebagai victim.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat empat baris:

```text
STATUS: 200
VICTIM: user_9002
EMAIL: <email yang kamu set pada akun victim>
TOKEN: <token sesi hasil login sebagai victim>
```

Verifier memvalidasi secara independen: `GET /me` dengan TOKEN harus mengembalikan
`user_id == user_9002` dan email yang sama dengan EMAIL; login dengan kredensial lama
victim harus sudah gagal.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan di mana `user_id` dari body dipercaya tanpa verifikasi
kepemilikan. Tulis perbaikan di `fix/app/app.py`:

- Tolak (403) bila `user_id` pada body tidak sama dengan user dari sesi.
- Minta konfirmasi password pada aksi ganti email; tolak (403) bila salah/tidak ada.
- Fail-closed: tidak ada perubahan email yang terjadi pada request yang ditolak.

Fungsi normal harus tetap utuh: ganti email sendiri (dengan password benar) → 200,
login → 200, password-reset untuk email sendiri tetap jalan.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://hackerone.com/reports/1250037 (ringkasan + timeline publik; komentar teknis tidak
  dipublikasikan)
- Pola umum: OWASP API Security — BOLA (API1:2023 Broken Object Level Authorization)
