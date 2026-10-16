# Lab 33 — Krayin CRM BOLA → password reset → ATO

Sumber: [CVE-2026-38529](https://github.com/trexnegro/security-advisories/blob/HEAD/CVE-2026-38529/README.md) —
researcher **trexnegro**, diuji pada Krayin CRM (laravel-crm) by Webkul versi **2.2.x**
(commit `ba25b7e7`). File terdampak:
`packages/Webkul/Admin/src/Http/Controllers/Settings/UserController.php`.
CVSS 8.8 High, CWE-269 + CWE-639.

## Skenario

Mock CRM ala Krayin. Endpoint edit user `PUT /admin/settings/users/edit/{id}`
semestinya hanya boleh dipakai pemilik akun atau admin — tapi gate-nya bocor:
user non-admin mana pun bisa me-reset password user non-admin **lain**,
lalu login sebagai korban (full account takeover). Tiga akun tersedia:

| Akun | Email | Password | id | admin |
|---|---|---|---|---|
| attacker | `attacker@lab.test` | `attacker-pw` | 100 | tidak |
| victim | `victim@lab.test` | `victim-pw` | 1 | tidak |
| admin | `admin@lab.test` | `admin-pw` | 2 | ya |

Endpoint:

- `POST /login` `{"email","password"}` → `{"token"}`
- `GET /me` (Bearer token) → `{"user_id","email","is_admin"}`
- `PUT /admin/settings/users/edit/{id}` (auth, form-urlencoded `password=...`)
  → `{"ok": true}` bila diizinkan

Catatan: di kasus asli, attacker butuh permission `users.edit`. Lab ini
menyederhanakan: semua user terautentikasi bisa memanggil endpoint — tantangannya
tetap pada otorisasi level objek, bukan pada permission-nya. Lab juga hanya
memodelkan field `password` (kasus asli menyebut `activated` juga bisa diubah).

## Akar Masalah

**BOLA: gate otorisasi memeriksa peran, bukan kepemilikan.** Logika di kasus asli
setara dengan:

```text
canEditAuthFields = (caller is not admin) && (target is not admin)
```

Autentikasi ada, dan ada *sedikit* otorisasi (non-admin tidak bisa menyentuh akun
admin) — tetapi tidak ada yang memeriksa *apakah `id` di path milik pemanggil*.
Akibatnya, ID numerik berurutan (`1`, `2`, …) menjadi kunci menuju akun siapa pun
yang non-admin: timpa `password`, lalu login sebagai korban.

Pola ini berima dengan Lab 32 (Indico): autentikasi ≠ otorisasi. Bedanya, di sini
primitifnya *tulis* (mengubah kredensial milik orang lain), bukan *baca* (PII).

Bentuk amannya:

1. Otorisasi per objek: field sensitif (`password`, `activated`, …) hanya boleh
   diubah pemilik akun atau admin — tolak `caller_id != target_id` untuk
   non-admin (fail-closed, 403).
2. Pisahkan field sensitif dari edit profil umum; pertimbangkan verifikasi ulang
   (password lama / re-auth) untuk perubahan kredensial.
3. ID berurutan + tanpa rate limit mempermudah enumerasi target — jangan jadikan
   "ID sulit ditebak" sebagai satu-satunya pertahanan.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai attacker → token. `GET /me` → id 100, non-admin.
   `PUT /admin/settings/users/edit/100` dengan `password=baru` (form-urlencoded)
   → 200 (self-edit wajar). `PUT .../edit/999` → 404. Tanpa token → 401.
   `PUT .../edit/2` (admin) → 403.
2. **Probe**: `PUT /admin/settings/users/edit/1` (milik victim) dengan password
   barumu sebagai attacker. Perhatikan: apakah server menolak, atau 200?
3. **Diferensial**: id milikmu (100) vs id orang lain (1) → respons identik (200,
   password berubah). Server tidak membedakan kepemilikan — sinyal BOLA.
4. **Eksploitasi**: reset password victim → `POST /login` sebagai
   `victim@lab.test` dengan password barumu → token sesi korban = ATO terbukti.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat dua baris:

```text
STATUS: 200
VICTIM_TOKEN: <token sesi hasil login sebagai korban>
```

`VICTIM_TOKEN` harus token sesi *valid milik korban* — verifier memakainya untuk
`GET /me` dan memastikan ia benar-benar sesi `victim@lab.test`, bukan token
attacker.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan gate yang memeriksa peran tetapi tidak memeriksa
kepemilikan. Tulis perbaikan di `fix/app/app.py`:

- `PUT /admin/settings/users/edit/{id}` mengubah password hanya bila pemanggil
  adalah pemilik akun atau admin; selain itu → 403 (fail-closed).
- Fungsi normal tetap utuh: self-edit → 200; admin edit user mana pun → 200;
  tanpa token → 401; id tak dikenal → 404.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://github.com/trexnegro/security-advisories/blob/HEAD/CVE-2026-38529/README.md (analisis + PoC)
- https://github.com/trexnegro/security-advisories/blob/HEAD/CVE-2026-38529/poc.md (langkah reproduksi)
- NVD: CVE-2026-38529 · CWE-269 + CWE-639
- OWASP API Security — API1:2023 Broken Object Level Authorization
