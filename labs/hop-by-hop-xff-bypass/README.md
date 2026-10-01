# Lab 1: Hop-by-Hop Header Abuse → X-Forwarded-For Stripping → Admin Bypass

**Sumber:** Nathan Davison, ["Abusing HTTP hop-by-hop request headers"](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers)
(didukung pembahasan OWASP WSTG tentang hop-by-hop header injection).

## Skenario

Sebuah aplikasi internal punya endpoint `/admin` yang hanya boleh diakses dari jaringan
internal. Di depannya ada rantai proxy:

```
                    +------------------+
                    |  kamu (penyerang) |
                    |  jaringan luar    |
                    +--------+---------+
                             | http://localhost:8080
                    +--------v---------+
                    | frontend (nginx) |  10.200.0.0/16  (frontnet)
                    | MENERUSKAN       |
                    | header Connection|  <-- VULNERABLE (ini bug-nya)
                    | kiriman klien    |
                    +--------+---------+
                             | 10.201.0.0/16 (backnet)
                    +--------v---------+
                    | mid (proxy py)   |
                    | - hapus header   |
                    |   yg terdaftar   |
                    |   di Connection  |
                    | - XFF = IP peer  |  <-- perilaku ala CloudFoundry gorouter
                    +--------+---------+
                             |
                    +--------v---------+
                    | app (python)     |
                    | /admin: percaya  |
                    | X-Forwarded-For  |  <-- trust boundary yang rapuh
                    +------------------+
```

Rantai ini meniru kasus nyata di write-up: satu hop meneruskan daftar hop-by-hop
kiriman klien, hop berikutnya mengonsumsi daftar itu (menghapus header yang disebut),
lalu menulis ulang `X-Forwarded-For` dengan IP hop sebelumnya (IP internal).
Backend yang membuat keputusan akses berdasarkan XFF pun tertipu.

## Fase 1 — Hacking

**Objektif:** dapatkan `HTTP 200` dari `GET /admin` (baseline normal: `403`).

Panduan metodologi ada di `exploit/README.md`. Intinya, seperti di write-up:

1. Kirim request baseline, catat respons.
2. Pakai `/debug/headers` untuk melihat header apa yang *benar-benar* diterima backend.
3. Uji: daftarkan sebuah header sebagai hop-by-hop via `Connection`, lihat apakah header
   itu hilang di sisi backend.
4. Temukan header yang dipercaya backend untuk keputusan akses, lalu buat rantai
   proxy menulis ulang header itu dengan nilai yang menguntungkanmu.

Keberhasilan fase 1 = exploit-mu reproducible (script), bukan kebetulan.

## Fase 2 — Fixing

**Objektif:** tutup kerentanannya **tanpa merusak fungsi normal**.

1. Review `frontend/nginx.conf` dan `mid/proxy.py`. Di mana tepatnya rantai ini bisa
   dimanipulasi penyerang? (Petunjuk: siapa yang seharusnya "mengonsumsi" header
   `Connection`, dan siapa yang malah "meneruskannya" — baca lagi RFC 9110 §7.6.1.)
2. Tulis perbaikanmu di `fix/frontend/nginx.conf` (scaffold sudah disiapkan —
   **jangan** edit file di `frontend/`, itu definisi rentan yang harus tetap pristine).
3. Kriteria fix yang benar:
   - Serangan fase 1 sekarang menghasilkan `403`.
   - Request normal tetap `403` untuk `/admin` (tetap ditolak untuk pihak luar).
   - `/` dan `/debug/headers` tetap `200`, dan rantai `X-Forwarded-For` normal
     (2 IP: IP klien + IP frontend) tetap utuh — artinya kamu tidak merusak
     perilaku proxy yang legitimate.
4. Bonus (defense in depth, tidak dinilai): apa yang masih rapuh dari keputusan akses
   di `app/app.py`? Bagaimana kamu mengeraskannya?

## Perintah

```bash
./lab.sh start    # bangun & jalankan lab (SELALU kondisi rentan)
./lab.sh verify   # verifikasi otomatis fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan & bersihkan
```

**Catatan reset:** `./lab.sh start` selalu build ulang dari file pristine, jadi lab
selalu kembali rentan. Fix-mu hanya aktif lewat `./lab.sh fix-up` atau `./lab.sh verify`.

## Jejak audit (untuk fase 1)

- `GET /` → `200`, halaman publik.
- `GET /admin` → `403` untuk pihak luar, `200` jika seluruh rantai XFF internal.
- `GET /debug/headers` → `200` JSON berisi header yang diterima backend (alat observasi).

## Referensi

- Nathan Davison — "Abusing HTTP hop-by-hop request headers" (artikel utama lab ini).
- OWASP WSTG — "Test HTTP Strict Transport Security" / bagian Other HTTP Security Header
  Misconfigurations (pembahasan hop-by-hop header injection).
- RFC 9110 §7.6.1 — Connection header & hop-by-hop fields.
