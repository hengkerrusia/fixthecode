# fix/ — hasil kerja FASE 2 tinggal di sini

Jangan edit file di `frontend/` — itu definisi *pristine* (rentan) yang harus
tetap tidak berubah. Salin pola kerjamu ke direktori ini:

```
fix/
  README.md            # file ini
  frontend/
    Dockerfile         # sama seperti ../frontend/Dockerfile
    nginx.conf         # <-- EDIT FILE INI: versi hasil hardening-mu
```

Scaffold `fix/frontend/nginx.conf` sudah diisi salinan config rentan dengan
penanda `TODO (fase 2)`. Tugasmu:

1. Temukan baris yang meneruskan daftar hop-by-hop kiriman klien ke hop berikut.
2. Perbaiki supaya frontend **mengonsumsi** header `Connection` (tidak meneruskan
   daftar kiriman klien), sesuai RFC 9110 §7.6.1.
3. Uji: `./lab.sh fix-up`, lalu
   - serangan fase 1-mu harus menghasilkan `403`,
   - `GET /` dan `GET /debug/headers` tetap `200`,
   - rantai `X-Forwarded-For` normal tetap utuh (lihat via `/debug/headers`).
4. Verifikasi resmi: `./lab.sh verify` (atau `python3 verify/verify.py`).

Catatan: `./lab.sh start` selalu build ulang dari file pristine, jadi lab selalu
kembali rentan — fix-mu hanya aktif lewat `fix-up` / `verify`.
