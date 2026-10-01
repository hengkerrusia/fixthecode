# fix/ — hasil kerja FASE 2 tinggal di sini

Jangan edit file di `frontend/` — itu definisi *pristine* (rentan) yang harus
tetap tidak berubah. Hasil kerjamu tinggal di sini:

```
fix/
  README.md            # file ini
  frontend/
    Dockerfile         # sama seperti ../frontend/Dockerfile
    nginx.conf         # <-- EDIT FILE INI: hasil hardening-mu
```

Materi & metodologi fase 2 ada di `../README.md` (bagian Fase 2).

Cara uji:
1. `./lab.sh fix-up` — lab berjalan dengan fix-mu (tanpa verifikasi).
2. `./lab.sh verify` — verifikasi resmi (atau `python3 verify/verify.py`).

Catatan: `./lab.sh start` selalu build ulang dari file pristine, jadi lab selalu
kembali rentan — fix-mu hanya aktif lewat `fix-up` / `verify`.
