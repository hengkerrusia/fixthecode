# fix/ — hasil kerja FASE 2 tinggal di sini

Jangan edit file di `gateway/` — itu definisi *pristine* (rentan) yang harus
tetap tidak berubah. Hasil kerjamu tinggal di sini:

```
fix/
  README.md            # file ini
  gateway/
    Dockerfile         # sama seperti ../../gateway/Dockerfile
    proxy.py           # <-- EDIT FILE INI: hasil hardening-mu
```

`fix/gateway/proxy.py` adalah salinan kode pristine — tanpa komentar instruksi.
Materi & metodologi fase 2 ada di `../README.md` (bagian Fase 2).

Cara uji:
1. `./lab.sh fix-up` — lab berjalan dengan fix-mu (tanpa verifikasi).
2. `./lab.sh verify` — verifikasi resmi (atau `python3 verify/verify.py`).

Catatan: `./lab.sh start` selalu build ulang dari file pristine, jadi lab selalu
kembali rentan — fix-mu hanya aktif lewat `fix-up` / `verify`.

**Penting:** verifier menganggap fase 2 belum dikerjakan selama isi
`fix/gateway/proxy.py` masih identik byte-per-byte dengan `gateway/proxy.py`
(pristine).
