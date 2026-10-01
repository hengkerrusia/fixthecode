# fixthecode

Lab keamanan web berbasis Docker. **Bukan CTF, bukan kejar flag.**

Setiap lab diselesaikan dalam **2 fase**:

1. **Fase 1 — Hacking.** Eksploitasi kerentanannya sampai berhasil. Pahami *bagaimana* serangan bekerja.
2. **Fase 2 — Fixing.** Review code/config, tulis perbaikan. Pahami *mengapa* itu rentan dan bagaimana menutupnya dengan benar.

Lab dinyatakan **sukses** hanya jika kedua fase lolos verifikasi otomatis (`verify/`).

## Aturan main

- **Restart = kembali rentan.** Image dibangun dari file *pristine* (definisi rentan) di tiap lab.
  Fix-mu tinggal di direktori `fix/` dan hanya dipakai saat verifikasi — tidak pernah menimpa
  definisi rentan. `docker compose down` + `up --build` selalu menghasilkan lab yang rentan lagi,
  walau sesi sebelumnya kamu sudah fixing.
- **Image seringan mungkin.** Prinsip: base image sekecil mungkin (`nginx:alpine`,
  `python:alpine`), tanpa dependency yang tidak perlu, tanpa build tool di image final.
- **Satu lab = satu kerentanan nyata**, dikurasi dari write-up / riset / CVE yang tepercaya
  (bukan artikel asal-asalan).

## Anatomi sebuah lab

```
labs/<nama-lab>/
  README.md               # skenario, arsitektur, objektif 2 fase, referensi
  docker-compose.yml      # definisi PRISTINE (rentan) — jangan diedit untuk fixing
  docker-compose.fix.yml  # overlay compose: pakai config dari fix/
  lab.sh                  # start | stop | verify | fix-up
  frontend/  mid/  app/   # service lab (Dockerfile + config, tanpa volume mount)
  fix/                    # <-- hasil kerja fase 2 tinggal di sini
  verify/verify.py        # verifier otomatis 2 fase (Python stdlib only)
  exploit/README.md       # panduan fase 1 (tanpa solusi)
  solutions/              # solusi referensi — buka hanya kalau mentok
```

## Daftar lab

| # | Lab | Kelas kerentanan | Sumber |
|---|-----|------------------|--------|
| 1 | `hop-by-hop-xff-bypass` | Hop-by-hop header abuse → X-Forwarded-For stripping → admin bypass | Nathan Davison, "Abusing HTTP hop-by-hop request headers" |

## Mulai cepat

```bash
cd labs/hop-by-hop-xff-bypass
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh stop     # hentikan & bersihkan container
```

Baca `README.md` di tiap lab sebelum mulai — di sana ada skenario, arsitektur,
dan kriteria suksesnya.
