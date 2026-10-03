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
labs/<kategori>/<nn>-<nama-lab>/
  README.md               # skenario, arsitektur, objektif 2 fase, referensi
  docker-compose.yml      # definisi PRISTINE (rentan) — jangan diedit untuk fixing
  docker-compose.fix.yml  # overlay compose: pakai config dari fix/
  lab.sh                  # start | stop | verify | fix-up
  frontend/  mid/  app/   # service lab (Dockerfile + config, tanpa volume mount)
  fix/                    # <-- hasil kerja fase 2 tinggal di sini
  verify/verify.py        # verifier otomatis 2 fase (Python stdlib only)
  exploit/                # panduan fase 1 + exploit.py milikmu (dieksekusi & dinilai verifier)
  solutions/              # solusi referensi — buka hanya kalau mentok
```

Kategori top-level dibuat lebar dan stabil (`web`, `api`, `network`, `crypto`, `mobile`,
`cloud`); satu lab masuk satu kategori utama (kategori sekunder dicatat di README lab).

## Daftar lab

| # | Lab | Kelas kerentanan | Sumber |
|---|-----|------------------|--------|
| 1 | [`web/01-hop-by-hop-xff-bypass`](labs/web/01-hop-by-hop-xff-bypass/) | Hop-by-hop header abuse → X-Forwarded-For stripping → admin bypass | Nathan Davison, "Abusing HTTP hop-by-hop request headers" |
| 2 | [`web/02-web-cache-deception`](labs/web/02-web-cache-deception/) | Web cache deception → halaman privat ter-cache publik | Omer Gil, "Web Cache Deception Attack" (PayPal, $3.000) |
| 3 | [`web/03-unkeyed-input-xfh`](labs/web/03-unkeyed-input-xfh/) | Unkeyed input → X-Forwarded-Host cache poisoning | HackerOne #977851 (Shopify, $1.300 → $6.300) |
| 4 | [`web/04-method-override`](labs/web/04-method-override/) | Method override → X-HTTP-Method-Override cache poisoning DoS | HackerOne #1160407 (GitLab, $2.500) |
| 5 | [`web/05-cpdos-error-caching`](labs/web/05-cpdos-error-caching/) | CPDoS → error caching (403) → denial of service | "Your Cache Has Fallen" (CCS 2019); 403-caching $2.500 |
| 6 | [`web/06-h2c-smuggling`](labs/web/06-h2c-smuggling/) | H2C smuggling → terowongan upgrade HTTP/2 cleartext → bypass proteksi /admin | Bishop Fox, h2csmuggler |

## Mulai cepat

```bash
cd labs/web/01-hop-by-hop-xff-bypass
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh stop     # hentikan & bersihkan container
```

Baca `README.md` di tiap lab sebelum mulai — di sana ada skenario, arsitektur,
dan kriteria suksesnya.
