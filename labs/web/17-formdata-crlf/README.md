# Lab 17 — CRLF Injection via Multipart `filename` (form-data CVE-2026-12143)

Sumber: [GHSA-hmw2-7cc7-3qxx — "form-data: CRLF injection in form-data
via unescaped multipart field names and filenames"](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx)
(CVE-2026-12143). Library npm `form-data` (200 ribu+ dependents)
sampai v4.0.5 menggabungkan field name dan `filename` langsung ke
header `Content-Disposition` tanpa escaping CR/LF/`"`. Diperbaiki di
4.0.6 / 3.0.5 / 2.5.6 dengan percent-encoding ala WHATWG.

## Skenario

Sebuah "upload proxy" menerima file dari klien, lalu **merakit ulang**
request multipart untuk diteruskan ke backend penyimpanan — pola umum
di API proxy, backend-to-backend, dan pipeline CI/CD. Nama file yang
diberikan klien disisipkan langsung ke parameter `filename` tanpa
sanitasi. Meniru perilaku `form-data` yang rentan.

Celahnya: `\r\n` di dalam filename mengakhiri baris header
`Content-Disposition` — penyerang menyuntik header part arbitrer (atau
bahkan part baru) ke request yang diteruskan ke backend.

### Topologi

```text
[learner --multipart--> gateway:8080 --multipart--> backend:8000]
   (field "filename" + field "file")      (menerima & mem-parse part)
```

- `gateway/` — upload proxy: membaca field `filename` (teks) dan field
  `file` (isi file) dari multipart klien, merakit ulang multipart baru
  ke backend dengan `filename="<nilai>"` tanpa sanitasi.
- `backend/` — storage: mem-parse multipart yang diterima dan
  mengembalikan daftar part beserta header-nya (cermin untuk observasi).

## Akar Masalah

**Penyebab umum.** Framework HTTP melindungi *jalur respons*-nya dari
CRLF (Lab 15), tapi **library di bawah framework** yang merakit teks
protokol sendiri tidak ikut dilindungi. Polanya selalu sama: *string
interpolation* nilai tak tepercaya ke dalam sintaks protokol
(`filename="<nilai>"`) tanpa netralisasi karakter kontrol. Varian yang
sama hidup di: nama field multipart, `Content-Disposition` saat
download, header yang dirakit manual untuk HTTP client, dan baris log.

**Bentuk aman dari pola yang sama.** Percent-encode karakter kontrol
(`\r` → `%0D`, `\n` → `%0A`, `"` → `%22`) mengikuti algoritma
WHATWG `multipart/form-data` — persis seperti perbaikan upstream
`form-data` 4.0.6. Alternatif: tolak fail-closed bila input mengandung
CR/LF.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** Upload normal: field `filename` = `doc.txt`, field
   `file` = isi bebas. Respons backend: 1 part, header
   `content-disposition` bersih berisi `filename="doc.txt"`.
2. **Probe.** Isi field `filename` dengan teks mengandung CRLF
   literal, mis. `doc.txt\r\nX-Marker: coba\r\n`. (Ingat: ini *nilai
   field*, bukan nama file di disk — batasnya adalah boundary
   multipart, bukan struktur baris, jadi CRLF di dalamnya legal
   sebagai data.) Amati daftar part header di respons backend.
3. **Diferensial.** Bandingkan: dari satu nilai `filename`, berapa
   header part yang dilihat backend? Header apa yang tidak kamu
   kirim sebagai header?
4. **Eksploitasi.** Suntik header part `X-Marker: <marker>` yang
   bersih (tanpa sisa quote menempel) lewat filename, dan buktikan ia
   ter-parse sebagai header part oleh backend.

### Deliverable

Exploit mencetak tepat dua baris:

```text
STATUS: 200
INJECTED: <marker alfanumerik pilihanmu>
```

- `INJECTED` = marker yang teramati sebagai nilai header part
  `x-marker` di respons backend.
- Verifier mengirim ulang serangan dengan marker-mu dan memastikan
  header part `x-marker: <marker>` muncul di respons backend.

## Fase 2 — Review & Fix

Baca `gateway/gateway.py`. Temukan di mana nilai tak tepercaya
diinterpolasi ke sintaks multipart tanpa netralisasi — dan mengapa
framework HTTP tidak melindungimu di titik itu.

Tulis perbaikan di `fix/gateway/gateway.py`: percent-encode `\r`,
`\n`, dan `"` pada filename sebelum diinterpolasi (mengikuti
perbaikan upstream). Verifier memastikan: serangan referensi tidak
lagi menghasilkan header suntikan, dan upload normal tetap utuh.

## Perintah

```bash
./lab.sh start    # jalankan lab rentan di http://localhost:8080
./lab.sh verify   # verifikasi dua fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

## Referensi

- GHSA-hmw2-7cc7-3qxx (CVE-2026-12143):
  https://github.com/advisories/GHSA-hmw2-7cc7-3qxx
- WHATWG multipart/form-data encoding:
  https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart-form-data
