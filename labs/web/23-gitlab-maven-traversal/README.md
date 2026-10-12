# Lab 23 — GitLab Maven Registry Traversal → SSH Key Write (HackerOne #733072)

Sumber: disclosed HackerOne report #733072 (bounty $1.000 terkonfirmasi).
Segmen `file_name` pada API Maven Package Registry lolos validasi route
dalam bentuk ter-encode (`%2e%2e%2f`), sehingga request PUT menulis file
sembarang di server — di kasus aslinya, attacker menimpa
`/var/opt/gitlab/.ssh/authorized_keys` lalu masuk via SSH (RCE).

## Skenario

Target adalah simulasi GitLab Maven Package Registry: API upload/download
artefak Maven per proyek.

```
PUT /api/v4/projects/<id>/packages/maven/<path>/<file_name>   (body = isi file)
GET /api/v4/projects/<id>/packages/maven/<path>/<file_name>
```

Server menyimpan artefak di bawah satu direktori penyimpanan
(`/data/packages/`), tanpa autentikasi. Di dunia nyata (GitLab),
endpoint ini bagian dari Package Registry; bug-nya: nama file yang
diterima dalam bentuk *ter-encode* tidak pernah divalidasi setelah
di-decode, sehingga traversal keluar dari direktori penyimpanan dan
menjadi primitif **tulis file sembarang** — jauh lebih berbahaya
daripada sekadar baca file.

Di lab ini, target tulisnya adalah `/data/.ssh/authorized_keys`
(simulasi dari `/var/opt/gitlab/.ssh/authorized_keys` di kasus asli).

Tugasmu: dari luar, tanpa kredensial apa pun, buktikan kamu bisa menulis
file di luar direktori penyimpanan.

## Akar Masalah

Pola umumnya: **membangun path filesystem dari input pengguna tanpa
canonicalization + containment check — pada operasi tulis.**

```python
dest = os.path.join(STORAGE, maven_path, file_name)  # file_name dari user
open(dest, "wb").write(data)
```

Dua hal yang membuat pola ini meledak:

1. **Decoding terjadi setelah "validasi".** Input tiba sebagai
   `%2e%2e%2f` (bukan `../`), sehingga pemeriksaan berbasis pola —
   bahkan route matching framework — melihatnya sebagai nama file biasa.
   Setelah di-decode, ia menjadi traversal sungguhan.
2. **Operasi tulis, bukan baca.** Traversal pada operasi baca "hanya"
   membocorkan file. Pada operasi tulis, attacker menentukan *isi* dan
   *lokasi* file — dari menimpa `authorized_keys` (kasus ini) sampai
   menanam web shell.

Bentuk aman dari pola yang sama:

- Canonicalize dulu path hasil gabungan (resolve `.`, `..`, symlink,
  dan semua bentuk encoding), **lalu** buktikan path hasil resolve
  tetap berada di dalam direktori yang diizinkan (*containment check*,
  mis. `os.path.commonpath`).
- Tolak secara *fail-closed* (mis. HTTP 400) bila pemeriksaan gagal —
  jangan "diperbaiki diam-diam" (mis. strip `../`), karena normalisasi
  parsial adalah sumber bypass berikutnya.
- Validasi_allowlist_ untuk nama file bila formatnya memang terbatas
  (mis. artefak Maven), sebagai lapisan tambahan — bukan pengganti
  containment check.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** PUT artefak normal, mis.
   `/api/v4/projects/1/packages/maven/com/example/1.0/lib.jar` dengan
   body bebas, lalu GET kembali. Catat: status, isi, dan struktur URL
   mana yang menjadi `<path>` vs `<file_name>`.
2. **Probe.** Uji segmen `file_name` dengan nilai yang tidak biasa:
   apa yang terjadi dengan `..` mentah? Dengan bentuk ter-encode
   (`%2e`, `%2f`)? Perhatikan kapan decoding terjadi — sebelum atau
   sesudah path dipecah menjadi segmen?
3. **Diferensial.** Respons `200` untuk `file_name` yang seharusnya
   tidak valid sebagai nama file adalah petunjuk: nilaimu mengalir
   langsung ke operasi filesystem.
4. **Eksploitasi.** Rangkai traversal ter-encode di segmen `file_name`
   sehingga path tujuan keluar dari direktori penyimpanan. Tulis marker
   ke `/data/.ssh/authorized_keys`, lalu verifikasi dengan GET ke path
   yang sama — isi yang kembali adalah bukti tulismu berhasil.

### Deliverable

Skrip `exploit/exploit.py` kamu dieksekusi verifier tanpa argumen dan
wajib mencetak tepat dua baris:

```
STATUS: 200
MARKER: GITLAB-TRAVERSAL-WRITE-OK
```

Baris `MARKER:` hanya boleh dicetak bila string
`GITLAB-TRAVERSAL-WRITE-OK` benar-benar muncul di body respons HTTP
yang diterima skripmu — yakni hasil GET yang membaca kembali file
yang kamu tulis di luar direktori penyimpanan.

## Fase 2 — Review & Fix

1. Baca kode aplikasi di `app/`. Temukan di mana input pengguna mengalir
   ke operasi tulis file, dan mengapa decoding + join tanpa validasi
   itu berbahaya.
2. Tulis perbaikan di `fix/` (mirror path `app/` — hanya
   `fix/server.py` yang dinilai). Perbaikan yang benar bersifat
   *fail-closed*: path tujuan tulis harus terbukti tetap di dalam
   direktori penyimpanan yang diizinkan, atau request ditolak.
3. Verifier me-rebuild lab dengan fix-mu: serangan referensi harus gagal
   (marker tidak muncul), dan fungsi normal (PUT/GET artefak biasa)
   harus tetap utuh.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh stop     # hentikan
./lab.sh verify   # verifikasi 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan dengan fix/ milikmu
```

## Referensi

- HackerOne report #733072 (disclosed) — traversal ter-encode di
  segmen `file_name` API Maven registry → tulis `authorized_keys` → RCE:
  https://hackerone.com/reports/733072
