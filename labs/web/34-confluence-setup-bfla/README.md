# Lab 34 — Confluence BFLA → rantai setup → admin takeover

Sumber: [advisory Atlassian CVE-2023-22515](https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html)
(4 Okt 2023). Terdampak Confluence Data Center/Server **8.0.0–8.5.1**,
diperbaiki di **8.3.3 / 8.4.3 / 8.5.2+**. CVSS 10.0 (Atlassian). Masuk CISA KEV
5 Okt 2023; advisory mencatat bukti eksploitasi nation-state.

## Skenario

Mock Confluence yang sudah selesai setup (`setupComplete: true`) dengan satu
admin bawaan (`admin` / `admin-pw`). Dua fungsi setup yang semestinya mati
setelah instalasi ternyata masih bisa dijangkau — dan dirantai menjadi
pembuatan akun administrator **tanpa autentikasi sama sekali**:

- `GET /server-info.action` → info server + status setup
- `GET /setup/setupadministrator-start.action` → halaman awal setup admin
- `POST /setup/setupadministrator.action` (form: `username`, `fullName`,
  `email`, `password`, `confirm`) → membuat administrator baru
- `POST /dologin.action` (form: `os_username`, `os_password`) → login
- `GET /me` (Bearer token) → info sesi (harness lab)

Catatan: ini mock ringan (Confluence asli adalah aplikasi Java yang berat).
`dologin` mengembalikan token (aslinya cookie JSESSIONID) dan `/me` adalah
harness lab — rantai serangannya sendiri setia pada PoC publik (termasuk nama
parameter `bootstrapStatusProvider.applicationConfig.setupComplete`).

## Akar Masalah

**BFLA: fungsi setup tanpa otorisasi level fungsi, dirantai dua langkah.**
Dua kegagalan yang masing-masing terlihat sepele:

1. **Endpoint informasi dengan setter tersembunyi.** `GET /server-info.action`
   mengikat parameter request ke properti konfigurasi internal (pola XWork
   parameter binding) — penyerang bisa me-reset `setupComplete` menjadi false
   lewat query string, tanpa autentikasi.
2. **Fungsi setup tidak memverifikasi konteksnya.** `/setup/setupadministrator`
   adalah fungsi setup-wizard yang hanya bermakna *saat instalasi*, tetapi tidak
   memeriksa apakah setup benar-benar belum selesai — begitu flag di langkah 1
   dibalik, fungsi pembuatan admin terbuka untuk siapa pun.

Ini BFLA, bukan BOLA: yang dieksploitasi bukan ID objek milik orang lain,
melainkan *fungsi* (`setupadministrator`) yang seharusnya tidak terjangkau
oleh peran pemanggil — di sini bahkan tanpa peran sama sekali (unauthenticated).

Bentuk amannya:

1. Fungsi setup hanya hidup selama instalasi: setelah `setupComplete`, semua
   `/setup/*` → 403 (fail-closed). Inilah mitigasi interim resmi Atlassian
   (blokir di network layer atau `web.xml` `<security-constraint>`).
2. Endpoint informasi read-only: jangan pernah mengikat parameter request ke
   state konfigurasi.
3. Perbaikan kanonis: upgrade ke versi yang diperbaiki.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: `GET /server-info.action` → 200, `setupComplete: true`.
   `GET /setup/setupadministrator-start.action` → 403 (setup sudah selesai).
   `POST /setup/setupadministrator.action` → 403.
2. **Probe**: amati parameter apa saja yang diterima `/server-info.action`.
   Framework web kadang mengikat parameter request ke properti konfigurasi
   internal — coba pengaruhi `setupComplete` lewat query string, lalu baca
   ulang responsnya.
3. **Diferensial**: sebelum vs sesudah flag berubah — `GET
   /setup/setupadministrator-start.action` yang tadinya 403 kini 200. Fungsi
   setup hidup kembali.
4. **Eksploitasi**: `POST /setup/setupadministrator.action` untuk membuat akun
   administrator → `POST /dologin.action` sebagai admin baru → ATO terbukti.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat dua baris:

```text
STATUS: 200
ADMIN_TOKEN: <token sesi hasil login sebagai admin baru>
```

`ADMIN_TOKEN` harus token sesi *valid milik admin yang kamu buat* — verifier
memakainya untuk `GET /me` dan memastikan `is_admin` true.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan dua titik rantai: binding parameter di
`/server-info.action` dan pengecekan setup di `/setup/*`. Tulis perbaikan di
`fix/app/app.py`:

- Status setup tidak bisa diubah lewat endpoint informasi.
- `/setup/*` selalu 403 setelah setup selesai (fail-closed).
- Fungsi normal tetap utuh: `/server-info.action` → 200 `setupComplete: true`;
  login admin bawaan → 200 + token.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html (advisory Atlassian)
- https://www.cisa.gov/news-events/alerts/2023/10/05/cisa-adds-three-known-exploited-vulnerabilities-catalog (CISA KEV)
- Nuclei template `http/cves/2023/CVE-2023-22515.yaml` (ProjectDiscovery) — rantai PoC publik
- OWASP API Security — API5:2023 Broken Function Level Authorization
