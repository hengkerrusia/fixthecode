# Lab 13 — CSPT via Stylesheet Loader → Open Redirect → CSS Injection

**Sumber:** Medi, "Practical Client Side Path Traversal Attacks" (2022, [tulisan asli via arsip](https://web.archive.org/web/20231129182802/https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html)) — disclosed sebagai HackerOne #1245165 (Acronis); dinominasikan PortSwigger Top 10 Web Hacking Techniques 2022.

## Skenario

- `GET /?theme=X` (butuh login sebagai `victim`/`victim123`) me-render:
  `<link rel="stylesheet" href="/static/theme.X.css">`
  dengan `X` direfleksikan **tanpa sanitasi**. Halaman juga memuat
  `<input type="hidden" name="csrf_token" value="<SECRET>">`.
- `GET /api/authorize?state=X` → 302 ke `X` tanpa validasi (open redirect;
  gadget — tidak eksploitable sendirian).
- Tema valid: `light`, `dark` (`/static/theme.light.css`, `theme.dark.css`).

Penyerang hanya mengendalikan `theme` di link yang diklik korban.

## Akar Masalah

**Penyebab umum:** CSPT tidak hanya hidup di `fetch`/`XHR` — *resource loader*
pun bisa menjadi sink. Pola umumnya sama seperti Lab 11/12: input tak tepercaya
(query string, fragment, path param) digabungkan ke URL resource tanpa
validasi/normalisasi, lalu browser me-resolve dot-segment sehingga resource
dimuat dari lokasi yang dikendalikan penyerang.

**Mengapa CSS injection berbahaya tanpa JavaScript:** stylesheet yang diterapkan
browser bisa memakai *attribute selector* (`input[value^="..."]`) untuk
menguji isi DOM dan membocorkannya lewat `url()` — browser me-request URL itu
hanya bila selector cocok. Satu karakter bocor per putaran; penyerang yang
adaptif menyusun ulang CSS per putaran hingga rahasia utuh. Tidak ada script
yang dieksekusi, tidak ada XSS — hanya CSS.

**Bentuk aman:** jangan bangun URL resource dari input tak tepercaya;
validasi allowlist di trust boundary server (dan di klien bila URL dibentuk
di JS); open redirect perbaiki dengan allowlist tujuan; dan untuk
`state`-style parameter, jangan refleksikan URL arbitrer ke `Location`.

## Fase 1 — Hacking

### Metodologi

1. **Baseline:** login, buka `/?theme=light`, amati `<link>` yang di-render
   dan respons `/api/authorize?state=http://example.com/x`.
2. **Probe:** selipkan `../` di `theme` — ke mana URL stylesheet dihitung
   oleh browser? Karakter apa yang mengakhiri path di URL (sehingga sisa
   `.css` bisa "ditelan")?
3. **Diferensial:** stylesheet normal (200, CSS lokal) vs stylesheet hasil
   traversal (302 ke luar).
4. **Eksploitasi:** rangkai traversal → open redirect → CSS milikmu.
   Jalankan attacker server sendiri (stdlib): sajikan `/core.css` adaptif
   (36 rule per putaran, satu per karakter kandidat) dan catat hit `/log`.
   Simulasikan browser korban: muat CSS, cocokkan selector ke DOM, request
   URL yang cocok. Tokennya 8 karakter `[a-z0-9]` (penyederhanaan lab yang
   disengaja; teknik aslinya identik untuk panjang berapa pun).

### Deliverable

`exploit/exploit.py` mencetak ke stdout, baris persis seperti ini:

```text
VICTIM_THEME: <nilai theme beracun>
STATUS: <kode status HTTP, 3 digit>
LOADED_CSS: <URL CSS penyerang yang dimuat korban>
EXFILTRATED: <token yang dicuri>
```

`EXFILTRATED` harus sama dengan token rahasia korban.

## Fase 2 — Review & Fix

Baca `app/app.py`. Temukan di mana `theme` direfleksikan ke `href` tanpa
validasi. Tulis perbaikanmu di `fix/app/app.py`:

- Handler `/` menolak `theme` di luar format sah (`^[a-z]{3,8}$`) dengan
  `400`. Ini gerbang yang diverifikasi otomatis — tanpa ini, link beracun
  tetap me-render halaman dan rantai serangan tetap hidup.

Lulus bila: serangan referensi gagal total (`GET /?theme=<racun>` → 400,
tidak ada CSS penyerang yang dimuat) sementara fungsi normal utuh
(`/?theme=light` → 200, `theme.light.css` → 200).

## Perintah

```bash
./lab.sh start    # jalankan lab rentan (selalu rebuild dari pristine)
./lab.sh verify   # verifier 2 fase (butuh docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

Lab di `http://localhost:8080`. Restart selalu kembali ke kondisi rentan.

## Referensi

- Medi — "Practical Client Side Path Traversal Attacks": https://web.archive.org/web/20231129182802/https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html
- Doyensec — "Exploiting Client-Side Path Traversal to Perform Cross-Site Request Forgery": https://blog.doyensec.com/2024/07/02/cspt2csrf.html (fondasi primitif CSPT; dipakai di Lab 11)
