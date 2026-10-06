# fix/

Fase 2: baca `../gateway/gateway.py`, temukan bagaimana request dengan
`Expect: 100-continue` ditangani ketika backend membalas non-100, lalu
tulis perbaikanmu di `gateway/gateway.py` (file ini).

Scaffold saat ini identik byte-per-byte dengan pristine — verifier
menolaknya (exit 2, "fase 2 belum dikerjakan").

Uji dengan `./lab.sh verify` (fase 2). Lulus bila serangan referensi
gagal total (request dengan `Expect: 100-continue` → 400, koneksi
ditutup) sementara fungsi normal utuh: `GET /` → 200, `POST /echo`
(tanpa Expect) → 200, dan `GET /lain` → 200.
