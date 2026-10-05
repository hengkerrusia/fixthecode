# fix/

Fase 2: baca `../gateway/gateway.py`, temukan bagaimana header yang
datang lewat HTTP/2 diteruskan menjadi request HTTP/1.1 ke backend,
lalu tulis perbaikanmu di `gateway/gateway.py` (file ini).

Scaffold saat ini identik byte-per-byte dengan pristine — verifier
menolaknya (exit 2, "fase 2 belum dikerjakan").

Uji dengan `./lab.sh verify` (fase 2). Lulus bila serangan referensi
gagal total (request ambigu → 400, tidak diteruskan ke backend, antrean
bersih) sementara fungsi normal utuh: `GET /` → 200 dan `POST /` via
HTTP/2 (body lewat DATA frame, tanpa `content-length`) → 200.
