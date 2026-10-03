# fix/

Fase 2: baca `../proxy/proxy.py`, temukan bagaimana ia membingkai
request yang membawa `Content-Length` dan `Transfer-Encoding`
sekaligus, lalu tulis perbaikanmu di `proxy/proxy.py` (file ini).

Scaffold saat ini identik byte-per-byte dengan pristine — verifier
menolaknya (exit 2, "fase 2 belum dikerjakan").

Uji dengan `./lab.sh verify` (fase 2). Lulus bila serangan referensi
gagal total (400, tidak ada yang diteruskan ke backend, cache bersih)
sementara fungsi normal utuh: `GET /`, `GET /signin`, `POST /`
(Content-Length saja maupun chunked saja) tetap 200.
