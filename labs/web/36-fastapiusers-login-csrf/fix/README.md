# fix — Lab 36

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- Token `state` OAuth harus terikat ke browser yang memulai alur authorize —
  misalnya dengan menyematkan nilai acak yang tidak bisa ditebak ke dalam token
  sekaligus ke cookie, lalu membandingkannya di callback (fail-closed).
- Callback dengan `state` yang tidak terikat ke sesi browser peminta → 400,
  dalam kondisi apa pun. Perbandingan harus constant-time.

Fungsi normal yang harus tetap jalan (dicek verifier):

- `POST /register` + `POST /login` → 200 + cookie sesi; `GET /me` benar.
- Alur SSO normal lengkap (authorize → provider → callback) untuk user baru →
  200 + cookie sesi; `GET /me` mengembalikan user tersebut.
- Alur SSO normal untuk user yang sudah login → identitas SSO ter-link.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
