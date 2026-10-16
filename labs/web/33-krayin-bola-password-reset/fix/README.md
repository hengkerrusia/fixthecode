# fix — Lab 33

`fix/app/app.py` adalah salinan kode rentan. Tulis perbaikanmu langsung di file ini
(mirror path `app/app.py`).

Syarat fix:

- `PUT /admin/settings/users/edit/<id>` hanya boleh mengubah password bila pemanggil
  adalah pemilik akun (`id` miliknya sendiri) atau admin; selain itu → 403
  (fail-closed).
- Password user lain tidak boleh bisa diubah dalam kondisi apa pun.

Fungsi normal yang harus tetap jalan (dicek verifier):

- User mengubah password miliknya sendiri → 200.
- Admin mengubah password user mana pun → 200.
- Tanpa token → 401; id tak dikenal → 404.

Jalankan `./lab.sh fix-up` lalu `./lab.sh verify` untuk menguji.
