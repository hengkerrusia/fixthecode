# fix/

Salin `../app/app.py` ke `fix/app/app.py` (sudah disediakan sebagai scaffold),
lalu tambahkan pemeriksaan kepemilikan di endpoint assignkeys.

Syarat fix yang benar:

- `GET /partnercdkeys/assignkeys?game_id=<milik orang lain>` → **403**,
  dan tidak ada key yang bocor.
- `game_id` milik sendiri → tetap 200 + key seperti semula.
- Gunakan relasi yang sudah ada di server (partner ↔ game) — jangan percaya
  klaim apa pun dari client selain identitas sesi.

Jangan ubah perilaku endpoint lain.
