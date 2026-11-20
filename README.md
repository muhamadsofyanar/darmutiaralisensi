# Darmutiara · uji aktivasi mandiri

Aplikasi uji untuk membuktikan bahwa kunci dari penerbit Darmutiara bisa dipakai pada instalasi milik Darmutiara. Aplikasi memverifikasi tanda tangan Ed25519, domain instalasi, dan masa berlaku. Pengurus mengakses halaman dengan kredensial admin melalui HTTPS.

## Pasang sebagai resource uji di Coolify

1. Jalankan paket penerbit `darmutiara-lisensi-v1.zip` sebagai resource tersendiri dengan domain HTTPS, misalnya `lisensi.darmutiara.com`.
2. Buat repositori untuk isi paket klien ini dan hubungkan sebagai resource Docker Compose baru. Arahkan domain uji HTTPS ke service `app`, port internal `8000`. Gunakan domain uji yang berbeda dari instalasi aktif yang sedang dipakai.
3. Isi variabel resource lalu deploy.

| Variabel | Isi |
|---|---|
| `APP_DOMAIN` | Domain uji klien, misalnya `uji.darmutiara.com`, tanpa protokol |
| `ISSUER_URL` | Origin HTTPS penerbit, misalnya `https://lisensi.darmutiara.com` |
| `ISSUER_PUBLIC_KEY` | Nilai kunci publik dari `python lisensi.py public-key` di container penerbit |
| `ADMIN_USER` | Nama admin uji, nilai bawaan `admin` |
| `ADMIN_PASSWORD` | Password baru yang acak, minimal 16 karakter |

4. Di terminal **penerbit**, terbitkan lisensi untuk domain yang sama persis dengan `APP_DOMAIN`. Ganti contoh domain jika Anda memakai alamat lain.

   ```sh
   python lisensi.py issue --domain uji.darmutiara.com --customer "Darul Mutaqin Sejahtera" --days 30
   ```

5. Buka domain uji melalui HTTPS, login sebagai admin, lalu masukkan kunci. Status menjadi **Aktif** jika lisensi berhasil diverifikasi.

Penyimpanan `activation_data` memuat kunci aktivasi dan bukti terbaru. Simpan volume dan cadangannya secara privat. Pada kunjungan admin, klien meminta bukti baru paling sering sekali per jam. Jika penerbit tidak dapat dijangkau, bukti lokal yang masih valid dapat digunakan hingga kedaluwarsa. Bila penerbit menolak lisensi, status aktif dihapus saat pemeriksaan ulang berikutnya.

## Status

Uji lokal mencakup issuer yang sebenarnya dari paket `darmutiara-lisensi-v1.zip`, HTTP aktivasi, domain berbeda, pencabutan, autentikasi admin, dan CSRF. Build image serta konfigurasi Coolify masih perlu diuji. Paket ini berisi halaman aktivasi. Modul anggota, Kajian, Diskusi, dan rilis pembaruan mandiri berada di luar uji ini.
