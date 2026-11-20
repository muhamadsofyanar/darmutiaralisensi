# Penerbit Lisensi Darmutiara

Layanan lisensi independen untuk Darmutiara. Administrator menerbitkan, memperpanjang, dan mencabut lisensi lewat terminal privat. Instalasi yang sudah mengintegrasikan protokol Darmutiara memanggil API melalui HTTPS untuk memperoleh bukti aktivasi Ed25519.

## Jalankan di Coolify

1. Tempatkan isi ZIP di root repositori privat layanan lisensi. Buat resource Docker Compose baru di Coolify menggunakan repositori itu.
2. Pilih service `app` dan port internal `8000` di halaman Domains. Pakai subdomain HTTPS seperti `lisensi.darmutiara.com` setelah DNS disiapkan.
3. Deploy. Cek `/health` untuk respons `{"status":"ok"}`. Volume bernama `licenses` menampung database serta kunci privat. Simpan cadangan privat volume tersebut agar kunci dan lisensi bertahan setelah pemulihan.
4. Dari Terminal **container app pada layanan lisensi**, jalankan:

   ```sh
   python lisensi.py issue --domain darmutiara.com --customer "Darul Mutaqin Sejahtera" --days 365
   ```

   Perintah menampilkan kunci lisensi satu kali. Simpan secara privat. Gunakan ID yang ditampilkan untuk administrasi berikutnya.

   ```sh
   python lisensi.py list
   python lisensi.py public-key
   python lisensi.py renew ID_LISENSI --days 365
   python lisensi.py revoke ID_LISENSI
   ```

## Hubungkan aplikasi milik Anda

- Panggil `POST /v1/activate` melalui HTTPS dengan header `Content-Type: application/json` dan dua field, `license_key` serta `domain`. Ambil domain dari konfigurasi kanonik instalasi. Panggilan yang sama digunakan untuk validasi ulang.
- Gunakan kunci publik dari `python lisensi.py public-key`, yang dipasang di sisi klien lewat konfigurasi tepercaya. Respons memuat `token` dan waktu kedaluwarsa. Token berisi `base64url(JSON).base64url(signature)`. Verifikasi tanda tangan atas teks ASCII segmen pertama, lalu cek issuer, domain, dan masa berlaku. Fungsi `verify` di `lisensi.py` adalah referensi Python.
- Jadwalkan validasi ulang sebelum token berakhir. Bukti aktivasi berlaku maksimal 24 jam, dibatasi tanggal kedaluwarsa lisensi. Pencabutan menghentikan penerbitan token baru, dan token yang sudah diterbitkan berakhir sesuai waktu kedaluwarsanya.
- Paket Averion yang ada di Coolify masih menggunakan aktivasi Averion. Integrasi layanan ini memerlukan aplikasi Darmutiara yang mendukung protokol di atas atau jalur integrasi yang diizinkan vendor. Panel visual dan layanan rilis pembaruan berada di luar paket awal ini.

## Uji

Jalankan `python -m unittest -v` setelah memasang dependensi. Pengujian memakai database sementara dan API lokal. Build image, konfigurasi DNS, HTTPS, dan deploy Coolify perlu diuji setelah resource baru dibuat.
