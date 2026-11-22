# Penerbit Lisensi Darmutiara

Layanan lisensi independen untuk Darmutiara. Administrator dapat menerbitkan, memperpanjang, dan mencabut lisensi melalui dashboard atau terminal privat. Instalasi yang sudah mengintegrasikan protokol Darmutiara memanggil API melalui HTTPS untuk memperoleh bukti aktivasi Ed25519.

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
- Paket Averion yang ada di Coolify masih menggunakan aktivasi Averion. Integrasi layanan ini memerlukan aplikasi Darmutiara yang mendukung protokol di atas atau jalur integrasi yang diizinkan vendor. Layanan ini menangani penerbitan lisensi Darmutiara.

## Uji

Jalankan `python -m unittest -v` setelah memasang dependensi. Pengujian memakai database sementara dan API lokal. Build image, konfigurasi DNS, HTTPS, dan deploy Coolify perlu diuji setelah resource baru dibuat.

## Dashboard admin

1. Unggah file dari ZIP update ke repositori penerbit, dengan struktur folder yang sama. Gunakan resource penerbit **yang sudah ada** di Coolify. Biarkan volume `licenses` tetap terpasang pada `/data`. Database dan kunci penandatangan disimpan di volume itu.
2. Di **Environment Variables** resource penerbit, isi `ISSUER_ADMIN_PASSWORD` dengan password acak minimal 16 karakter. Nama pengguna default `admin`. Untuk menggantinya, isi `ISSUER_ADMIN_USER`. Aktifkan **Available at Runtime**. Simpan dan deploy. Jangan commit password.
3. Buka `https://lisensi.darmutiara.com/admin/`. Login pada dialog browser. Gunakan HTTPS dan simpan kredensial admin secara privat.
4. Klik **Buat lisensi** untuk menerbitkan kunci, atau pilih domain di daftar untuk mengganti pelanggan, memperpanjang masa berlaku, memindahkan domain, atau mencabut lisensi. Tanggal dan jam di dashboard memakai WIB. Form masa berlaku pada detail menetapkan tanggal akhir yang baru.
5. Salin kunci DRM pada halaman setelah lisensi diterbitkan. Database hanya menyimpan hash kunci. Untuk konfigurasi VPS, buka **Kunci publik** dan salin kunci Ed25519 ke aplikasi klien.

Sebelum deploy, cadangkan volume `licenses` secara privat. Hindari membuat resource baru tanpa volume penerbit lama karena resource baru dapat membuat kunci penandatangan yang berbeda. Setelah deploy, cek `/health` dan pastikan kunci publik di dashboard sama dengan nilai yang digunakan klien.

Perpindahan domain dan pencabutan berlaku saat klien kembali meminta bukti. Bukti yang sudah diterbitkan bisa tetap berlaku secara offline sampai kedaluwarsa. Jadwal kedaluwarsa lisensi baru dipakai saat permintaan bukti berikutnya.


### Fitur dasbor dan pencatatan

- Kartu status menghitung seluruh lisensi dan membuka daftar sesuai status yang dipilih. Kategori **Segera habis** mencakup lisensi yang masih berlaku dan berakhir dalam 30 hari. Kategori **Aktif** pada dasbor mencakup lisensi yang berakhir lebih dari 30 hari lagi.
- Daftar mendukung pencarian domain dan pelanggan, pengurutan, serta ekspor CSV sesuai filter. Ekspor tidak memuat kunci DRM, token, atau kunci privat.
- Detail lisensi menampilkan ID, masa berlaku, waktu verifikasi berhasil terakhir, jumlah verifikasi berhasil, dan hingga 50 perubahan terbaru. Aktivasi awal dan validasi ulang memakai endpoint yang sama, sehingga hitungan mencakup keduanya. Riwayat dan verifikasi mulai tercatat setelah versi ini dijalankan.
- Tombol **Perpanjang** menambahkan hari ke tanggal berakhir lisensi. Untuk lisensi kedaluwarsa, perhitungan dimulai dari waktu perpanjangan. Untuk lisensi yang dicabut, terbitkan lisensi baru jika akses perlu diberikan kembali.

### Pembaruan dari GitHub

Ekstrak ZIP pembaruan. Unggah isi folder ke root repositori `darmutiaralisensi` pada branch yang dibaca Coolify. Pastikan `compose.yaml` dan `Dockerfile` tetap berada di root. Gunakan resource penerbit yang sama untuk redeploy. Saat container mulai, inisialisasi menambahkan tabel dan pemicu pencatatan pada SQLite yang sudah ada sambil mempertahankan data lisensi dan kunci penandatangan yang ada pada volume.

Untuk memeriksa hasil, buka `/health`, login ke dashboard, cocokkan kunci publik, lalu klik **Cek Ulang Lisensi** pada satu instalasi Kajian yang aktif. Pastikan kolom verifikasi berhasil diperbarui pada domain tersebut.

### Antarmuka administrasi dan profil instalasi

- Alamat dasar penerbit mengarahkan pengguna ke `/admin/`. Akses panel dan ekspor tetap menggunakan kredensial admin yang sama.
- Menu **Pelanggan** mengelompokkan nama sesuai data lisensi yang tercatat. Menu **Instalasi** mengelompokkan domain. Buka satu entri untuk melihat lisensi terkait, termasuk riwayat lisensi yang sudah dicabut pada domain yang sama. Nama yang ditulis berbeda tampil sebagai entri tersendiri.
- Dari detail lisensi, gunakan **Edit profil instalasi** untuk memilih Produksi atau Uji dan menambahkan catatan internal. Profil melekat pada ID lisensi yang dipilih. Catatan internal hanya tampil di panel admin. CSV memuat label lingkungan.
- Form perpanjangan, edit, dan pencabutan tersedia pada bagian terpisah. Cek tanggal, domain, dan ID lisensi sebelum mengubah data.
- Jalankan pembaruan dependensi, cadangan, dan simulasi pemulihan secara berkala. Menjaga volume `licenses` pada `/data` mempertahankan database dan kunci penandatangan lama saat redeploy.
