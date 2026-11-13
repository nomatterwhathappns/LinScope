# Belajar LinScope dari hasil jadi

Mulai dengan menjalankan program dan membaca hasilnya. Setelah kebayang bentuk
hasilnya, ikuti satu alur data dari input sampai laporan. Tidak perlu memahami
semua modul sekaligus.

## 1. Lihat hasil tanpa memeriksa mesin dulu

Buka `examples/report.json` atau `examples/report.html`. Semuanya data sintetis,
bukan hasil pemeriksaan sebuah server sungguhan. Bandingkan dua contoh:

```bash
linscope --compare examples/report.json examples/report-after.json
```

Perhatikan perubahan `SSH-001`. Temuan selesai hanya jika berubah dari WARN/FAIL
menjadi PASS. Hilangnya bukti, misalnya berubah ke UNKNOWN, tidak dihitung selesai.

## 2. Jalankan satu kategori

Di Linux dengan Python 3.10 atau lebih baru:

```bash
linscope --category kernel
```

Mulai tanpa sudo. Pilih profil yang menggambarkan mesinmu, misalnya
`--profile container` untuk container atau `--profile router` untuk mesin yang
memang melakukan routing. Kalau command/file tidak tersedia, UNKNOWN adalah
hasil yang perlu dibaca, bukan berarti program harus mengarang kesimpulan.

## 3. Ikuti satu pemeriksaan sampai selesai

Baca urutan ini:

1. `linscope/__main__.py`: pintu masuk `python -m linscope`.
2. `linscope/cli.py`: membaca argumen dan menentukan cakupan.
3. `linscope/registry.py`: memetakan nama kategori ke fungsi pemeriksaannya.
4. `linscope/checks/kernel.py`: lihat `KERNEL-001` dan helper `_values`.
5. `linscope/core.py`: bagaimana `Context.read` membaca bukti dan `Finding`
   menyimpan hasil.
6. `linscope/reporting.py`: bagaimana hasil yang sama menjadi text/JSON/HTML.

Untuk KERNEL-001, tanyakan: file apa yang dibaca? Nilai mana yang sesuai profil
server? Kenapa profil router mengharapkan nilai berbeda? Apa yang terjadi kalau
file tidak bisa dibaca? Coba jawab dengan menunjuk baris kode yang bersangkutan.

## 4. Ulik versi kecil lebih dulu

Semua checkpoint tetap ada di branch `main`; tag menandai snapshot-nya.

| Tag | Fokus belajar |
| --- | --- |
| `v1.0` | CLI, model data, SSH, akun, permission |
| `v1.1` | PAM, jaringan/firewall, service; perbaikan penanganan shell kosong |
| `v1.2` | Sysctl, cache paket, logging |
| `v1.3` | Cron/timer, mount, AppArmor/SELinux, symlink |
| `v1.4` | Policy, HTML, perbandingan laporan, penguatan validasi input |
| `v1.5` | Konteks SSH Match, ACL, sudo efektif, baseline yang bisa diatur |
| `v1.6` | Filter tampilan, preflight, riwayat, laporan HTML interaktif |
| `v1.7` | Hardening service systemd, Docker, metadata credential milik user |

Gunakan versi terbaru untuk pemakaian; versi lama adalah checkpoint belajar
dan belum memiliki seluruh perbaikan yang ada di versi terakhir.

Untuk membaca versi lama tanpa mengganti file kerja:

```bash
git show v1.0:linscope/cli.py
git diff v1.0..v1.1 -- linscope/checks/accounts.py
```

Kalau ingin menjalankan snapshot lama, pastikan pekerjaan lokal sudah tersimpan:

```bash
git switch --detach v1.0
pipx install --force .
linscope --help
git switch main
pipx install --force .
```

## 5. Pakai tes buat mencoba perubahan

```bash
python3 -m unittest tests.test_kernel -v
python3 -m unittest discover -v
```

Tes memakai file dan hasil command buatan. Untuk latihan, ubah nilai fixture
forwarding dari 0 ke 1 dan lihat perbedaan profil server/router. Jangan mengubah
konfigurasi keamanan mesin hanya agar suatu tes lulus.

Latihan berikutnya: tambahkan satu sysctl yang lo pahami ke pola pemeriksaan
yang ada, tentukan ID baru, tulis bukti dan rekomendasinya, lalu buat tes untuk
nilai sesuai, nilai berbeda, dan izin baca ditolak. Diskusikan alasan teknisnya
sebelum menambah banyak pemeriksaan.

## Hal yang perlu bisa lo jelaskan

* Kenapa PASS hanya berlaku untuk satu baseline, bukan seluruh keamanan mesin.
* Kenapa bind `0.0.0.0` belum membuktikan akses dari internet.
* Kenapa membaca file SSH secara manual bisa berbeda dari `sshd -T`.
* Kenapa PAM yang menyebut suatu modul belum membuktikan enforcement.
* Kenapa symlink mengharuskan kita memeriksa lokasi target dan parent-nya.
* Kenapa nol update dari cache lama belum membuktikan paket sudah mutakhir.

Kalau lo bisa menjelaskan ini sambil menunjukkan kode dan tesnya, project ini
mulai menjadi bukti pemahaman infrastructure security lo.
