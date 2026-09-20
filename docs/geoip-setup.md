# Cài GeoLite2 thật (thay chế độ mock)

✅ **Đã cài xong** (14/09/2026) — `backend/geoip/GeoLite2-City.mmdb` (~63MB) đang có sẵn, không commit lên git (`.gitignore`). Nếu file bị mất/máy khác cần cài lại, làm theo hướng dẫn dưới.

`backend/app/detection/geoip.py` tự chạy ở "chế độ mock" khi chưa có file
`.mmdb`. Hệ thống vẫn chạy đúng, chỉ là GeoIP luôn trả `None` trừ vài IP mẫu
cứng trong code. Để dùng dữ liệu thật:

1. Đăng ký tài khoản free tại `https://www.maxmind.com/en/geolite2/signup`.
2. Đăng nhập → **My License Keys** → **Generate new license key**.
3. Thêm vào `.env` (gốc repo, không commit): `MAXMIND_ACCOUNT_ID=...` và `MAXMIND_LICENSE_KEY=...`.
4. Tải database — **dùng endpoint cũ** (`geoip_download`, chỉ cần license key qua query param; endpoint mới `download.maxmind.com/geoip/databases/...` cần Basic Auth `account_id:license_key` và đã bị từ chối xác thực với key kiểu cũ khi test — tuỳ loại key khi tạo trên MaxMind mà endpoint nào chạy được):

   ```bash
   cd /path/to/repo
   set -a && source .env && set +a
   curl -sS -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" -o /tmp/GeoLite2-City.tar.gz
   tar -xzf /tmp/GeoLite2-City.tar.gz -C /tmp
   cp /tmp/GeoLite2-City_*/GeoLite2-City.mmdb backend/geoip/GeoLite2-City.mmdb
   rm -rf /tmp/GeoLite2-City*
   ```

5. Không cần sửa code — `geoip.py` tự phát hiện file tồn tại và chuyển qua dùng thật ở lần gọi tiếp theo (restart backend để chắc chắn).

Kiểm tra đã hoạt động:

```bash
cd backend
venv\Scripts\python.exe -c "from app.detection.geoip import lookup_ip; print(lookup_ip('8.8.8.8'))"
```

## GeoLite2-ASN (giai đoạn mở rộng, cần từ MR12)

Đặc trưng ASN (nhà mạng/hạ tầng của IP) dùng file **riêng** `GeoLite2-ASN.mmdb`, không nằm trong GeoLite2-City. Chưa có file này thì `lookup_asn()` trả `None` (không lỗi) — làm việc với dữ liệu RBA (MR2–MR8) không cần file này vì RBA đã có sẵn cột ASN; chỉ luồng đăng nhập thật (MR12) mới cần.

Tải giống bước 4 ở trên, đổi `edition_id`:

```bash
cd /path/to/repo
set -a && source .env && set +a
curl -sS -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" -o /tmp/GeoLite2-ASN.tar.gz
tar -xzf /tmp/GeoLite2-ASN.tar.gz -C /tmp
cp /tmp/GeoLite2-ASN_*/GeoLite2-ASN.mmdb backend/geoip/GeoLite2-ASN.mmdb
rm -rf /tmp/GeoLite2-ASN*
```

Hoặc tải thủ công trên trang MaxMind (**Download Files → GeoLite2 ASN**) rồi chép `GeoLite2-ASN.mmdb` vào `backend/geoip/`. Đường dẫn cấu hình bằng `GEOIP_ASN_DB_PATH` (mặc định `./geoip/GeoLite2-ASN.mmdb`). Kiểm tra: `python -m ml.check_env`.

Kết quả thật (đã xác nhận): `GeoResult(country='US', city=None, latitude=37.751, longitude=-97.822)` — khác giá trị mock cứng (`Mountain View`), tức là đang đọc từ file `.mmdb` thật. Lưu ý một số IP (VD `1.1.1.1`) trả về đủ trường `None` dù lookup "thành công" — GeoLite2 free không có dữ liệu cho mọi IP, đây là hành vi bình thường, không phải lỗi.
