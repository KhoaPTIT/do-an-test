# Cài GeoLite2 thật (thay chế độ mock)

`backend/app/detection/geoip.py` tự chạy ở "chế độ mock" khi chưa có file
`.mmdb`. Hệ thống vẫn chạy đúng, chỉ là GeoIP luôn trả `None` trừ vài IP mẫu
cứng trong code. Để dùng dữ liệu thật:

1. Đăng ký tài khoản free tại `https://www.maxmind.com/en/geolite2/signup`.
2. Đăng nhập → **My License Keys** → **Generate new license key**.
3. Tải `GeoLite2-City.mmdb`:
   - Cách 1 (tay): trang **Download Files** → tải `GeoLite2-City` (định dạng `.mmdb`), giải nén.
   - Cách 2 (script, cần license key): xem `https://dev.maxmind.com/geoip/updating-databases`.
4. Đặt file vào `backend/geoip/GeoLite2-City.mmdb` (thư mục này đã được `.gitignore`, không commit — file ~60MB và có điều khoản license riêng).
5. Không cần sửa code — `geoip.py` tự phát hiện file tồn tại và chuyển qua dùng thật ở lần gọi tiếp theo (restart backend để chắc chắn).

Kiểm tra đã hoạt động:

```bash
cd backend
venv\Scripts\python.exe -c "from app.detection.geoip import lookup_ip; print(lookup_ip('8.8.8.8'))"
```

Nếu thấy `country='US'` (thay vì mock cứng `Mountain View`), tức là đang đọc từ file `.mmdb` thật.
