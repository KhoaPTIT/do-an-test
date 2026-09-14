# Hướng dẫn khởi động dự án

Máy đã cài sẵn mọi thứ (Docker, venv, node_modules). Đây là các bước để
**chạy lại từ đầu mỗi khi mở máy/mở lại dự án**. Mở 2 cửa sổ terminal
(PowerShell hoặc Git Bash) — 1 cho backend, 1 cho frontend.

## Bước 1 — Bật Docker Desktop

Mở app **Docker Desktop**, đợi tới khi icon cá voi hết loading (khoảng
30s-1 phút). Sau đó ở terminal bất kỳ:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong
docker compose up -d
docker ps
```

Phải thấy `lad_postgres` và `lad_redis` ở trạng thái `healthy`. Nếu lệnh
`docker compose` báo lỗi kết nối → Docker Desktop chưa khởi động xong, đợi
thêm rồi thử lại.

## Bước 2 — Chạy backend (terminal 1)

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```

Kiểm tra: mở `http://localhost:8000/health` phải thấy
`{"status":"ok","database":"connected"}`. Tài liệu API tự sinh ở
`http://localhost:8000/docs`.

> Terminal này phải để chạy liên tục (không đóng) trong lúc dùng hệ thống.

## Bước 3 — Chạy frontend (terminal 2, cửa sổ khác)

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\frontend
npm run dev
```

Mở `http://localhost:5173` trên trình duyệt.

## Bước 4 — Đăng nhập thử

Web app mẫu ở `http://localhost:5173/login`. Tài khoản có sẵn (do script
sinh dữ liệu tạo — xem Bước 5):

- Username: `user001` đến `user025`
- Password: `Demo@12345` (giống nhau cho tất cả)

Đăng nhập đúng sẽ chuyển sang `/dashboard` (hiện mới có khung 4 khu vực,
chưa nối dữ liệu thật — sẽ làm ở Tuần 4).

## Bước 5 — (Tuỳ chọn) Sinh lại dữ liệu mẫu

Chỉ cần chạy lại khi muốn dữ liệu mới hoặc lần đầu setup máy mới. Dữ liệu
hiện tại (25 user, 924 bản ghi có nhãn) đã có sẵn trong Postgres, **không
cần chạy lại** trừ khi bạn muốn.

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
set PYTHONIOENCODING=utf-8
python -m scripts.generate_labeled_anomalies --reset
```

## Dừng hệ thống khi xong việc

- Terminal backend/frontend: `Ctrl+C`.
- Docker: `docker compose down` (giữ lại dữ liệu DB) hoặc để chạy nền cũng
  không sao — không tốn tài nguyên đáng kể khi máy rảnh.

## Lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| `uvicorn` báo lỗi bind port 8000 | Còn tiến trình cũ chưa tắt | Đóng terminal cũ đang chạy uvicorn, hoặc `netstat -ano \| findstr :8000` rồi `taskkill /F /PID <pid>` |
| Vite báo "Port 5173 is in use" | Tương tự, tiến trình cũ | Đóng terminal cũ hoặc kill theo PID như trên |
| Chữ tiếng Việt lỗi (`UnicodeEncodeError`) khi chạy script Python | Console Windows dùng codepage cp1252 | Chạy `set PYTHONIOENCODING=utf-8` trước khi gọi script |
| `docker compose up` báo lỗi kết nối tới Docker | Docker Desktop chưa khởi động xong | Mở Docker Desktop, đợi rồi thử lại |
| Frontend gọi API bị lỗi CORS | Backend chưa chạy, hoặc chạy sai port | Đảm bảo backend chạy ở port 8000 (khớp `VITE_API_BASE_URL` trong `.env`) |

## Chạy test

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
pytest -q
```

Không cần Docker chạy — test dùng SQLite in-memory + Redis giả lập
(fakeredis), tách biệt hoàn toàn khỏi dữ liệu dev thật.
