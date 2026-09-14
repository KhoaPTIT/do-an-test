# Hệ thống phát hiện đăng nhập bất thường

Đồ án tốt nghiệp — Anomaly Login Detection System. Giám sát các lần đăng nhập,
chấm điểm rủi ro qua 3 tầng (rule-based → behavioral scoring → ML mở rộng) và
cảnh báo gần như tức thời trên dashboard, thay vì chỉ xác thực đúng/sai mật khẩu
như một web app thông thường.

Tiến độ triển khai bám theo checklist 8 tuần trong
[`docs/checklist.md`](docs/checklist.md). Quyết định kiến trúc & API contract
(nhiệm vụ 1.1) nằm ở [`docs/api-contract.md`](docs/api-contract.md).

## Thành phần

- **backend/** — FastAPI + PostgreSQL + Redis: API đăng nhập, detection engine, WebSocket.
- **frontend/** — React (Vite): web app đăng nhập mẫu + dashboard real-time.
- **attack-sim/** — script giả lập tấn công dùng để tự kiểm thử hệ thống (Tuần 6).
- **docs/** — tài liệu quyết định, checklist, số liệu đánh giá.

## Phân công

- **Thành viên A — Backend & Detection**: schema DB, API backend, toàn bộ detection engine, bảo mật API/WebSocket.
- **Thành viên B — Frontend, Dashboard & Kiểm thử**: web app mẫu, dashboard, real-time, script tấn công, đo precision/recall.

## Chạy môi trường (Tuần 1)

Yêu cầu: Docker Desktop, Python 3.11+, Node 20+.

```bash
cp .env.example .env      # sửa giá trị nếu cần, không commit .env

docker compose up -d      # PostgreSQL + Redis
```

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate      # Windows — macOS/Linux: source venv/bin/activate
pip install -r requirements.txt

alembic upgrade head       # tạo schema 6 bảng
uvicorn app.main:app --reload --port 8000
```

Kiểm tra: `http://localhost:8000/health` phải trả `{"status": "ok", "database": "connected"}`.
Tài liệu API tự sinh: `http://localhost:8000/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Mở `http://localhost:5173` — điều hướng được giữa `/login` và `/dashboard` (chưa có logic, chỉ khung).

## Trạng thái

✅ **Tuần 1 hoàn thành** — kiến trúc, schema DB (6 bảng), khung backend/frontend. Xem chi tiết ở lịch sử README trước hoặc [`docs/checklist.md`](docs/checklist.md).

✅ **Tuần 2 hoàn thành** — đã kiểm tra thật:
- `POST /login` ghi log mọi lần thử (thành công/thất bại/tài khoản không tồn tại) — test bằng curl + 5 unit test đều pass, mật khẩu không lộ plain text ở đâu (đã grep log server).
- Form đăng nhập frontend gọi API thật, xử lý đúng cả 2 trường hợp, field request/response khớp `docs/api-contract.md` (đã kiểm tra qua tab Network trình duyệt).
- Script [`backend/scripts/generate_historical_data.py`](backend/scripts/generate_historical_data.py) tạo 20 user + ~580-600 bản ghi lịch sử, mỗi user tập trung quanh 1 khung giờ riêng (stddev ~1-1.3h so với ~6.93h nếu random đều) — xem biểu đồ [`docs/figures/login_hour_distribution.png`](docs/figures/login_hour_distribution.png).

Còn thiếu để chuyển sang Tuần 3: đối chiếu lại với tài liệu **"Kế hoạch đồ án"** gốc khi có (xem cảnh báo ⚠️ trong [`docs/api-contract.md`](docs/api-contract.md) mục 6).

### Dữ liệu mẫu

```bash
cd backend
venv\Scripts\python.exe -m scripts.generate_historical_data --reset   # tạo lại 20 user + login_events giả lập
venv\Scripts\python.exe -m scripts.plot_login_hour_distribution       # vẽ biểu đồ kiểm tra phân bố giờ
```

Trên Windows, nếu gặp lỗi `UnicodeEncodeError` khi in tiếng Việt ra console, chạy với `set PYTHONIOENCODING=utf-8` trước (cmd) hoặc `$env:PYTHONIOENCODING="utf-8"` (PowerShell).

🚧 Tiếp theo: Tuần 3 — Rule-based tầng 1. Theo dõi ở [`docs/checklist.md`](docs/checklist.md).
