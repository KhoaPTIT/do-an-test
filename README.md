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

✅ **Tuần 3 hoàn thành** — đã kiểm tra thật, kể cả bắt được 1 bug thật (member trùng trong Redis sorted set do `id(object())` bị tái sử dụng — sửa bằng `uuid4`):
- GeoIP wrapper đang dùng dữ liệu **GeoLite2-City thật** (license MaxMind đã cài — xem [`docs/geoip-setup.md`](docs/geoip-setup.md)), không bao giờ crash kể cả khi thiếu file, có log riêng lookup thất bại.
- Redis sliding window (sorted set) đếm login fail — test cả bằng curl thật (counter = đúng N) lẫn unit test (TTL, tự reset sau cửa sổ).
- Rule-based tầng 1 (`brute_force`, `credential_stuffing`, `impossible_travel`) nối thẳng vào `POST /login`, tạo `Alert` khi khớp — đã test **4 ca brute force + 3 ca credential stuffing thật** qua curl (≥ 3 ca/loại theo DoD), xác nhận không false-positive với đăng nhập bình thường.
- Dashboard 4 khu vực (bản đồ, biểu đồ, log, cảnh báo) — test cả desktop lẫn mobile viewport, không vỡ layout, không lỗi console.
- Dữ liệu mở rộng: 25 user, 924 bản ghi (88.2% bình thường / 11.8% bất thường có nhãn), nhãn lưu ở [`backend/ml/data/labels.csv`](backend/ml/data/labels.csv) — tách biệt hoàn toàn khỏi `login_events`.

✅ **Tuần 4 hoàn thành** — đã kiểm tra thật qua API, kể cả bắt được 1 bug thật khác (xem bên dưới):
- Baseline hành vi (`avg_login_hour`, `stddev_login_hour`) cập nhật realtime sau mỗi lần đăng nhập thành công + script batch [`backend/scripts/backfill_baseline.py`](backend/scripts/backfill_baseline.py) tính lại cho dữ liệu lịch sử đã nạp thẳng vào DB. **Bug thật bắt được**: session `autoflush=False` khiến vòng lặp tạo `UserBaseline`/`KnownDevice`/`KnownLocation` bị trùng khoá chính — sửa bằng `db.flush()` tường minh sau mỗi lần tạo mới.
- Chế độ học (< 10 lần đăng nhập hoặc < 7 ngày) hoạt động đúng — user mới không bị tính `unusual_hour`/`unknown_location` dù lệch giờ rất xa.
- Risk score tầng 2 (0-100, trọng số theo mục 4.2) test qua API thật: đăng nhập lệch giờ → đúng 20 điểm; thành công ngay sau 3 fail → đúng 50 điểm, tạo alert `medium` ngay lập tức; đăng nhập bình thường → 0 điểm, không alert nhầm.
- `GET /login-events` + `GET /alerts` (phân trang, **chưa có JWT** — thêm ở Tuần 5) nối vào dashboard thật: bảng log tô màu đúng ngưỡng risk, biểu đồ Recharts vẽ risk score theo thời gian, test phân trang với 1001 bản ghi (67 trang), đối chiếu dữ liệu UI khớp DB.

Còn thiếu để chuyển sang Tuần 5: đối chiếu lại với tài liệu **"Kế hoạch đồ án"** gốc khi có (xem cảnh báo ⚠️ trong [`docs/api-contract.md`](docs/api-contract.md) mục 6) — đặc biệt ngưỡng brute force/credential stuffing và "chuỗi fail" ở risk score hiện là tự giả định.

### Dữ liệu mẫu

```bash
cd backend
venv\Scripts\python.exe -m scripts.generate_historical_data --reset       # 20 user cơ bản (Tuần 2)
venv\Scripts\python.exe -m scripts.plot_login_hour_distribution           # biểu đồ kiểm tra phân bố giờ
venv\Scripts\python.exe -m scripts.generate_labeled_anomalies --reset     # 25 user + nhãn is_anomaly (Tuần 3, thay thế bộ dữ liệu trên)
venv\Scripts\python.exe -m scripts.backfill_baseline                      # tính lại baseline cho dữ liệu đã nạp thẳng (Tuần 4)
```

Trên Windows, nếu gặp lỗi `UnicodeEncodeError` khi in tiếng Việt ra console, chạy với `set PYTHONIOENCODING=utf-8` trước (cmd) hoặc `$env:PYTHONIOENCODING="utf-8"` (PowerShell).

🚧 Tiếp theo: Tuần 5 — Bảo mật & real-time. Theo dõi ở [`docs/checklist.md`](docs/checklist.md).
