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

alembic upgrade head       # tạo schema 6 bảng + admins (Tuần 5)
uvicorn app.main:app --reload --port 8000
```

Kiểm tra: `http://localhost:8000/health` phải trả `{"status": "ok", "database": "connected"}`.
Tài liệu API tự sinh: `http://localhost:8000/docs`.

Tạo tài khoản admin (bắt buộc để vào được `/dashboard` từ Tuần 5):

```bash
venv\Scripts\python.exe -m scripts.create_admin --username admin --password "MatKhauManh123!"
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Mở `http://localhost:5173` — `/login` là web app mẫu, `/admin/login` là đăng nhập quản trị (bắt buộc trước khi vào `/dashboard`).

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

✅ **Tuần 5 hoàn thành** — đã kiểm tra thật, kể cả một phát hiện đo lường trung thực (không phải cải thiện "đẹp"):
- JWT admin (`POST /admin/login`, bảng `admins` tách biệt hoàn toàn khỏi `users`) bảo vệ `GET /login-events`, `GET /alerts` và WebSocket `/ws/alerts` — test qua request thật cả 2 chiều (không token → 401, có token → 200/kết nối được) và WebSocket thật (`websockets` client Python: không token bị từ chối, có token kết nối thành công).
- Detection engine (GeoIP, rule tầng 1, risk score tầng 2, baseline...) chuyển sang chạy nền qua `BackgroundTasks` (`POST /login` giờ chỉ verify password rồi trả response ngay). **Benchmark thật trước/sau** (xem [`docs/performance.md`](docs/performance.md)): **không cải thiện đáng kể** vì bcrypt chiếm ~227ms/tổng ~250-260ms — đây là kết quả trung thực kèm phân tích, không chỉnh sửa số liệu cho đẹp.
- Dashboard nối WebSocket real-time thật: bắn alert từ backend → popup + bảng log/biểu đồ tự làm mới trong < 1s không cần reload; kill backend rồi bật lại → tự reconnect, không cần reload trang; mô phỏng `impossible_travel` → bản đồ vẽ đúng 2 điểm + đường nối (ảnh minh chứng đã xem trực tiếp qua trình duyệt).
- Phát hiện rủi ro bảo mật nhỏ đã biết: JWT qua query param WebSocket có thể lộ trong console log — ghi rõ trong [`docs/api-contract.md`](docs/api-contract.md) mục 3, giảm thiểu bằng JWT hết hạn 60 phút.

✅ **Tuần 6 hoàn thành** — 4 script giả lập tấn công (`attack-sim/`) + kiểm thử end-to-end thật, bắt và sửa đúng 2 lỗi mức "chặn demo" trước khi coi tuần này xong:
- `brute_force.py`, `credential_stuffing.py`, `success_after_fail.py`, `impossible_travel.py` — mỗi script test độc lập qua dashboard thật, đúng alert tương ứng xuất hiện real-time, không cần thao tác thủ công.
- **Lỗi 1 (đã sửa):** IP mẫu ban đầu cho `impossible_travel.py` (`203.0.113.10`, dải TEST-NET) không có trong GeoLite2 thật → lookup luôn thất bại có kiểm soát → alert không kích hoạt được. Đổi sang IP thật (`203.119.101.100`, Brisbane/AU).
- **Lỗi 2 (đã sửa):** bản đồ vẽ đúng marker + đường nối nhưng nằm ngoài khung nhìn mặc định (center Việt Nam) khi toạ độ ở xa — trông như không vẽ gì. `MapPanel.jsx` thêm tự động `fitBounds()`.
- Bảng test case đầy đủ + phân loại lỗi: [`docs/e2e-test-report.md`](docs/e2e-test-report.md). Hệ thống chạy liên tục không lỗi suốt phiên kiểm thử.

Còn thiếu để chuyển sang Tuần 7: đối chiếu lại với tài liệu **"Kế hoạch đồ án"** gốc khi có (xem cảnh báo ⚠️ trong [`docs/api-contract.md`](docs/api-contract.md) mục 6).

### Dữ liệu mẫu

```bash
cd backend
venv\Scripts\python.exe -m scripts.generate_historical_data --reset       # 20 user cơ bản (Tuần 2)
venv\Scripts\python.exe -m scripts.plot_login_hour_distribution           # biểu đồ kiểm tra phân bố giờ
venv\Scripts\python.exe -m scripts.generate_labeled_anomalies --reset     # 25 user + nhãn is_anomaly (Tuần 3, thay thế bộ dữ liệu trên)
venv\Scripts\python.exe -m scripts.backfill_baseline                      # tính lại baseline cho dữ liệu đã nạp thẳng (Tuần 4)
venv\Scripts\python.exe -m scripts.create_admin --username admin --password "MatKhauManh123!"   # tạo tài khoản admin (Tuần 5)
```

Trên Windows, nếu gặp lỗi `UnicodeEncodeError` khi in tiếng Việt ra console, chạy với `set PYTHONIOENCODING=utf-8` trước (cmd) hoặc `$env:PYTHONIOENCODING="utf-8"` (PowerShell).

🚧 Tiếp theo: Tuần 7 — ML mở rộng & đánh giá hệ thống. Theo dõi ở [`docs/checklist.md`](docs/checklist.md).
