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

✅ **Tuần 1 hoàn thành** — đã kiểm tra thật (không chỉ viết code):
- `docker compose up -d` chạy Postgres + Redis, cả hai container `healthy`.
- Migration Alembic tạo đủ 6 bảng, FK và index đúng như thiết kế (đã test insert vi phạm FK → bị chặn).
- `GET /health` trả `{"status":"ok","database":"connected"}`, `pytest` pass.
- Frontend `npm run build` sạch, `npm run dev` điều hướng đúng `/login` ↔ `/dashboard`, không lỗi console.

Còn thiếu để chuyển sang Tuần 2: đối chiếu lại với tài liệu **"Kế hoạch đồ án"** gốc khi có (xem cảnh báo ⚠️ trong [`docs/api-contract.md`](docs/api-contract.md) mục 6).

🚧 Tiếp theo: Tuần 2 — Đăng nhập & log cơ bản. Theo dõi ở [`docs/checklist.md`](docs/checklist.md).
