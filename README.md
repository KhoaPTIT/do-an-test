# Hệ thống phát hiện đăng nhập bất thường

Đồ án tốt nghiệp — Anomaly Login Detection System. Giám sát các lần đăng nhập,
chấm điểm rủi ro bằng **20 detector luật đã kiểm chứng + một model AI phát hiện bất thường (Isolation Forest)** gộp
thành MỘT điểm rủi ro, và cảnh báo gần như tức thời trên dashboard, thay vì chỉ xác thực đúng/sai mật khẩu như một web
app thông thường. Luồng: `POST /login` → 20 rule + ML → risk score → alert → dashboard; ML chỉ là tín hiệu bổ sung, không
bao giờ tự khoá tài khoản ([`docs/ml-anomaly-model.md`](docs/ml-anomaly-model.md)).
Toàn cảnh hành vi nào được phát hiện, bằng detector nào, kiểm chứng tới đâu (Phase 3: **20/21 hành vi VERIFIED**
qua pipeline thật, bằng chứng do máy sinh): [`docs/behavior-coverage-matrix.md`](docs/behavior-coverage-matrix.md).

Tiến độ triển khai theo hai giai đoạn: **Tuần 1-8** (khung hệ thống, xem "Trạng
thái" bên dưới) rồi **giai đoạn mở rộng AI, MR1-19** (nâng cấp lên rule engine
v2, mô hình ML hybrid huấn luyện trên bộ dữ liệu học thuật RBA, phản ứng tự
động, dashboard quản trị) — checklist đầy đủ ở [`docs/checklist.md`](docs/checklist.md).
Quyết định kiến trúc & API contract (nhiệm vụ 1.1) nằm ở [`docs/api-contract.md`](docs/api-contract.md).

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

alembic upgrade head       # tạo toàn bộ schema
python -m ml.pipeline      # train model AI (~1 phút, dataset tổng hợp sinh từ mã trong repo) -> ml/artifacts/anomaly_iforest/
uvicorn app.main:app --reload --port 8000   # lúc khởi động tự nạp model; thiếu artifact thì chạy bằng 20 detector luật
```

Kiểm tra model AI: `GET /ml/status` (JWT admin) hoặc trang **Sức khoẻ mô hình** trên dashboard.

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

Mở `http://localhost:5173` — `/login` là trang đăng nhập chung, hệ thống tự phân quyền theo tài khoản: user web app mẫu ở lại trang, admin được chuyển vào `/dashboard`.

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
- Dữ liệu mở rộng: 25 user, 924 bản ghi (88.2% bình thường / 11.8% bất thường có nhãn), nhãn tách biệt hoàn toàn khỏi `login_events` (từ Phase 4.1 ghi ra `backend/ml/data/demo_dashboard_labels.csv`, không commit).

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

✅ **Tuần 7 hoàn thành (7.1 + 7.2)** — ⚠️ *lịch sử: bộ dữ liệu, mã và số liệu tầng 3 dưới đây đã gỡ ở Phase 4.1, KHÔNG tái lập được trên mã hiện tại; model AI đang chạy và số liệu hiện hành ở mục "Phase 4.1" bên dưới.*
- **5 kiểu bất thường** (không chỉ 2 như Tuần 3): giờ lạ, vị trí lạ, thiết bị lạ, tốc độ đăng nhập bất thường, kết hợp nhiều tín hiệu — 40 user riêng, 1846 bản ghi, 15.2% có nhãn bất thường.
- **3 thuật toán ML** so sánh công bằng trên cùng tập test tách theo thời gian (không rò rỉ dữ liệu tương lai): Isolation Forest (F1=0.751, ROC-AUC=0.882), Local Outlier Factor (F1=0.717), Autoencoder (F1=0.612) — cả 3 **vượt xa** tầng 2 hành vi cũ (F1=0.070, gần như "im lặng hoàn toàn", chỉ bắt 3/83 ca).
- **So sánh trên chính hàm sản xuất thật** (`compute_risk_score()`), không viết lại song song — phát hiện nguyên nhân gốc rễ: tầng 2 không có trọng số cho thiết bị lạ/tốc độ bất thường, và baseline giờ bị "pha loãng" theo thời gian (hạn chế thật trong production, không phải lỗi đánh giá).
- **Tích hợp real-time thật** — tầng 3 chạy song song tầng 1-2, không thay thế: test trực tiếp trên server sống, bắt được ca mà tầng 2 bỏ sót (risk_score=30, dưới ngưỡng 40, nhưng ML đúng phát hiện bất thường).
- Phân tích đầy đủ + giới hạn thật (dữ liệu tự sinh, không phải tấn công thật ngoài đời) — nói thẳng để không overclaim khi bảo vệ: [`docs/ml-evaluation.md`](docs/ml-evaluation.md).
- **7.2 — giao diện viết lại hoàn chỉnh**: hệ thống thiết kế riêng (CSS variables, bỏ template Vite mặc định), nav bar + form đăng nhập + dashboard đều polish lại, trạng thái loading có spinner (không giật bảng khi có alert mới), test responsive thật trên desktop/tablet/mobile (bắt và sửa 1 lỗi thật: nav bar vỡ chữ giữa từ trên màn hình hẹp).

Còn thiếu: đối chiếu lại với tài liệu **"Kế hoạch đồ án"** gốc khi có (xem cảnh báo ⚠️ trong [`docs/api-contract.md`](docs/api-contract.md) mục 6).

### Dữ liệu mẫu

```bash
cd backend
venv\Scripts\python.exe -m scripts.generate_historical_data --reset       # 20 user cơ bản (Tuần 2)
venv\Scripts\python.exe -m scripts.plot_login_hour_distribution           # biểu đồ kiểm tra phân bố giờ
venv\Scripts\python.exe -m scripts.generate_labeled_anomalies --reset     # 25 user + nhãn is_anomaly (Tuần 3, thay thế bộ dữ liệu trên)
venv\Scripts\python.exe -m scripts.backfill_baseline                      # tính lại baseline cho dữ liệu đã nạp thẳng (Tuần 4)
venv\Scripts\python.exe -m scripts.create_admin --username admin --password "MatKhauManh123!"   # tạo tài khoản admin (Tuần 5)

# Model AI (Phase 4.1) — dataset TỔNG HỢP riêng (file CSV, không ghi vào DB), xem docs/ml-anomaly-model.md
venv\Scripts\python.exe -m ml.pipeline                      # = ml.dataset -> ml.build_features -> ml.train -> ml.evaluate
```

Trên Windows, nếu gặp lỗi `UnicodeEncodeError` khi in tiếng Việt ra console, chạy với `set PYTHONIOENCODING=utf-8` trước (cmd) hoặc `$env:PYTHONIOENCODING="utf-8"` (PowerShell).

## ✅ Giai đoạn mở rộng AI hoàn thành (MR1-19)

Sau Tuần 1-8, dự án tiếp tục 19 MR (merge request) nâng cấp phần AI/detection theo kế hoạch đã duyệt — mỗi MR có tài
liệu findings riêng, liệt kê đầy đủ ở [`docs/checklist.md`](docs/checklist.md). Tóm tắt không đầy đủ, chỉ nêu phần lớn nhất:

- **Mô hình ML trên dữ liệu học thuật thật** (MR1-8, MR8b/CP2): huấn luyện và đánh giá 13 mô hình/baseline trên bộ
  **RBA** (Wiefling et al., ACM TOPS 2022 — dữ liệu **tổng hợp**, không phải log thật, xem
  [`docs/rba-data-card.md`](docs/rba-data-card.md)), có khoảng tin cậy, kiểm định rò rỉ/dấu vân tay của bộ mô phỏng
  kẻ tấn công. Mô hình chốt `hybrid_cp2` chạy trên `/login` từ MR12 tới Phase 4.0; **từ Phase 4.1 đã gỡ khỏi runtime** (cần bộ
  9GB ngoài repo, lệch train/serve — audit Phase 4.0), chỉ còn là nghiên cứu offline. Kết quả đầy đủ:
  [`docs/ml-evaluation-v2.md`](docs/ml-evaluation-v2.md), model card: [`docs/model-card-rba.md`](docs/model-card-rba.md).
- **Rule engine v2** (MR9-10, mở rộng ở Phase 3): 23 luật hành vi/hạ tầng cấu hình được qua admin UI (MR17); luật
  `verified` tự tạo cảnh báo gắn đúng luật, `datacenter_ip`/`vpn_ip` vẫn `shadow`, `unusual_hour` vẫn `experimental` —
  danh mục đầy đủ: [`docs/rule-catalog.md`](docs/rule-catalog.md).
- **Hybrid risk engine** (MR11): ghép luật + ML thành một điểm rủi ro (noisy-OR), ngưỡng cảnh báo/xác thực thêm/khoá — [`docs/hybrid-risk-engine.md`](docs/hybrid-risk-engine.md) (hồ sơ hiệu chỉnh RBA không còn nạp từ Phase 4.1).
- **Giải thích cảnh báo** (MR8): mỗi cảnh báo kèm tối đa 3 lý do bằng tiếng Việt, đã kiểm định độ trung thực — [`docs/ml-explanations.md`](docs/ml-explanations.md).
- **Phản ứng tự động** (MR16): OTP xác thực thêm (mô phỏng), khoá tài khoản/IP có hạn, admin mở khoá — [`docs/automated-response.md`](docs/automated-response.md).
- **Vòng phản hồi & ngưỡng thích nghi** (MR15): nút "Đúng/Báo nhầm" nới ngưỡng theo user/nhóm, không bao giờ tự siết dưới mức mặc định — [`docs/feedback-loop.md`](docs/feedback-loop.md).
- **Tương quan chiến dịch** (MR14) và **thư viện kịch bản tấn công mô phỏng v2** (MR18, 9 kịch bản có scorecard) — [`docs/attack-scenarios-v2.md`](docs/attack-scenarios-v2.md).
- **Dashboard quản trị v2** (MR17): cấu hình luật, sức khoẻ mô hình (trạng thái model AI đang chạy; PSI drift RBA cũ), hồ sơ rủi ro theo user.
- **Kiểm chứng hành vi phát hiện** (Phase 3, Milestone A → C+): mỗi hành vi 20 kịch bản dương tính + 20 âm tính sát
  ngưỡng + lưu lượng bình thường 63 người dùng × 30 ngày, chấm theo QUY KẾT (cảnh báo phải mang đúng `rule_id`) —
  20/21 VERIFIED, cross-behavior 19/19; bằng chứng: [`artifacts/behavior_verification/`](artifacts/behavior_verification/),
  chạy lại: `cd backend && python -m scripts.behavior_verification`. Phần bổ sung hành vi phát hiện đã KẾT THÚC ở Milestone C+.
- **Tổng hợp cuối cùng** (MR19, ma trận cập nhật ở Phase 3): ma trận phủ toàn bộ hành vi × tầng phát hiện — [`docs/behavior-coverage-matrix.md`](docs/behavior-coverage-matrix.md); so với công cụ thương mại (Okta, Microsoft Entra ID Protection, Auth0) và baseline học thuật — [`docs/commercial-comparison.md`](docs/commercial-comparison.md).

⚠️ Mọi số liệu ML trong các tài liệu trên đo trên dữ liệu **tổng hợp** hoặc **tự mô phỏng**, không phải log tấn công
thật ngoài đời — xem giới hạn ở từng tài liệu trước khi trích dẫn.

Hướng dẫn chạy các phần MR1-19 (rule engine v2, hybrid model, admin config, simulator...): [`docs/getting-started.md`](docs/getting-started.md). Tái lập toàn bộ pipeline nghiên cứu (huấn luyện lại mọi mô hình, kịch bản mô phỏng, từ đầu) theo đúng thứ tự: [`docs/reproduction-guide.md`](docs/reproduction-guide.md).

🚧 Còn lại (ngoài phạm vi MR1-19, chưa làm): mục "Bổ sung tuỳ chọn" ở cuối [`docs/checklist.md`](docs/checklist.md).
