# Quyết định kiến trúc & API contract (nhiệm vụ 1.1)

Ghi lại theo yêu cầu checklist mục 1.1. Đây là quyết định làm việc của nhóm —
**chưa đối chiếu với tài liệu "Kế hoạch đồ án" gốc** (chưa có trong repo lúc viết
tài liệu này). Chỗ nào tài liệu gốc quy định khác, sửa lại theo tài liệu gốc và
xoá dòng ghi chú "⚠️ giả định" tương ứng.

## 1. Sơ đồ kiến trúc tóm tắt

```
Web app mẫu (React)                Attack-sim scripts
        │  POST /login                     │  POST /login (giả lập)
        ▼                                   ▼
                     FastAPI backend
                            │
                 ┌──────────┼──────────┐
                 ▼          ▼          ▼
           Ghi login_events   Redis      GeoIP (.mmdb)
                 │        (đếm fail)         │
                 └──────────┬───────────────┘
                             ▼
                    Detection engine
              (rule-based → behavioral → ML)
                             │
                    risk_score + alerts
                             │
                    WebSocket (JWT) ──────▶ Dashboard (React)
                             │
                     Admin API (JWT) ──────▶ Dashboard (bảng log, biểu đồ)
```

- **Web app mẫu**: nơi người dùng cuối đăng nhập — mục tiêu bị tấn công (brute force, credential stuffing...).
- **Backend**: một service FastAPI duy nhất, chứa cả API đăng nhập, admin API, detection engine và WebSocket — không tách microservice (quy mô đồ án không cần).
- **Dashboard**: React riêng, chỉ admin đăng nhập được (JWT riêng, tách khỏi tài khoản web app mẫu).

## 2. Quy ước API chung

- Định dạng: JSON, `snake_case` cho mọi field.
- Thời gian: ISO 8601, UTC, có hậu tố `Z` — ví dụ `"2026-09-14T10:23:00Z"`. Backend lưu và trả về UTC; frontend tự convert sang giờ local khi hiển thị.
- Lỗi: theo mặc định của FastAPI — `{"detail": "<thông báo>"}`, HTTP status code phản ánh đúng loại lỗi (400/401/403/404/422/500).
- Phân trang: query param `page` (bắt đầu từ 1) và `page_size` (mặc định 20, tối đa 100). Response bọc trong `{"items": [...], "total": N, "page": N, "page_size": N}`.
- Auth: 2 hệ thống tách biệt hoàn toàn —
  - Tài khoản **web app mẫu** (`users` table) — không có quyền admin, không gọi được API quản trị.
  - Tài khoản **admin** (Tuần 5, chưa có bảng riêng ở Tuần 1) — đăng nhập qua `POST /login` (trang đăng nhập chung — response có `role="admin"` + `access_token`) hoặc `/admin/login`, nhận JWT, dùng cho toàn bộ route quản trị + WebSocket.

## 3. Endpoint (theo từng tuần triển khai)

| Endpoint | Tuần | Mô tả |
|---|---|---|
| `GET /health` | 1 | Kiểm tra service + kết nối DB |
| `POST /login` | 2 | Đăng nhập chung: tài khoản web app mẫu (ghi `login_events`, `role="user"`) hoặc admin (trả `role="admin"` + `access_token` JWT, không ghi `login_events`) |
| `POST /admin/login` | 5 | Đăng nhập admin (bảng `admins` riêng), trả JWT (`jwt_expire_minutes` = 60) |
| `GET /login-events` | 4→5→8 | Danh sách log, phân trang + lọc (`username`, `success`, `risk_level`, `is_synthetic` — nâng cấp sau Tuần 7). **Có JWT bắt buộc từ Tuần 5** |
| `GET /alerts` | 4→5→13→17 | Danh sách cảnh báo, phân trang, mặc định sắp theo ưu tiên (`?sort=priority`\|`recent`, MR13); lọc `?attack_family=`\|`rule_id=`\|`campaign_id=`\|`status=` (MR17). **Có JWT bắt buộc từ Tuần 5** |
| `GET /campaigns` | 14 | Danh sách chiến dịch (nhiều tài khoản chung hạ tầng), phân trang, lọc `?status=`. **Có JWT bắt buộc từ Tuần 5** |
| `GET /campaigns/{id}` | 14 | Chi tiết một chiến dịch: timeline, tài khoản bị nhắm, đồ thị liên kết user-IP-ASN-thiết bị. **Có JWT bắt buộc từ Tuần 5** |
| `POST /alerts/{id}/feedback` | 15 | "Đúng"/"Báo nhầm" (`{correct, note?}`) — ghi `alerts.status`/`feedback` + `audit_log`; ngưỡng thích nghi tính lại ĐỊNH KỲ, không phải ngay lúc gọi. **Có JWT bắt buộc từ Tuần 5** |
| `POST /login/verify-otp` | 16 | Xác thực bước OTP giả lập khi `POST /login` trả `step_up_required=true` (`{challenge_id, code}`) |
| `GET /blocklist` | 16 | Danh sách khoá tạm/chặn (`?active_only=`, mặc định `true`), phân trang. **Có JWT bắt buộc từ Tuần 5** |
| `DELETE /blocklist/{id}` | 16 | Mở khoá trước hạn — ghi `audit_log` rồi xoá hàng, vô hiệu cache 15s ngay. **Có JWT bắt buộc từ Tuần 5** |
| `GET /rules` | 17 | Danh sách MỌI luật kèm trạng thái hiệu lực (mặc định GHÉP ghi đè, nếu có). **Có JWT bắt buộc từ Tuần 5** |
| `PUT /rules/{id}` | 17 | Bật/tắt + chỉnh tham số một luật (`{mode?, params?}`, chỉ field có mặt mới đổi). **Có JWT bắt buộc từ Tuần 5** |
| `DELETE /rules/{id}` | 17 | Khôi phục mặc định của sổ đăng ký (xoá hẳn ghi đè). **Có JWT bắt buộc từ Tuần 5** |
| `GET /model-health` | 17 | Phiên bản mô hình đã đăng ký + trôi đặc trưng (PSI, 300 dòng gần nhất, `?refresh=` bỏ qua cache 10 phút). **Có JWT bắt buộc từ Tuần 5** |
| `GET /users/{id}/profile` | 17 | Hồ sơ user: timeline (50 gần nhất), alert (20 gần nhất), thiết bị/quốc gia quen, ngưỡng rủi ro riêng (MR15). **Có JWT bắt buộc từ Tuần 5** |
| `WS /ws/alerts` | 5 | Đẩy cảnh báo real-time, xác thực bằng JWT qua query param `?token=` |

⚠️ **Rủi ro đã biết (chấp nhận có chủ đích):** JWT qua query param của WebSocket
có thể lộ ra trong console log lỗi trình duyệt, access log phía server, và
đôi khi lịch sử trình duyệt — khác với header (không bị log theo cách này).
Checklist gốc mục 5.1 cho phép "qua query param hoặc header khi handshake";
chọn query param vì `WebSocket` API của trình duyệt không hỗ trợ set custom
header khi handshake. Giảm thiểu bằng JWT hết hạn sau 60 phút.

⚠️ **Rủi ro đã biết khác (Tuần 6, `TRUST_FORWARDED_FOR`):** `POST /login`
đọc IP nguồn từ header `X-Forwarded-For` thay vì IP TCP thật khi biến môi
trường `TRUST_FORWARDED_FOR=true` — chỉ để script `attack-sim/impossible_travel.py`
giả lập vị trí đăng nhập khi demo cục bộ. Mặc định **TẮT**. Bật cờ này khi
backend expose thật ra ngoài (không qua reverse proxy đáng tin cậy) cho
phép BẤT KỲ ai tự khai IP nguồn tuỳ ý, né được toàn bộ rule theo IP (brute
force theo IP, credential stuffing, GeoIP) — xem `backend/app/config.py`.

### `POST /login` (nhiệm vụ 2.1, mở rộng MR16)

Request:
```json
{ "username": "user007", "password": "matkhau123" }
```

Response 200 (thành công — MR16 thêm 4 field mới, luôn có mặt với giá trị "không có gì đặc biệt" khi đăng nhập bình thường):
```json
{ "success": true, "message": "Login successful", "step_up_required": false, "challenge_id": null, "demo_otp_code": null, "locked": false }
```

Response 401 (sai mật khẩu **hoặc** tài khoản không tồn tại — dùng chung một thông báo để tránh lộ thông tin user có tồn tại hay không):
```json
{ "success": false, "message": "Invalid username or password" }
```

Response 200, `step_up_required=true` (MR16 — mật khẩu ĐÚNG nhưng hybrid risk engine đề xuất xác thực thêm cho CHÍNH lần thử này; vẫn HTTP 200 vì mật khẩu đã được xác nhận đúng, chỉ chưa đủ để hoàn tất):
```json
{ "success": false, "message": "Cần xác thực thêm — mã demo: 042857 (...)", "step_up_required": true, "challenge_id": 42, "demo_otp_code": "042857", "locked": false }
```
⚠️ `demo_otp_code` CHỈ tồn tại vì đây là OTP **GIẢ LẬP** (không có nhà cung cấp SMS/email nào tích hợp) — hệ thống thật không bao giờ trả mã trực tiếp trong response. Gọi `POST /login/verify-otp` với `challenge_id`+mã để hoàn tất.

Response 423 (MR16 — tài khoản hoặc IP nguồn đang bị khoá tạm; từ chối NGAY TỪ TRƯỚC khi xác thực mật khẩu nếu bị chặn từ trước, hoặc SAU khi chấm điểm nếu mật khẩu đúng nhưng hành động là `lock`):
```json
{ "success": false, "message": "Tài khoản hoặc nguồn đăng nhập đang tạm khoá do hoạt động bất thường. Thử lại sau.", "locked": true }
```

⚠️ Giả định: hệ thống không trả JWT/session cho tài khoản web app mẫu ở bước này — mục tiêu của web app mẫu là sinh dữ liệu đăng nhập cho detection engine, không phải xây một hệ thống auth đầy đủ. Nếu tài liệu gốc yêu cầu khác, cập nhật lại.

⚠️ **Đánh đổi độ trễ (MR16):** để biết được có cần trả `step_up_required`/`locked` hay không, một lần thử ĐÚNG mật khẩu giờ phải CHỜ đồng bộ kết quả chấm điểm (`await`) thay vì chạy nền như trước (nhiệm vụ 5.2 nguyên bản) — đo được thêm ~140ms ở trung vị so với đường sai mật khẩu (không đổi, vẫn chạy nền). Chi tiết: [`automated-response.md`](automated-response.md).

### `POST /login/verify-otp` (MR16)

Request:
```json
{ "challenge_id": 42, "code": "042857" }
```

Response 200 (đúng mã):
```json
{ "success": true, "message": "Login successful", "step_up_required": false, "challenge_id": null, "demo_otp_code": null, "locked": false }
```

Response 200, thất bại (SAI mã **hoặc** `challenge_id` không tồn tại **hoặc** đã hết hạn (5 phút) **hoặc** đã xác thực thành công trước đó **hoặc** đã sai quá 5 lần — dùng chung MỘT thông báo cho mọi lý do, cùng triết lý mục 3 ở trên):
```json
{ "success": false, "message": "Mã xác thực không đúng hoặc đã hết hạn.", "step_up_required": false, "challenge_id": null, "demo_otp_code": null, "locked": false }
```

### `GET /blocklist` / `DELETE /blocklist/{id}` (MR16, admin — JWT bắt buộc)

`GET /blocklist?active_only=true&page=1&page_size=20` → `{"items": [{"id", "kind", "value", "reason", "added_by", "expires_at", "created_at"}], "total", "page", "page_size"}` — `active_only=false` để xem cả mục đã hết hạn (lịch sử).

`DELETE /blocklist/{id}` → `204 No Content` khi thành công, `404` nếu không thấy — ghi một hàng `audit_log` (`action="unlock"`, `detail` giữ lại toàn bộ thông tin mục chặn) TRƯỚC KHI xoá hàng, rồi vô hiệu cache blocklist (15s TTL) ngay lập tức thay vì đợi hết hạn.

## 4. Quy ước đặt tên DB (mục 7 tài liệu chính — áp dụng tạm, chờ đối chiếu)

- Tên bảng: số nhiều, `snake_case` — `users`, `login_events`, `user_baseline`, `known_devices`, `known_locations`, `alerts`.
- Khóa chính: luôn là cột `id` (integer, auto-increment), trừ `user_baseline` dùng `user_id` làm khóa chính (quan hệ 1-1 với `users`).
- Khóa ngoại: `<tên_bảng_số_ít>_id` — ví dụ `user_id`, `login_event_id`.
- Timestamp: luôn `_at` — `created_at`, `updated_at`, `first_seen_at`, `last_seen_at`, `resolved_at`.
- Boolean: tiền tố ngầm định qua tên — `success`, `is_synthetic`, `resolved`.

Chi tiết từng bảng, xem [`docs/db-schema.md`](db-schema.md).

## 5. Ngưỡng phát hiện đã có sẵn trong checklist (dùng trực tiếp, không phải giả định)

Lấy nguyên văn từ `Ke_hoach_trien_khai_chi_tiet_va_checklist.docx`:

- Risk score: **< 40 bình thường**, **40–70 trung bình**, **> 70 cao** (mục 4.2).
- Trọng số gợi ý: lệch giờ đăng nhập +20, IP lạ +30, fail liên tiếp +40, đăng nhập thành công ngay sau chuỗi fail +50 (mục 4.2 — sẽ tinh chỉnh ở Tuần 4).
- Impossible travel: ngưỡng tốc độ **~900 km/h** (mục 3.3).
- Chế độ học (learning mode): áp dụng khi user có **< 10 lần đăng nhập** hoặc **chưa đủ 7 ngày** kể từ lần đăng nhập đầu tiên (mục 4.1).
- Tỷ lệ dữ liệu giả lập: **80–90% bình thường**, còn lại là ca bất thường có nhãn (mục 3.5 / mục 11).

## 6. ⚠️ Giả định cần đối chiếu với tài liệu "Kế hoạch đồ án" khi có

Các con số dưới đây **không** có sẵn trong bản checklist, tôi tự chọn hợp lý —
cập nhật ngay khi có tài liệu gốc (mục 4, mục 9):

- Ngưỡng brute force: **5 lần fail liên tiếp trong 5 phút, cùng một tài khoản**.
- Ngưỡng credential stuffing: **10 lần fail trong 5 phút, cùng một IP, ≥ 5 username khác nhau**.
- Cửa sổ sliding window Redis: TTL 5 phút cho cả 2 key `fail:{user_id}` và `fail_ip:{ip}`.
- JWT admin hết hạn sau **60 phút**.
