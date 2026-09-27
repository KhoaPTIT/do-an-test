# Schema cơ sở dữ liệu (nhiệm vụ 1.2 + bảng `admins` Tuần 5 + 5 bảng MR12)

6 bảng gốc PostgreSQL (nhiệm vụ 1.2) + bảng `admins` (nhiệm vụ 5.1) + 5 bảng MR12 (`campaigns`, `blocklist`,
`response_actions`, `audit_log`, `model_registry`) và cột mới trên `login_events`/`alerts`, định nghĩa bằng SQLAlchemy ở
[`backend/app/models.py`](../backend/app/models.py), tạo bằng Alembic migration trong
[`backend/alembic/versions/`](../backend/alembic/versions/) (`..._initial_schema.py` cho 6 bảng gốc,
`..._add_admins_table.py` cho Tuần 5, `..._add_ml_anomaly_score...py` cho `ml_anomaly_score`,
`..._mr12_realtime_integration...py` cho phần MR12 — xem [`realtime-integration.md`](realtime-integration.md)).

## users

Tài khoản của **web app mẫu** — không phải admin.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| username | VARCHAR(64) | UNIQUE, indexed |
| password_hash | VARCHAR(255) | bcrypt, không bao giờ lưu plain text |
| email | VARCHAR(255) | nullable |
| created_at | TIMESTAMPTZ | default now() |

## login_events

Bảng quan trọng nhất — mọi lần thử đăng nhập, thành công lẫn thất bại.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER FK → users.id | **nullable** — NULL khi `attempted_username` không tồn tại (vẫn phải log để phát hiện dò tài khoản) |
| attempted_username | VARCHAR(64) | username thực sự gửi lên, kể cả khi không tồn tại |
| success | BOOLEAN | |
| ip_address | VARCHAR(45) | đủ chỗ cho IPv6 |
| user_agent | TEXT | nullable |
| device_fingerprint | VARCHAR(128) | nullable — tính ở Tuần 4 |
| country | VARCHAR(2) | ISO country code, nullable — NULL khi GeoIP lookup thất bại |
| city | VARCHAR(128) | nullable |
| latitude / longitude | FLOAT | nullable |
| risk_score | INTEGER | nullable — điền bởi detection engine Tuần 4 |
| ml_anomaly_score | FLOAT | nullable — điền bởi ML tầng 3 Tuần 7, CHẠY SONG SONG risk_score, không thay thế |
| asn | INTEGER | nullable, indexed — tra bằng GeoLite2-ASN (MR12), NULL khi IP riêng/không có trong CSDL |
| os_name / browser_name | VARCHAR(64) | nullable — parse User-Agent (MR12, `app/utils/device.py`), cùng bộ giá trị RBA |
| device_type | VARCHAR(16) | nullable — `mobile`\|`desktop`\|`tablet`\|`bot`\|`unknown` (MR12) |
| hybrid_risk_score | INTEGER | nullable, 0–100 — điểm hybrid risk engine (MR11), CHẠY SONG SONG risk_score/ml_anomaly_score |
| hybrid_action | VARCHAR(16) | nullable — `allow`\|`alert`\|`step_up`\|`lock`, ĐỀ XUẤT của hybrid risk engine (chưa tự thực thi, xem `response_actions`) |
| is_synthetic | BOOLEAN | default false — phân biệt dữ liệu giả lập (nhiệm vụ 2.3) |
| created_at | TIMESTAMPTZ | default now() |

Index: `(user_id, created_at)` kết hợp, và riêng `ip_address` — đúng yêu cầu mục 1.2.

## user_baseline

Hồ sơ hành vi "bình thường" theo user (Tuần 4). Quan hệ 1-1 với `users`.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| user_id | INTEGER PK, FK → users.id | |
| avg_login_hour | FLOAT | giờ đăng nhập trung bình (0–23.99), nullable đến khi đủ dữ liệu |
| stddev_login_hour | FLOAT | độ lệch chuẩn |
| successful_login_count | INTEGER | default 0 — dùng để xác định còn ở "chế độ học" không (< 10) |
| first_login_at | TIMESTAMPTZ | nullable — dùng để xác định đủ 7 ngày chưa |
| updated_at | TIMESTAMPTZ | auto update |

## known_devices

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER FK → users.id | indexed |
| device_fingerprint | VARCHAR(128) | |
| user_agent | TEXT | nullable |
| first_seen_at / last_seen_at | TIMESTAMPTZ | |

## known_locations

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER FK → users.id | indexed |
| country | VARCHAR(2) | nullable |
| city | VARCHAR(128) | nullable |
| first_seen_at / last_seen_at | TIMESTAMPTZ | |

## alerts

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| login_event_id | INTEGER FK → login_events.id | indexed |
| user_id | INTEGER FK → users.id | nullable (username không tồn tại thì không có user) |
| alert_type | VARCHAR(32) | `brute_force` \| `credential_stuffing` \| `impossible_travel` \| `high_risk_score` \| `ml_anomaly` \| `hybrid_risk` (MR12) |
| severity | VARCHAR(16) | `low` \| `medium` \| `high` — ánh xạ từ risk_score theo mục 4.2 |
| risk_score | INTEGER | |
| message | TEXT | mô tả người đọc được, hiển thị trực tiếp trên dashboard |
| rule_id | VARCHAR(64) | nullable (MR12) — mã luật (`app/detection/engine/registry.py`) hoặc luật ghi đè đã sinh ra cảnh báo; NULL nếu chỉ do ML/tầng 1-2 cũ |
| attack_family | VARCHAR(64) | nullable (MR12) — dự trữ cho MR13 (gán họ tấn công), chưa có gì điền |
| explanation | JSON | nullable (MR12) — `{"contributions": [{"source", "label", "weight", "group"}, ...]}` từ `RiskResult` của hybrid risk engine |
| campaign_id | INTEGER FK → campaigns.id | nullable (MR12) — dự trữ cho MR13, chưa có gì gán |
| status | VARCHAR(16) | default `'open'` (MR12) — `open`\|`acknowledged`\|`resolved`\|`false_positive`; chi tiết hơn `resolved`, TỒN TẠI SONG SONG (tương thích ngược) |
| feedback | TEXT | nullable (MR12) — phản hồi ngắn của quản trị viên, chưa có router nào ghi |
| resolved | BOOLEAN | default false |
| resolved_at | TIMESTAMPTZ | nullable |
| created_at | TIMESTAMPTZ | indexed — dùng để sort mới nhất trước |

## admins (bổ sung Tuần 5 — nhiệm vụ 5.1)

Tài khoản quản trị. **Tách biệt hoàn toàn** khỏi `users` — không có khóa
ngoại nào liên kết 2 bảng này. Không nằm trong 6 bảng gốc mục 1.2 vì JWT
admin chỉ phát sinh nhu cầu từ Tuần 5.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| username | VARCHAR(64) | UNIQUE, indexed |
| password_hash | VARCHAR(255) | bcrypt |
| created_at | TIMESTAMPTZ | default now() |

Tạo tài khoản admin qua script (chưa có UI): `python -m scripts.create_admin --username admin --password "..."`.

## campaigns (bổ sung MR12 — dự trữ cho MR13)

Gom nhiều `Alert` được coi là CÙNG một đợt tấn công. MR12 chỉ tạo bảng và cột `alerts.campaign_id`; MR13 mới quyết định
gán alert nào vào campaign nào (theo IP/ASN/khoảng thời gian gần nhau) — bảng hiện CHƯA có hàng nào.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| label | VARCHAR(128) | |
| attack_family | VARCHAR(64) | nullable |
| status | VARCHAR(16) | default `'open'` — `open`\|`closed` |
| alert_count | INTEGER | default 0 |
| first_seen_at / last_seen_at | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | default now() |

## blocklist (bổ sung MR12)

Bản lưu DB của `app.detection.engine.intel.Blocklist` (MR9, trước đó chỉ có trong bộ nhớ cho replay/test). Luồng thật
nạp lại bảng này thành một `Blocklist` trong bộ nhớ mỗi lần chấm điểm (cache TTL 15 giây,
`app/detection/rule_engine_runtime.refresh_blocklist`) vì tra cứu cần nhanh, không phải truy vấn SQL cho mỗi lần đăng
nhập. Khớp blocklist tạo cảnh báo/ghi đè điểm rủi ro (`blocklist_hit`, hành động `lock`) — **chưa có hành động chặn
THẬT** (từ chối đăng nhập), việc đó là của MR16.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| kind | VARCHAR(16) | `ip`\|`cidr`\|`asn`\|`username` |
| value | VARCHAR(128) | đã chuẩn hoá (`Blocklist._normalize`) |
| reason | TEXT | nullable |
| added_by | VARCHAR(64) | default `'admin'` |
| expires_at | TIMESTAMPTZ | nullable — NULL = vĩnh viễn; so với thời gian của SỰ KIỆN, không phải giờ hệ thống |
| created_at | TIMESTAMPTZ | default now() |

UNIQUE (kind, value).

## response_actions (bổ sung MR12)

Hành động ứng phó mà hybrid risk engine ĐỀ XUẤT khi điểm gộp đạt `step_up`/`lock`, hoặc do luật ghi đè. `status =
'recommended'` nghĩa là mới chỉ GHI NHẬN đề xuất — chưa có gì thực thi thật (không có luồng MFA/khoá tài khoản ở web
app mẫu); thực thi thật là việc của MR16.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| login_event_id | INTEGER FK → login_events.id | nullable, indexed |
| alert_id | INTEGER FK → alerts.id | nullable |
| user_id | INTEGER FK → users.id | nullable |
| action | VARCHAR(16) | `step_up`\|`lock` |
| status | VARCHAR(16) | default `'recommended'` — `recommended`\|`executed`\|`reverted` |
| reason | TEXT | nullable |
| created_by | VARCHAR(64) | default `'system'` |
| created_at | TIMESTAMPTZ | default now() |
| executed_at | TIMESTAMPTZ | nullable |

## audit_log (bổ sung MR12)

Nhật ký thao tác chung. Hiện chỉ được hệ thống tự ghi khi tạo `response_actions` (`actor='system'`, `action=
'recommend_step_up'`/`'recommend_lock'`); quản trị viên thao tác tay (duyệt cảnh báo, thêm blocklist...) sẽ ghi thêm khi
các router đó được xây (MR13+).

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| actor | VARCHAR(64) | `"system"` hoặc username quản trị viên |
| action | VARCHAR(64) | |
| target_type | VARCHAR(32) | nullable — `"login_event"`\|`"alert"`\|`"blocklist"`\|... |
| target_id | INTEGER | nullable |
| detail | JSON | nullable |
| created_at | TIMESTAMPTZ | indexed |

## model_registry (bổ sung MR12)

Phiên bản mô hình hybrid đã/đang nạp ("nạp model theo phiên bản, fallback an toàn"). Tự đăng ký lúc ứng dụng khởi động
nếu artifact có sẵn trên đĩa và chưa có hàng nào (`app/detection/model_registry.ensure_registered`); nạp lỗi (thiếu
file, `feature_signature` lệch) thì `app/detection/hybrid_runtime.py` bỏ qua thành phần ML, không sập ứng dụng.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| name | VARCHAR(64) | `"hybrid_cp2"` |
| version | VARCHAR(64) | `"cp2"` |
| artifact_path | TEXT | đường dẫn `.joblib` |
| profile_path | TEXT | nullable — hồ sơ hiệu chỉnh (`app/detection/hybrid/profiles/*.json`, MR11) |
| feature_signature | VARCHAR(32) | nullable — `ml.rba.features.feature_signature()` lúc train, đối chiếu để phát hiện lệch phiên bản đặc trưng |
| metrics | JSON | nullable |
| is_active | BOOLEAN | default false |
| trained_at | TIMESTAMPTZ | nullable |
| created_at | TIMESTAMPTZ | default now() |

UNIQUE (name, version).

## Kiểm tra sau khi hoàn thành (checklist gốc mục 1.2)

- [x] Cả 6 bảng đúng tên, đúng kiểu dữ liệu — xem migration.
- [x] Khoá ngoại `login_events.user_id → users.id` hoạt động đúng — đã test insert `user_id` không tồn tại → bị chặn (`UniqueViolation`/`ForeignKeyViolation` xác nhận qua psql), xem [`README.md`](../README.md).
- [x] Index xác nhận bằng `\di` — xác nhận khi chạy migration thật (Tuần 1).
