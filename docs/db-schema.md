# Schema cơ sở dữ liệu (nhiệm vụ 1.2 + bảng `admins` Tuần 5 + 5 bảng MR12 + 1 bảng MR15 + 1 bảng MR16)

6 bảng gốc PostgreSQL (nhiệm vụ 1.2) + bảng `admins` (nhiệm vụ 5.1) + 5 bảng MR12 (`campaigns`, `blocklist`,
`response_actions`, `audit_log`, `model_registry`) + `user_risk_profiles` (MR15) + `otp_challenges` (MR16) và cột mới
trên `login_events`/`alerts`, định nghĩa bằng SQLAlchemy ở [`backend/app/models.py`](../backend/app/models.py), tạo
bằng Alembic migration trong [`backend/alembic/versions/`](../backend/alembic/versions/) (`..._initial_schema.py` cho
6 bảng gốc, `..._add_admins_table.py` cho Tuần 5, `..._add_ml_anomaly_score...py` cho `ml_anomaly_score`,
`..._mr12_realtime_integration...py` cho phần MR12 — xem [`realtime-integration.md`](realtime-integration.md);
`..._mr16_otp_challenges.py` cho `otp_challenges`).

## users

Tài khoản của **web app mẫu** — không phải admin.

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| username | VARCHAR(64) | UNIQUE, indexed |
| password_hash | VARCHAR(255) | bcrypt, không bao giờ lưu plain text |
| email | VARCHAR(255) | nullable |
| created_at | TIMESTAMPTZ | default now() |
| importance | FLOAT | default 1.0 (MR13) — hệ số nhân trong công thức ưu tiên cảnh báo (`alert_intelligence.priority_score`); demo không có khái niệm "tài khoản quan trọng" thật nên mặc định bằng nhau, placeholder cho hệ thống thật |

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
| hybrid_action | VARCHAR(16) | nullable — `allow`\|`alert`\|`step_up`\|`lock` của hybrid risk engine; `step_up`/`lock` được THỰC THI thật từ MR16 (xem `response_actions`, `otp_challenges`) |
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
| attack_family | VARCHAR(64) | nullable — GỢI Ý (MR13, `alert_intelligence.suggest_attack_family`): 1 trong 4 `CATEGORIES` của rule engine (ưu tiên nếu có luật/danh tiếng khớp) hoặc nhãn thành phần `HybridMinTail` (chỉ khi không luật nào khớp); KHÔNG PHẢI khẳng định |
| attack_family_confidence | FLOAT | nullable (MR13) — độ tin cậy [0,1] của `attack_family`, = trọng số của bằng chứng dẫn đầu |
| explanation | JSON | nullable (MR12) — `{"contributions": [...], "action": ...}` từ `RiskResult`; `action` (MR13) là mức đề xuất TỆ NHẤT của cả đợt tính đến lần gộp gần nhất, dùng để phát hiện leo thang khi chống trùng lặp |
| campaign_id | INTEGER FK → campaigns.id | nullable — dự trữ cho MR14 (tương quan chiến dịch), chưa có gì gán |
| status | VARCHAR(16) | default `'open'` (MR12) — `open`\|`acknowledged`\|`resolved`\|`false_positive`; chi tiết hơn `resolved`, TỒN TẠI SONG SONG (tương thích ngược) |
| feedback | TEXT | nullable — ghi chú ngắn của quản trị viên (MR15, `POST /alerts/{id}/feedback`); `status` chuyển `resolved`\|`false_positive` cùng lúc, nguồn cho `user_risk_profiles` |
| occurrence_count | INTEGER | default 1 (MR13) — chống trùng lặp: số lần CÙNG (tài khoản hoặc IP) + `attack_family` khớp trong `DEDUP_WINDOW` (15 phút) đã GỘP vào hàng này thay vì tạo hàng mới |
| last_seen_at | TIMESTAMPTZ | nullable (MR13) — lần khớp GẦN NHẤT của đợt đã gộp; `created_at` giữ nguyên lần ĐẦU TIÊN |
| priority_score | FLOAT | nullable (MR13) — `novelty_level × attack_family_confidence × users.importance`; sắp xếp mặc định của `GET /alerts` (NULLS LAST), KHÔNG thay `severity`/`risk_score` |
| resolved | BOOLEAN | default false |
| resolved_at | TIMESTAMPTZ | nullable |
| created_at | TIMESTAMPTZ | indexed — mốc TẠO đầu tiên; `GET /alerts` mặc định sắp theo `priority_score`, `sort=recent` sắp theo cột này |

Index bổ sung MR13: `(user_id, attack_family, status)` — dùng cho tra cứu chống trùng lặp trước khi ghi mỗi lần chấm.

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

## campaigns (bổ sung MR12, gán tự động từ MR14)

Gom nhiều `Alert` được coi là CÙNG một đợt tấn công CỦA NHIỀU TÀI KHOẢN dùng chung hạ tầng (IP hoặc ASN, trong 24 giờ
— `app/detection/campaign_correlation.py`) — khác chống trùng lặp của MR13 (`alerts.occurrence_count`, chỉ gộp CÙNG
MỘT tài khoản/IP lặp lại). `app/detection/pipeline.py` gán `alerts.campaign_id` NGAY khi alert mới khớp hạ tầng với
một alert khác (tài khoản khác) trong cửa sổ — GIA TĂNG (mở rộng chiến dịch đang có), KHÔNG GỘP LẠI hai chiến dịch đã
tách nếu có alert bắc cầu đến sau (xem giới hạn ở `docs/campaign-correlation.md`).

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| label | VARCHAR(128) | tự sinh — `"Chiến dịch qua ASN <n>"` (ưu tiên) hoặc `"Chiến dịch qua IP <ip>"` khi không biết ASN |
| attack_family | VARCHAR(64) | nullable — lấy từ `attack_family` (MR13) của alert ĐẦU TIÊN có giá trị này gia nhập chiến dịch, không tính lại khi có thêm alert |
| status | VARCHAR(16) | default `'open'` — `open`\|`closed` (đóng chiến dịch: thủ công, chưa có router quản trị) |
| alert_count | INTEGER | default 0 |
| first_seen_at / last_seen_at | TIMESTAMPTZ | |
| created_at | TIMESTAMPTZ | default now() |

## blocklist (bổ sung MR12)

Bản lưu DB của `app.detection.engine.intel.Blocklist` (MR9, trước đó chỉ có trong bộ nhớ cho replay/test). Luồng thật
nạp lại bảng này thành một `Blocklist` trong bộ nhớ mỗi lần chấm điểm (cache TTL 15 giây,
`app/detection/rule_engine_runtime.refresh_blocklist`) vì tra cứu cần nhanh, không phải truy vấn SQL cho mỗi lần đăng
nhập. Khớp blocklist tạo cảnh báo/ghi đè điểm rủi ro (`blocklist_hit`, hành động `lock`). Từ MR16: `POST /login`
(`app/routers/auth.py`) từ chối NGAY (HTTP 423) một mục còn hiệu lực ở đây, TRƯỚC CẢ khi xác thực mật khẩu — hàng có
thể do quản trị viên tự thêm (`added_by` khác `"system"`) hoặc do pipeline TỰ ĐỘNG thêm khi hành động là `lock`
(`added_by="system"`, luôn CÓ `expires_at` — 30 phút, `app/detection/response_execution.LOCK_TTL`). Quản trị viên xem/mở
khoá qua `GET /blocklist` + `DELETE /blocklist/{id}` (`app/routers/blocklist.py`).

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
'recommended'` khi chỉ GHI NHẬN đề xuất (dùng khi đã có hàng CÙNG alert từ trước, chống trùng lặp không leo thang thêm,
MR13). Từ MR16: `status = 'executed'` khi đã THỰC THI thật — `lock` → tạo/gia hạn `blocklist` (`app/detection/pipeline.py`),
`step_up` → tạo `otp_challenges` (`app/routers/auth.py`) — kèm `executed_at`.

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

Nhật ký thao tác chung. `actor='system'` khi hệ thống tự ghi: tạo `response_actions` (`action='recommend_step_up'`\|
`'recommend_lock'`), MR16 thực thi thật (`'execute_lock'`\|`'execute_step_up'`), MR16 từ chối ở precheck
(`'reject_blocked_login'`, `target_type='blocklist'`, không có `login_event` vì bị chặn TRƯỚC khi ghi). `actor=`username
quản trị viên khi thao tác tay: phản hồi alert (MR15, `'feedback_correct'`\|`'feedback_false_positive'`), mở khoá
(MR16, `'unlock'`, `target_type='blocklist'`, `detail` giữ lại toàn bộ thông tin mục chặn TRƯỚC KHI xoá hàng).

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

## user_risk_profiles (bổ sung MR15)

Ngưỡng THÍCH NGHI theo TỪNG tài khoản ("vòng phản hồi") — suy ra ĐỊNH KỲ (không phải ngay lúc admin bấm phản hồi, xem
`backend/scripts/retrain_from_feedback.py`) từ `alerts.status`/`feedback`. Tài khoản chưa đủ phản hồi (`feedback_count`
< 3, `app/detection/adaptive_threshold.MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD`) KHÔNG có hàng ở đây — tự động dùng ngưỡng
NHÓM (mặc định toàn hệ thống). CHỈ NỚI LỎNG (`threshold_delta` luôn ≥ 0) — không bao giờ tự động thắt chặt xuống dưới
mặc định nhóm dù phản hồi toàn "đúng".

| Cột | Kiểu | Ghi chú |
|---|---|---|
| user_id | INTEGER PK, FK → users.id | |
| threshold_delta | FLOAT | default 0.0 — cộng THÊM vào cả ba mốc `alert_at`/`step_up_at`/`lock_at` khi chấm điểm cho tài khoản này (`app/detection/adaptive_threshold.apply_delta`) |
| feedback_count | INTEGER | default 0 — tổng số alert đã có phản hồi (`resolved` + `false_positive`) |
| false_positive_count | INTEGER | default 0 — trong đó, số phản hồi "báo nhầm" |
| updated_at | TIMESTAMPTZ | tự cập nhật (`onupdate=func.now()`) |

## otp_challenges (bổ sung MR16)

Bước xác thực thêm khi hành động là `step_up` (mật khẩu ĐÃ đúng, `app/routers/auth.py`). ⚠️ OTP GIẢ LẬP — không có nhà
cung cấp SMS/email nào tích hợp, mã trả THẲNG trong response `POST /login` (`demo_otp_code`), luôn ghi rõ đây là mô
phỏng. Xác thực qua `POST /login/verify-otp` — thông báo lỗi GIỐNG NHAU cho MỌI lý do thất bại (không tồn tại, hết
hạn, quá số lần thử, sai mã, đã dùng), cùng triết lý "sai mật khẩu = tài khoản không tồn tại" đã có
(`docs/api-contract.md` mục 3).

| Cột | Kiểu | Ghi chú |
|---|---|---|
| id | INTEGER PK | |
| login_event_id | INTEGER FK → login_events.id | không null, indexed — lần đăng nhập đã sinh ra thử thách này |
| user_id | INTEGER FK → users.id | không null |
| code_hash | VARCHAR(255) | bcrypt (`app.security.hash_password` — tái dùng, không viết hàm băm riêng cho mã 6 số) |
| expires_at | TIMESTAMPTZ | không null — `OTP_TTL` = 5 phút kể từ lúc tạo |
| verified_at | TIMESTAMPTZ | nullable — đã xác thực thành công; có giá trị rồi thì mọi lần thử SAU đều bị từ chối (không cho dùng lại) |
| attempts | INTEGER | default 0 — mỗi lần xác thực SAI (kể cả sau khi đã hết hạn) tăng 1; ≥ `OTP_MAX_ATTEMPTS` (5) thì từ chối luôn cả khi gửi đúng mã |
| created_at | TIMESTAMPTZ | default now() |

## Kiểm tra sau khi hoàn thành (checklist gốc mục 1.2)

- [x] Cả 6 bảng đúng tên, đúng kiểu dữ liệu — xem migration.
- [x] Khoá ngoại `login_events.user_id → users.id` hoạt động đúng — đã test insert `user_id` không tồn tại → bị chặn (`UniqueViolation`/`ForeignKeyViolation` xác nhận qua psql), xem [`README.md`](../README.md).
- [x] Index xác nhận bằng `\di` — xác nhận khi chạy migration thật (Tuần 1).
