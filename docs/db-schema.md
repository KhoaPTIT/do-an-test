# Schema cơ sở dữ liệu (nhiệm vụ 1.2 + bảng `admins` bổ sung Tuần 5)

6 bảng gốc PostgreSQL (nhiệm vụ 1.2) + bảng `admins` (nhiệm vụ 5.1), định
nghĩa bằng SQLAlchemy ở [`backend/app/models.py`](../backend/app/models.py),
tạo bằng Alembic migration trong [`backend/alembic/versions/`](../backend/alembic/versions/)
(`..._initial_schema.py` cho 6 bảng gốc, `..._add_admins_table.py` cho Tuần 5).

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
| alert_type | VARCHAR(32) | `brute_force` \| `credential_stuffing` \| `impossible_travel` \| `high_risk_score` |
| severity | VARCHAR(16) | `low` \| `medium` \| `high` — ánh xạ từ risk_score theo mục 4.2 |
| risk_score | INTEGER | |
| message | TEXT | mô tả người đọc được, hiển thị trực tiếp trên dashboard |
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

## Kiểm tra sau khi hoàn thành (checklist gốc mục 1.2)

- [x] Cả 6 bảng đúng tên, đúng kiểu dữ liệu — xem migration.
- [x] Khoá ngoại `login_events.user_id → users.id` hoạt động đúng — đã test insert `user_id` không tồn tại → bị chặn (`UniqueViolation`/`ForeignKeyViolation` xác nhận qua psql), xem [`README.md`](../README.md).
- [x] Index xác nhận bằng `\di` — xác nhận khi chạy migration thật (Tuần 1).
