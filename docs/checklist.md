# Checklist tổng hợp toàn dự án

Chép từ phụ lục checklist gốc (`Ke_hoach_trien_khai_chi_tiet_va_checklist.docx`, mục 11).
Tick `[x]` khi nhiệm vụ đã qua đủ các mục kiểm tra — không tick khi chỉ mới viết code xong.

## Tuần 1 — Kiến trúc & khung project

- [x] 1.1 Thống nhất kiến trúc & API contract — Cả hai — xem [`docs/api-contract.md`](api-contract.md)
- [x] 1.2 Thiết kế schema cơ sở dữ liệu — A — xem [`docs/db-schema.md`](db-schema.md)
- [x] 1.3 Khởi tạo khung backend (FastAPI) — A
- [x] 1.4 Khởi tạo khung frontend (React) — B

## Tuần 2 — Đăng nhập & log cơ bản

- [x] 2.1 API đăng nhập cơ bản + ghi log — A — `POST /login`, xem [`backend/app/routers/auth.py`](../backend/app/routers/auth.py)
- [x] 2.2 Giao diện đăng nhập web app mẫu — B — [`frontend/src/pages/LoginPage.jsx`](../frontend/src/pages/LoginPage.jsx)
- [x] 2.3 Sinh dữ liệu đăng nhập lịch sử giả lập ban đầu — Cả hai — [`backend/scripts/generate_historical_data.py`](../backend/scripts/generate_historical_data.py)

## Tuần 3 — Rule-based tầng 1

- [x] 3.1 Tích hợp MaxMind GeoLite2 — A — [`backend/app/detection/geoip.py`](../backend/app/detection/geoip.py), dùng dữ liệu GeoLite2-City thật (xem [`docs/geoip-setup.md`](geoip-setup.md))
- [x] 3.2 Đếm login fail bằng Redis (sliding window) — A — [`backend/app/detection/rate_counter.py`](../backend/app/detection/rate_counter.py)
- [x] 3.3 Viết rule-based detection tầng 1 — A — [`backend/app/detection/rules.py`](../backend/app/detection/rules.py)
- [x] 3.4 Dựng khung dashboard 4 khu vực — B — [`frontend/src/pages/DashboardPage.jsx`](../frontend/src/pages/DashboardPage.jsx)
- [x] 3.5 Mở rộng dữ liệu lịch sử giả lập cho baseline — B — [`backend/scripts/generate_labeled_anomalies.py`](../backend/scripts/generate_labeled_anomalies.py)

## Tuần 4 — Behavioral scoring tầng 2

- [x] 4.1 Xây baseline hành vi user — A — [`backend/app/detection/baseline.py`](../backend/app/detection/baseline.py)
- [x] 4.2 Cài đặt chấm điểm risk score tầng 2 — A — [`backend/app/detection/scoring.py`](../backend/app/detection/scoring.py)
- [x] 4.3 Bảng log & biểu đồ tĩnh trên dashboard — B — `GET /login-events`, `GET /alerts` + [`frontend/src/components/LogTablePanel.jsx`](../frontend/src/components/LogTablePanel.jsx), [`RiskChartPanel.jsx`](../frontend/src/components/RiskChartPanel.jsx)

## Tuần 5 — Bảo mật & real-time

- [x] 5.1 Xác thực JWT cho admin & WebSocket — A — [`backend/app/dependencies.py`](../backend/app/dependencies.py), [`backend/app/routers/admin.py`](../backend/app/routers/admin.py)
- [x] 5.2 Tối ưu tốc độ detection engine — A — [`backend/app/detection/pipeline.py`](../backend/app/detection/pipeline.py) (BackgroundTasks), xem [`docs/performance.md`](performance.md)
- [x] 5.3 Kết nối WebSocket thật & bản đồ real-time — B — [`frontend/src/services/useAlertsSocket.js`](../frontend/src/services/useAlertsSocket.js)

## Tuần 6 — Kịch bản tấn công & kiểm thử end-to-end

- [x] 6.1 Viết 4 script giả lập tấn công — B — [`attack-sim/`](../attack-sim/)
- [x] 6.2 Kiểm thử end-to-end toàn luồng — Cả hai — [`docs/e2e-test-report.md`](e2e-test-report.md)

## Tuần 7 — ML mở rộng & đánh giá hệ thống

- [ ] 7.1 Thử nghiệm mô hình ML tầng 3 (tuỳ chọn) — A
- [ ] 7.2 Hoàn thiện giao diện & đo precision/recall — B

## Tuần 8 — Báo cáo, slide & diễn tập demo

- [ ] 8.1 Viết báo cáo, chuẩn bị slide, diễn tập demo — Cả hai
