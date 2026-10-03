# Hướng dẫn khởi động dự án

Máy đã cài sẵn mọi thứ (Docker, venv, node_modules). Đây là các bước để
**chạy lại từ đầu mỗi khi mở máy/mở lại dự án**. Mở 2 cửa sổ terminal
(PowerShell hoặc Git Bash) — 1 cho backend, 1 cho frontend.

## Bước 1 — Bật Docker Desktop

Mở app **Docker Desktop**, đợi tới khi icon cá voi hết loading (khoảng
30s-1 phút). Sau đó ở terminal bất kỳ:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong
docker compose up -d
docker ps
```

Phải thấy `lad_postgres` và `lad_redis` ở trạng thái `healthy`. Nếu lệnh
`docker compose` báo lỗi kết nối → Docker Desktop chưa khởi động xong, đợi
thêm rồi thử lại.

## Bước 2 — Chạy backend (terminal 1)

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```

Kiểm tra: mở `http://localhost:8000/health` phải thấy
`{"status":"ok","database":"connected"}`. Tài liệu API tự sinh ở
`http://localhost:8000/docs`.

> Terminal này phải để chạy liên tục (không đóng) trong lúc dùng hệ thống.

## Bước 3 — Chạy frontend (terminal 2, cửa sổ khác)

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\frontend
npm run dev
```

Mở `http://localhost:5173` trên trình duyệt.

## Bước 4 — Đăng nhập thử

Web app mẫu ở `http://localhost:5173/login`. Tài khoản có sẵn (do script
sinh dữ liệu tạo — xem Bước 5):

- Username: `user001` đến `user030` (dữ liệu demo dashboard, Tuần 2-3)
- Password: `Demo@12345` (giống nhau cho tất cả)

> Dữ liệu huấn luyện model AI (Phase 4.1) KHÔNG nằm trong DB — sinh ra file CSV riêng ở Bước 5b.

Đăng nhập đúng sẽ chuyển sang `/dashboard` của **web app mẫu** — trang này
không phải dashboard giám sát.

## Bước 4b — Vào Dashboard giám sát (cần tài khoản admin riêng)

`/dashboard` (giám sát, real-time) là khu vực quản trị, yêu cầu đăng nhập bằng
tài khoản admin. Chỉ có MỘT trang đăng nhập chung `http://localhost:5173/login`
— hệ thống tự phân quyền theo tài khoản (user web app mẫu hay admin). Nếu chưa
có tài khoản admin, tạo bằng:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
python -m scripts.create_admin --username admin --password "MatKhauManh123!"
```

Đăng nhập ở `/login` bằng tài khoản vừa tạo, hệ thống tự chuyển sang
`/dashboard` — góc trên bên phải tiêu đề hiện `● real-time` nghĩa là
WebSocket đã kết nối, cảnh báo mới sẽ hiện popup + cập nhật bảng/biểu đồ
ngay lập tức, không cần reload trang.

> Từ giai đoạn mở rộng AI (MR14-17), khu quản trị còn có: **Campaigns** (chiến
> dịch tấn công gom nhiều tài khoản/alert theo hạ tầng chung), **Rules** (bật/tắt
> và chỉnh tham số 19 luật rule engine v2 mà không cần sửa code, xem
> [`docs/dashboard-v2.md`](dashboard-v2.md)), **Model Health** (drift PSI của
> mô hình so với dữ liệu train), và trang hồ sơ rủi ro theo từng user.

## Bước 5 — (Tuỳ chọn) Sinh lại dữ liệu mẫu

Chỉ cần chạy lại khi muốn dữ liệu mới hoặc lần đầu setup máy mới. Dữ liệu
hiện tại (25 user, 924 bản ghi có nhãn) đã có sẵn trong Postgres, **không
cần chạy lại** trừ khi bạn muốn.

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
set PYTHONIOENCODING=utf-8
python -m scripts.generate_labeled_anomalies --reset
```

## Bước 5b — Train model AI (Isolation Forest, Phase 4.1)

Artifact không commit lên git (`backend/ml/artifacts/anomaly_iforest/`). Máy mới chạy MỘT lệnh (~1 phút, không tải gì
từ ngoài — dataset TỔNG HỢP sinh tất định từ mã trong repo):

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
set PYTHONIOENCODING=utf-8
python -m ml.pipeline      # dataset -> đặc trưng -> train -> đánh giá trên test -> artifacts/ml/*.json
```

Rồi khởi động (lại) backend — lúc khởi động nó tự nạp artifact (log: `đã nạp model bất thường isolation_forest ...`).
Kiểm tra trên trang **Sức khoẻ mô hình** của dashboard hoặc `GET /ml/status`.

⚠️ **Nếu thiếu artifact, hệ thống KHÔNG lỗi** — `ml_available=false`, 20 detector luật vẫn chạy, dashboard ghi
"AI model: Not loaded". ML chỉ là tín hiệu bổ sung cho risk engine và không bao giờ tự khoá tài khoản. Chi tiết:
[`ml-anomaly-model.md`](ml-anomaly-model.md).

## Bước 5c — (Tuỳ chọn) Nghiên cứu RBA / `hybrid_cp2` (offline)

Từ Phase 4.1, `hybrid_cp2` KHÔNG còn chạy trong `/login`. Mã nghiên cứu `ml/rba/` giữ nguyên để tái lập số liệu MR1-8
(cần `rba-dataset.zip` 9GB): [`reproduction-guide.md`](reproduction-guide.md) Giai đoạn 1-4.

## Bước 6 — Thử kịch bản tấn công (attack-sim)

Mở dashboard (Bước 4b) trước để xem cảnh báo hiện real-time, rồi ở
terminal khác:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\attack-sim
set PYTHONIOENCODING=utf-8
"..\backend\venv\Scripts\python.exe" brute_force.py --target user001
"..\backend\venv\Scripts\python.exe" credential_stuffing.py
"..\backend\venv\Scripts\python.exe" success_after_fail.py --target user001 --correct-password Demo@12345
```

`impossible_travel.py` cần thêm `TRUST_FORWARDED_FOR=true` trong `.env`
(mặc định tắt — chỉ bật khi demo cục bộ, xem cảnh báo trong
`backend/app/config.py`) rồi khởi động lại backend.

## Bước 6b — (Tuỳ chọn) Thư viện kịch bản tấn công mô phỏng v2 (MR18)

`attack-sim/` (Tuần 6) chỉ có 4 kịch bản cơ bản. Giai đoạn mở rộng AI thêm một thư viện 9 kịch bản thực tế hơn (IP/ASN
thật qua GeoIP, botnet, dò danh sách tài khoản, kẻ tấn công tinh vi...), chạy thẳng qua HTTP như người dùng thật, tự
tính điểm phát hiện theo từng tầng và xuất báo cáo:

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
set PYTHONIOENCODING=utf-8
python -m scripts.attack_scenario_runner   # ghi lại docs/attack-scenarios-v2.md
```

Các script mô phỏng khác (không phải test, dùng để khảo sát/minh chứng — mỗi script tự dựng CSDL/Redis riêng trong bộ
nhớ, không đụng dữ liệu dev thật, KHÔNG chạy qua pytest): tương quan cảnh báo/chiến dịch
(`scripts.alert_intelligence_sim`, MR13), vòng phản hồi + ngưỡng thích nghi (`scripts.feedback_loop_sim`, MR15),
phản ứng tự động — OTP/khoá tài khoản (`scripts.automated_response_sim`, MR16). Đọc kết quả tương ứng ở
[`docs/attack-scenarios-v2.md`](attack-scenarios-v2.md), [`docs/feedback-loop.md`](feedback-loop.md),
[`docs/automated-response.md`](automated-response.md) trước khi chạy lại — mỗi script mất vài phút và một số dùng dữ
liệu ngẫu nhiên không hạt giống cố định nên số liệu có thể lệch nhẹ giữa các lần chạy.

## Dừng hệ thống khi xong việc

- Terminal backend/frontend: `Ctrl+C`.
- Docker: `docker compose down` (giữ lại dữ liệu DB) hoặc để chạy nền cũng
  không sao — không tốn tài nguyên đáng kể khi máy rảnh.

## Lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| `uvicorn` báo lỗi bind port 8000 | Còn tiến trình cũ chưa tắt | Đóng terminal cũ đang chạy uvicorn, hoặc `netstat -ano \| findstr :8000` rồi `taskkill /F /PID <pid>` |
| Vite báo "Port 5173 is in use" | Tương tự, tiến trình cũ | Đóng terminal cũ hoặc kill theo PID như trên |
| Chữ tiếng Việt lỗi (`UnicodeEncodeError`) khi chạy script Python | Console Windows dùng codepage cp1252 | Chạy `set PYTHONIOENCODING=utf-8` trước khi gọi script |
| `docker compose up` báo lỗi kết nối tới Docker | Docker Desktop chưa khởi động xong | Mở Docker Desktop, đợi rồi thử lại |
| Frontend gọi API bị lỗi CORS | Backend chưa chạy, hoặc chạy sai port | Đảm bảo backend chạy ở port 8000 (khớp `VITE_API_BASE_URL` trong `.env`) |

## Chạy test

```bash
cd D:\github\phat-hien-dang-nhap-bat-thuong\backend
venv\Scripts\activate
pytest -q
```

Không cần Docker chạy — test dùng SQLite in-memory + Redis giả lập
(fakeredis), tách biệt hoàn toàn khỏi dữ liệu dev thật.
