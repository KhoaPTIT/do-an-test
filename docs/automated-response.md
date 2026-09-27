# Phản ứng tự động — mô phỏng toàn bộ luồng (MR16)

Chạy qua HTTP thật (`TestClient`, không bỏ qua router như các script MR13-15) — mã nguồn: [`backend/scripts/automated_response_sim.py`](../backend/scripts/automated_response_sim.py). Cơ chế: [`app/detection/response_execution.py`](../backend/app/detection/response_execution.py), [`app/routers/auth.py`](../backend/app/routers/auth.py), [`app/routers/blocklist.py`](../backend/app/routers/blocklist.py).

## Kịch bản 1 — Khoá tự động (lock)

Nạn nhân có tài khoản thật; kẻ tấn công có MẬT KHẨU ĐÚNG (rò rỉ từ nơi khác) nhưng đến từ một ASN đã biết xấu.

| Bước | Kết quả |
|---|---|
| 1. Nạn nhân đăng nhập bình thường (trước khi bị tấn công) | ✅ thành công |
| 2. Kẻ tấn công đăng nhập ĐÚNG mật khẩu từ ASN đã bị chặn | HTTP 423, `locked=True` ✅ |
| 3. Mục khoá mới nhắm vào TÀI KHOẢN (không phải IP kẻ tấn công) | ✅ |
| 4. ⚠️ Nạn nhân đăng nhập lại (IP RIÊNG của họ, mật khẩu đúng) | bị khoá theo (423) ✅ |
| 5. Admin thấy mục khoá trong `GET /blocklist` | ✅ |
| 6. Admin mở khoá (`DELETE /blocklist/{id}`) | HTTP 204 ✅ |
| 7. Nạn nhân đăng nhập lại SAU khi admin mở khoá | ✅ thành công |

## Kịch bản 2 — Xác thực thêm (step_up / OTP giả lập)

Không có luật GHI ĐÈ nào ra `step_up` như `blocklist_hit` ra `lock` — ép thẳng qua `hybrid_runtime` (kỹ thuật `_spy_on_evaluate` đã dùng ở `tests/test_pipeline_mr15.py`), xem docstring script.

| Bước | Kết quả |
|---|---|
| 1. Đăng nhập đúng mật khẩu, hành động bị ép = step_up | HTTP 200, `step_up_required=True` ✅ |
| 2. OTP giả lập được tạo (challenge_id + mã demo) | ✅ |
| 3. Xác thực với mã SAI | từ chối, message: "Mã xác thực không đúng hoặc đã hết hạn." ✅ |
| 4. Xác thực với mã ĐÚNG | HTTP 200, thành công ✅ |

## Diễn giải

- **Phát hiện đáng chú ý (bước 4, kịch bản 1)**: khoá tự động MR16 khoá TÀI KHOẢN khi tài khoản có thật (`lock_kind_and_value`, `app/detection/response_execution.py`) — nghĩa là SAU một lần bị dò trúng mật khẩu từ hạ tầng khả nghi, chính CHỦ tài khoản cũng không đăng nhập được (từ BẤT KỲ IP nào, kể cả IP quen thuộc của họ) cho tới khi admin mở khoá hoặc hết `LOCK_TTL` (30 phút). Đây là đánh đổi AN TOÀN > TIỆN LỢI có chủ đích (nếu mật khẩu đã lộ, phải ngăn TẤT CẢ các lần đăng nhập cho tới khi xác minh qua kênh khác) — nhưng là một CHI PHÍ thật cho người dùng hợp lệ, không phải tác dụng phụ nên bỏ qua.
- Precheck (`app/routers/auth.py`) không tra ASN (đắt) nên bước 2 CHỈ bị bắt SAU khi mật khẩu đã được xác thực và pipeline chấm điểm xong — khác bước 4 (bị bắt NGAY ở precheck, vì lần này là khoá THEO TÊN TÀI KHOẢN, loại precheck CÓ kiểm) — cả hai đường đều đúng, chỉ khác chỗ chặn.
- `step_up` không có "cửa" xác định nào để tái lập tự nhiên qua toàn bộ rule engine + mô hình thật một cách đáng tin cậy (phụ thuộc hiệu chỉnh `ActionBands`, xem `docs/hybrid-risk-engine.md`) — ép thẳng qua `hybrid_runtime` LÀ kỹ thuật kiểm thử chính thống, không phải né tránh (cùng cách `tests/test_pipeline_mr15.py` đã làm cho một vấn đề tương tự).

## Giới hạn

- Cả hai kịch bản chạy 1 lần, minh hoạ CƠ CHẾ — không phải khảo sát thống kê trên diện rộng.
- DB SQLite in-memory + fakeredis (không phải Postgres/Redis dev thật) — số đo ĐỘ TRỄ (khác script này) nằm ở mục riêng bên dưới, đo qua HTTP thật.
- Kịch bản `step_up` dùng hành động ÉP CỨNG, không phải điểm số tự nhiên — không nói lên được NGƯỠNG thật sự dễ/khó đạt step_up thế nào trong dữ liệu thật (đó là câu hỏi của hiệu chỉnh `ActionBands`, đã bàn ở `docs/hybrid-risk-engine.md`, không phải của MR16).
- Chưa mô phỏng OTP hết hạn / quá số lần thử sai / challenge bị dùng lại — các nhánh đó đã có test đơn vị đầy đủ ở `backend/tests/test_auth_mr16.py`, không lặp lại ở đây (script này minh hoạ LUỒNG, không thay thế bộ test).

## Độ trễ (đo riêng, HTTP thật, Postgres dev thật — `scripts/benchmark_login.py`)

30 request TUẦN TỰ mỗi kịch bản, cùng máy, cùng phiên đo (để so sánh công bằng — số tuyệt đối cao hơn baseline MR12 vì máy đang chạy nhiều tiến trình khác lúc đo, không phải vì MR16; xem cột chênh lệch để tách hai hiệu ứng):

| Kịch bản | min | median | p95 | max |
|---|---|---|---|---|
| Sai mật khẩu (nền, KHÔNG đổi từ MR12) | 347,8 ms | 596,0 ms | 1.193,4 ms | 2.366,9 ms |
| Đúng mật khẩu (MỚI — chờ đồng bộ kết quả chấm điểm) | 641,8 ms | 735,6 ms | 793,9 ms | 2.730,1 ms |
| **Chênh lệch (median)** | | **+139,6 ms** | | |

Chênh lệch trung vị (~140 ms) khớp cùng bậc độ lớn với chi phí pipeline TRONG TIẾN TRÌNH đã đo ở MR12 (`docs/realtime-integration.md` mục 3.1: mean 28,1 ms, **p99 134,2 ms**) — phần lớn khác biệt TUYỆT ĐỐI giữa hai lần đo (735 ms hôm nay so với 280 ms ở MR12) đến từ MÔI TRƯỜNG đo (máy dev đang chạy nhiều tiến trình khác khi đo MR16), KHÔNG PHẢI từ thay đổi của MR16 — đo cả hai đường trong CÙNG một phiên (bảng trên) mới là số đáng tin để đánh giá chi phí thật của việc chuyển sang chờ đồng bộ.
