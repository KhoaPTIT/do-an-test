# Kiểm thử end-to-end toàn luồng (nhiệm vụ 6.2)

Môi trường: backend + frontend + Postgres + Redis chạy đồng thời như môi
trường demo thật (`docker compose up -d`, `uvicorn`, `npm run dev`), dashboard
mở trong trình duyệt, đăng nhập admin thật, quan sát trực tiếp qua WebSocket
real-time — không dùng dữ liệu giả lập cho phần kiểm thử này.

## Bảng test case

| # | Input (script + tham số) | Kết quả mong đợi | Kết quả thực tế | Pass/Fail |
|---|---|---|---|---|
| TC1 | `brute_force.py --target user007` (6 lần sai) | Dashboard nổi alert `brute_force` ngay khi đạt ngưỡng, không cần reload | Alert `brute_force` xuất hiện qua WebSocket ngay lập tức, bảng log cập nhật đủ 6 dòng | ✅ Pass |
| TC2 | `credential_stuffing.py --prefix cs_final` (12 username) | Dashboard nổi alert `credential_stuffing` | Alert đúng loại xuất hiện real-time, log hiển thị đủ 12 username khác nhau | ✅ Pass |
| TC3 | `success_after_fail.py --target user008 --correct-password Demo@12345` (4 fail + 1 đúng) | Risk score tăng vọt ngay lần cuối (+50), alert `high_risk_score` xuất hiện ngay | `risk_score=50`, alert `high_risk_score (medium)` xuất hiện đúng thời điểm | ✅ Pass |
| TC4 | `impossible_travel.py --target user009 --password Demo@12345` (IP Mỹ → IP Úc) | Alert `impossible_travel`, bản đồ vẽ 2 điểm + đường nối | Alert đúng loại; **lần chạy đầu bản đồ trông như trống** — xem mục Lỗi phát hiện bên dưới | ✅ Pass (sau khi sửa) |
| TC5 | Đăng nhập bình thường (không tấn công) | Không tạo alert nhầm, risk_score thấp | Xác nhận qua Tuần 3-5 (không lặp lại ở đây) — không có false positive | ✅ Pass |
| TC6 | Kill backend giữa phiên, khởi động lại | WebSocket tự reconnect, không cần reload trang | Header chuyển "○ mất kết nối" → tự phục hồi "● real-time" trong vài giây sau khi backend sống lại | ✅ Pass |

## Lỗi phát hiện trong quá trình kiểm thử

| # | Mô tả | Mức độ | Trạng thái |
|---|---|---|---|
| 1 | Script `impossible_travel.py` demo dùng IP mẫu `203.0.113.10` (dải TEST-NET, RFC 5737) — không có trong GeoLite2-City thật, lookup luôn thất bại (trả `None` có kiểm soát, không crash) nên `is_impossible_travel()` không có đủ dữ liệu để kích hoạt. Không lộ ra ở chế độ mock (Tuần 3) vì lúc đó chưa cài GeoLite2 thật. | Chặn demo (script chạy "thành công" nhưng không tạo được alert cần minh hoạ) | **Đã sửa** — đổi sang IP `203.119.101.100` (đã xác nhận có toạ độ thật, Brisbane/AU), thêm cảnh báo trong docstring về việc tránh dải IP dành cho tài liệu/test khi tự đổi IP. |
| 2 | Khi 2 alert `impossible_travel` liên tiếp có toạ độ ở xa trung tâm bản đồ mặc định (Việt Nam, zoom 5), marker + đường nối bị vẽ **ngoài khung nhìn** — trông như bản đồ không vẽ gì, dù dữ liệu và logic vẽ đều đúng (xác nhận bằng cách replay đúng message WebSocket qua console trình duyệt). | Chặn demo (hội đồng sẽ không thấy được bằng chứng trực quan quan trọng nhất của tính năng) | **Đã sửa** — `MapPanel.jsx` thêm `FitBoundsOnChange` (dùng `useMap().fitBounds()`) để bản đồ tự pan/zoom thấy đủ cả 2 điểm mỗi khi có đường bay mới. |

Cả 2 lỗi đều được phát hiện thông qua kiểm thử E2E thật (không phải suy luận), và đều thuộc mức "chặn demo" theo phân loại checklist — đã sửa trước khi coi Tuần 6 hoàn thành, đúng nguyên tắc "sửa lỗi chặn demo trước, chạy lại toàn bộ".

## Chạy liên tục không lỗi (yêu cầu ≥ 15-20 phút)

- Bắt đầu tính từ lần khởi động ổn định cuối cùng (không restart thêm): backend + frontend + Postgres + Redis.
- Trong khoảng thời gian này: chạy đủ cả 4 kịch bản tấn công (TC1-TC4) + thao tác qua lại trên dashboard, không có lỗi mới phát sinh, không cần khởi động lại tiến trình nào.
- `docker ps` xác nhận Postgres/Redis giữ trạng thái `healthy` liên tục suốt phiên.

## Kết luận (Definition of Done Tuần 6)

- [x] Cả 4 kịch bản tấn công chạy đúng kết quả mong đợi trên dashboard, không cần can thiệp thủ công (sau khi sửa 2 lỗi ở trên).
- [x] Bảng test case end-to-end không còn dòng nào ở trạng thái Fail mức "chặn demo".
- [x] Hệ thống chạy liên tục không lỗi trong khoảng thời gian tương đương buổi bảo vệ thật.
