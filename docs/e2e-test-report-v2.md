# Kiểm thử end-to-end toàn luồng — giai đoạn mở rộng AI (MR19)

Bổ sung cho [`e2e-test-report.md`](e2e-test-report.md) (Tuần 6, chỉ phủ tầng 1). Môi trường giống hệt: backend +
frontend + Postgres + Redis thật chạy đồng thời (`docker compose up -d`, `uvicorn`, `npm run dev`), đăng nhập admin
thật qua trình duyệt (`mr19_e2e_admin`, tạo bằng `scripts.create_admin` — không dùng tài khoản admin có sẵn vì không
rõ mật khẩu), thao tác qua UI thật (không gọi API trực tiếp), quan sát WebSocket real-time. Không dùng dữ liệu giả
lập cho phần này — mọi log/alert dưới đây do chính phiên kiểm thử này tạo ra trên DB dev thật.

**Phạm vi:** các tính năng MR9-18 chưa có TC nào ở báo cáo Tuần 6 — hybrid risk scoring, giải thích cảnh báo, khoá tự
động + mở khoá, 4 trang quản trị mới (Campaigns, Rules, Model Health, User Profile), vòng phản hồi.

## Bảng test case

| # | Thao tác qua UI | Kết quả mong đợi | Kết quả thực tế | Pass/Fail |
|---|---|---|---|---|
| TC1 | 5 lần đăng nhập sai mật khẩu + 1 lần đúng, tài khoản `user020`, qua form `/login` thật | `brute_force` (tầng 1) + hybrid risk engine đề xuất `lock`, tài khoản bị khoá tự động (MR16), frontend hiện thông báo khoá thay vì đăng nhập thành công | Alert `high_risk_score (Dò mật khẩu)`, `hybrid_risk (high, 81đ, đề xuất 'lock')` xuất hiện real-time; response `423`, frontend hiện "Tài khoản hoặc nguồn đăng nhập đang tạm khoá do hoạt động bất thường" | ✅ Pass |
| TC2 | Xem giải thích cảnh báo `hybrid_risk` vừa tạo ở TC1 trên dashboard | Tối đa 3 yếu tố, câu tiếng Việt, có % đóng góp (MR8) | "Hybrid risk engine: điểm 81/100, đề xuất 'lock' — **mô hình học máy (81%)**; Đăng nhập thành công 'user020' sau 5 lần sai/10 phút từ 1 IP (0%); Lần đầu thiết bị này (0%)" — đúng định dạng, đúng 3 yếu tố, ML là yếu tố áp đảo | ✅ Pass |
| TC3 | Mở panel "Khoá tạm & chặn (MR16)" trên dashboard sau TC1 | Thấy đúng 1 mục khoá tài khoản `user020`, có nút mở khoá | Mục hiện: loại "Tài khoản", giá trị `user020`, lý do "Tự động khoá (MR16) — mô hình học máy (81%)...", hết hạn hiển thị đúng giờ, nút "🔓 Mở khoá" | ✅ Pass |
| TC4 | Bấm "🔓 Mở khoá" trên mục vừa thấy ở TC3 | Panel cập nhật ngay (không reload), tài khoản đăng nhập lại được | Panel đổi thành "Không có khoá/chặn nào đang hiệu lực" ngay lập tức; đăng nhập lại `user020`/`Demo@12345` qua `/login` thật → "Đăng nhập thành công" | ✅ Pass |
| TC5 | Bấm nút phản hồi "👍 Đúng" trên một alert `ml_anomaly` đang chờ | Nút biến mất, thay bằng xác nhận, ghi `audit_log` (MR15) | Hiện "*Đã xác nhận đúng*" ngay lập tức, không lỗi console | ✅ Pass |
| TC6 | Mở `/dashboard/rules` | Danh sách ≥ 15 luật, mỗi luật có mức độ, mô tả, dropdown chế độ, nút Lưu (MR17) | Hiện đủ nhóm "Danh tiếng hạ tầng" (blocklist/datacenter/Tor/VPN...) với đúng badge mức độ (HIGH/MEDIUM/LOW) và chế độ mặc định (Bật/Theo dõi) | ✅ Pass |
| TC7 | Mở `/dashboard/model-health` | Bảng phiên bản mô hình đang active + bảng drift PSI (MR17) | `hybrid_cp2`/`cp2`, "✅ Đang dùng", `feature_signature=2e54756a441c` (khớp [`model-card-rba.md`](model-card-rba.md)) — xác nhận mô hình vận hành thật ĐÃ nạp, không rơi về hồ sơ dự phòng; bảng PSI hiện đủ, xem ⚠️ ở mục Phát hiện bên dưới | ✅ Pass (kèm phát hiện) |
| TC8 | Mở `/dashboard/campaigns`, xem chi tiết 1 chiến dịch | Danh sách + trang chi tiết (dòng thời gian, tài khoản bị nhắm, đồ thị hạ tầng) (MR14) | Chiến dịch tự gom đúng theo IP nguồn, trang chi tiết hiện dòng thời gian alert đúng thứ tự thời gian, danh sách tài khoản bị nhắm, khung đồ thị hạ tầng render không lỗi | ✅ Pass |
| TC9 | Mở `/dashboard/users/{id}` cho một user có lịch sử | Ngưỡng rủi ro riêng (MR15), thiết bị/quốc gia quen, dòng thời gian alert (MR17) | Đúng hiện "Chưa đủ phản hồi — đang dùng ngưỡng NHÓM" (chưa cá nhân hoá — đúng vì user này chưa đủ phản hồi), 2 thiết bị quen liệt kê đúng UA, 20 alert gần nhất | ✅ Pass |
| TC10 | Đăng nhập admin bằng tài khoản admin **có sẵn** trên máy dev (không phải tài khoản test mới tạo) | — (không phải test case, chỉ để tận dụng tài khoản có sẵn) | Sai mật khẩu ("Sai tài khoản hoặc mật khẩu quản trị") — không rõ mật khẩu gốc; chuyển sang tạo tài khoản test riêng (`mr19_e2e_admin`) thay vì đoán thêm | ℹ️ Không tính pass/fail — đổi cách tiếp cận |

## Phát hiện trong quá trình kiểm thử

| # | Mô tả | Mức độ | Trạng thái |
|---|---|---|---|
| 1 | **PSI drift ở `/dashboard/model-health` cực đoan và không mang tính hành động**: mọi đặc trưng đều "trôi đáng kể" với PSI 8,3–10,6 (thang PSI tiêu chuẩn: > 0,25 đã là "đáng kể" — số đo được cao hơn ngưỡng đó **30-40 lần**). Nguyên nhân: tham chiếu là **train RBA** (1.139.727 dòng, log SSO Na Uy thật đã tổng hợp lại) so với **hiện tại** là 300 dòng đăng nhập demo/dev của chính dự án này (user00x/mô phỏng) — hai quần thể khác nhau về bản chất (không phải cùng hệ thống trôi theo thời gian), nên PSI luôn cực lớn bất kể mô hình có "cũ" hay không. Trang vẫn tính đúng theo công thức, không phải lỗi code — nhưng con số **không nói lên được gì về sức khoẻ mô hình trong bối cảnh dự án này**, khác với ý nghĩa PSI vốn có khi so cùng một hệ thống qua thời gian. | Thông tin gây hiểu nhầm (không phải crash) | **Chưa sửa** — ghi nhận làm giới hạn của tính năng, không thuộc phạm vi MR19. Hướng khả dĩ: đổi "hiện tại" thành log RBA của một tháng sau thay vì log demo của dự án, hoặc ẩn PSI khi hai quần thể được biết là không cùng nguồn. |
| 2 | **`scripts/create_admin.py` crash với `UnicodeEncodeError` trên PowerShell/cmd mặc định** (không set `PYTHONIOENCODING=utf-8`) — NHƯNG việc tạo/cập nhật admin trong DB đã xảy ra thành công TRƯỚC khi crash ở dòng `print` cuối; script thoát mã lỗi 1 dù việc chính đã xong, dễ khiến người chạy tưởng thất bại và thử lại/nghi ngờ sai. Cùng lớp lỗi đã biết ở nhiều script khác trong dự án (xem "Lỗi thường gặp" ở [`getting-started.md`](getting-started.md)) — không mới, nhưng đây là lần đầu quan sát được nó có thể che giấu một thao tác ĐÃ thành công. | Nhỏ (cosmetic, không mất dữ liệu/chức năng) | **Chưa sửa** — đã có hướng dẫn `set PYTHONIOENCODING=utf-8` ở getting-started.md; sửa tận gốc (set encoding trong chính script) là cải tiến hợp lý cho MR-S nào đó sau này, ngoài phạm vi MR19. |

Không có lỗi nào ở mức "chặn demo" — cả hai phát hiện trên đều là hạn chế/khó chịu nhỏ, hệ thống hoạt động đúng chức
năng chính trong toàn bộ phiên kiểm thử (không backend error nào ở log server suốt phiên, xác nhận qua
`preview_logs` cấp độ lỗi).

## Ghi chú

- Không lặp lại TC1-6 của [`e2e-test-report.md`](e2e-test-report.md) (brute force/credential stuffing/impossible
  travel/reconnect WebSocket ở tầng 1) — đã pass ở đó, hành vi tầng 1 không đổi qua MR9-18.
- Không test lại kịch bản đã có scorecard qua HTTP thật ở [`attack-scenarios-v2.md`](attack-scenarios-v2.md) (MR18,
  9 kịch bản) hay luồng OTP đầy đủ ở [`automated-response.md`](automated-response.md) (MR16, kịch bản 2) — trùng lặp
  không cần thiết; giá trị tăng thêm của phiên này là xác nhận **giao diện** render đúng các trạng thái đó, việc mà
  hai tài liệu kia (chạy qua `TestClient`, không có trình duyệt) không kiểm chứng được.
