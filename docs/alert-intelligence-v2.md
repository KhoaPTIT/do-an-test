# Cảnh báo thông minh v2 (MR13)

Kịch bản có NHÃN TỰ ĐẶT (không phải RBA — RBA không có nhãn "họ tấn công") chạy trên CHÍNH pipeline thật (rule engine v2 + hybrid risk engine, model `hybrid_cp2` thật), DB SQLite cô lập mỗi kịch bản — mã nguồn: [`backend/scripts/alert_intelligence_sim.py`](../backend/scripts/alert_intelligence_sim.py). Cơ chế (novelty, gán họ tấn công, ưu tiên, chống trùng lặp): [`app/detection/alert_intelligence.py`](../backend/app/detection/alert_intelligence.py).

## Kết quả chính

- **Giảm số cảnh báo nhờ chống trùng lặp**: 7 lần pipeline đề xuất khác "allow" → còn lại 3 hàng `Alert` sau khi gộp — giảm **57.1%** (gần như toàn bộ đến từ `reputation_burst`, xem diễn giải).
- **Tỉ lệ kịch bản có nhãn thực sự vượt ngưỡng "alert" một mình**: 40.0% (2/5) — câu hỏi KHÁC với độ chính xác gán họ, xem diễn giải.
- **Độ chính xác gán họ tấn công gợi ý, trong số kịch bản THỰC SỰ có alert**: **100.0%** (2 kịch bản có alert trong số 5 kịch bản có nhãn).
- **Báo nhầm phát hiện được**: 1 — benign_control (xem diễn giải, liên quan trực tiếp phát hiện PSI drift của MR12).

## Từng kịch bản

| Kịch bản | Họ kỳ vọng | Số lần đề xuất khác allow | Số alert còn lại | Họ được gán | Đúng? |
|---|---|---|---|---|---|
| `brute_force` — 8 lần sai liên tiếp vào 1 tài khoản (ngưỡng 5 lần/300s) | Đoán và dò mật khẩu | 0 | 0 | *(không có alert nào)* | ❌ |
| `bot_user_agent` — 1 lần thử với User-Agent Googlebot | Tự động hoá | 0 | 0 | *(không có alert nào)* | ❌ |
| `impossible_travel` — Đăng nhập thành công ở Hà Nội rồi Mỹ chỉ sau 5 phút | Ngữ cảnh tài khoản | 1 | 1 | Ngữ cảnh tài khoản | ✅ |
| `dormant_account_login` — 1 lần thành công 100 ngày trước (VN) rồi đăng nhập lại từ Trung Quốc | Ngữ cảnh tài khoản | 0 | 0 | *(không có alert nào)* | ❌ |
| `reputation_burst` — 5 lần đăng nhập thành công liên tiếp từ 1 IP trong blocklist | Danh tiếng hạ tầng | 5 | 1 | Danh tiếng hạ tầng | ✅ |
| `benign_control` — Đăng nhập bình thường khớp lịch sử quen thuộc (đối chứng âm) | *(không có — đối chứng âm)* | 1 | 1 | đăng nhập bất thường | ❌ |

## Diễn giải

- `reputation_burst` là kịch bản đo GIẢM ALERT rõ nhất: `blocklist_hit` ghi đè (điểm 100/lock) một cách TẤT ĐỊNH ở MỌI lần, nên "số lần đề xuất khác allow" phản ánh đúng số lần NẾU KHÔNG chống trùng lặp mỗi lần sẽ ra 1 alert riêng — gán họ ĐÚNG ("Danh tiếng hạ tầng") ở CẢ 5 lần trước khi gộp, không chỉ lần đầu.
- `brute_force`, `bot_user_agent`, `dormant_account_login`: luật liên quan CÓ khớp (`evaluation.hits`) nhưng KHÔNG tự vượt ngưỡng "alert" của hybrid risk engine MỘT MÌNH — ĐÚNG như hiệu chỉnh MR11 đã đo (một luật ồn đứng một mình đóng góp trọng số thấp, cần thêm bằng chứng khác mới đủ), không phải lỗi. Không tính vào mẫu đo độ chính xác gán họ (không có alert nào để gán) — tách riêng thành `detection_rate_pct` để không đánh đồng "gán sai họ" với "không đủ tự tin để báo", hai vấn đề khác nhau.
- `impossible_travel`: hai IP thật đều CŨNG khớp `datacenter_ip` (8.8.8.8 nằm trong danh sách datacenter thật đã tải, xác nhận trực tiếp qua `ThreatIntel.in_datacenter`) — nhưng `impossible_travel` (severity cao hơn, trọng số hiệu chỉnh lớn hơn) vẫn thắng đúng như kỳ vọng. `dormant_account_login` LÚC ĐẦU dùng chung IP này và bị gán NHẦM thành "Danh tiếng hạ tầng" (datacenter_ip thắng, trọng số cao hơn dormant_account_login) — không phải lỗi code, mà là chọn IP kịch bản chưa cẩn thận (vô tình kéo theo một bằng chứng luật KHÁC mạnh hơn); đã đổi sang IP sạch (CHINA_IP, xác nhận không nằm trong danh sách datacenter/VPN nào) trước khi chạy bản cuối này.
- **`benign_control` (đối chứng âm) tạo ra 1 báo nhầm** — mô hình ML (`hybrid_cp2`) MỘT MÌNH vượt ngưỡng "alert" cho một lần đăng nhập hoàn toàn khớp lịch sử quen thuộc của chính tài khoản đó, không luật nào khớp. Nguyên nhân xác định được TRỰC TIẾP (không phải suy đoán): quốc gia/ASN Việt Nam của IP dùng trong kịch bản CỰC HIẾM so với phân bố huấn luyện của RBA nên đặc trưng `rare_country`/`rare_asn`/`llr_*` bị đẩy rất cao — CHÍNH XÁC là hệ quả của phát hiện PSI drift đã công bố ở MR12 (`docs/realtime-integration.md`), lần này ĐO ĐƯỢC CỤ THỂ bằng một ca báo nhầm thật thay vì chỉ số PSI trừu tượng. Không sửa bằng cách né tránh (đổi sang IP không phải Việt Nam) vì hệ thống demo NÊN được thử với đúng loại lưu lượng thật của nó — giữ nguyên và báo cáo trung thực. Hệ quả thực tế: `attack_family` gợi ý cho alert do MỘT MÌNH ML dẫn đầu (không có luật nào đồng hành) nên được đọc kèm cảnh giác cao hơn bình thường trên hệ thống demo hiện tại — sẽ bớt xảy ra khi hybrid_cp2 được hiệu chỉnh lại cho đúng quy mô dữ liệu thật (việc chưa làm, đã ghi ở MR12).

## Giới hạn

- Nhãn "họ tấn công" của TỪNG kịch bản do người viết kịch bản (tôi) tự đặt khi THIẾT KẾ kịch bản để CÓ THỂ đo được, không phải kịch bản tấn công đối kháng độc lập — thư viện tấn công mô phỏng đầy đủ, đối kháng hơn là MR18.
- Chưa có kịch bản "ML dẫn đầu ĐÚNG Ý ĐỊNH" (chỉ hybrid_cp2 tự phát hiện, không kèm luật, và KHÔNG phải báo nhầm do drift) — `benign_control` vô tình cho thấy đúng trường hợp ML dẫn đầu nhưng đó là báo nhầm, không phải ví dụ tốt.
- Cửa sổ chống trùng lặp (15 phút, `alert_intelligence.DEDUP_WINDOW`) là hằng số TỰ CHỌN, chưa đối chiếu với khoảng cách thời gian thật giữa các đợt tấn công (out of scope MR13).
- Chỉ 6 kịch bản, chạy 1 lần (không lặp lại với seed ngẫu nhiên khác) — đủ để kiểm chứng CƠ CHẾ hoạt động đúng và phát hiện được vấn đề thật (báo nhầm do drift), KHÔNG đủ để ước lượng độ chính xác gán họ trên diện rộng như một bộ đánh giá thống kê nghiêm túc.
