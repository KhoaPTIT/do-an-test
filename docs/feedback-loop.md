# Vòng phản hồi (MR15)

Mô phỏng **8 vòng** liên tiếp trên CHÍNH pipeline thật (rule engine + hybrid risk engine, model `hybrid_cp2` thật) — mã nguồn: [`backend/scripts/feedback_loop_sim.py`](../backend/scripts/feedback_loop_sim.py). Cơ chế (ngưỡng thích nghi, retrain định kỳ): [`app/detection/adaptive_threshold.py`](../backend/app/detection/adaptive_threshold.py), [`scripts/retrain_from_feedback.py`](../backend/scripts/retrain_from_feedback.py).

## Kết quả chính

- **Tài khoản hay bị báo nhầm** (tái dùng đúng kịch bản báo nhầm THẬT đã phát hiện ở MR13 — IP Việt Nam thật, ASN/quốc gia cực hiếm so với RBA khiến một mình ML vượt ngưỡng): bị báo ở các vòng **[1, 2, 3]**.
- **Ngừng báo nhầm kể từ vòng 4** trở đi (và không báo lại vòng nào sau đó trong 8 vòng đã chạy).
- **Tài khoản bị tấn công thật (IP trong blocklist) vẫn bị phát hiện ở CẢ 8/8 vòng**: ✅ đúng như kỳ vọng (ngưỡng thích nghi không làm mất phát hiện thật).

## Từng vòng

| Vòng | TK hay báo nhầm bị báo? | threshold_delta sau retrain | Số phản hồi tích luỹ | TK bị tấn công có bị phát hiện? |
|---|---|---|---|---|
| 1 | ✅ có | 0.0 | 1 | ✅ lock |
| 2 | ✅ có | 0.0 | 2 | ✅ lock |
| 3 | ✅ có | 12.0 | 3 | ✅ lock |
| 4 | — | 12.0 | 3 | ✅ lock |
| 5 | — | 12.0 | 3 | ✅ lock |
| 6 | — | 12.0 | 3 | ✅ lock |
| 7 | — | 12.0 | 3 | ✅ lock |
| 8 | — | 12.0 | 3 | ✅ lock |

## Diễn giải

- `MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD` = 3 vòng (`app/detection/adaptive_threshold.py`) nên 2 vòng đầu KHÔNG THỂ có điều chỉnh (chưa đủ mẫu) dù đã có phản hồi — đây là thiết kế có chủ đích (mẫu quá nhỏ không đáng tin), không phải chậm trễ ngoài ý muốn.
- `threshold_delta` chỉ NỚI LỎNG (không bao giờ âm) và được TÍNH LẠI TỪ ĐẦU mỗi lần retrain trên toàn bộ lịch sử phản hồi tích luỹ — không cộng dồn theo số lần chạy script, xem docstring `retrain_from_feedback.py`.
- Kịch bản tấn công thật dùng `blocklist_hit` (luật GHI ĐÈ, không phụ thuộc `ActionBands`) nên về mặt THIẾT KẾ không thể bị ảnh hưởng bởi ngưỡng thích nghi của MỘT tài khoản khác — bảng trên đo TRỰC TIẾP để xác nhận, không chỉ tin vào thiết kế.

## Hai biến nhiễu tự phát hiện và cách kiểm soát

Cả hai đo được TRỰC TIẾP khi dựng script (không phải giả thuyết) — nếu không kiểm soát, cả hai đều tự làm giảm điểm rủi ro theo thời gian, khiến báo nhầm "ngừng" vì LÝ DO KHÁC, không phải vì `threshold_delta`, làm sai lệch hoàn toàn kết luận của mô phỏng này:
1. **Quen dần theo SỐ LƯỢT đăng nhập**: điểm rủi ro giảm mạnh (32 → 22/100) chỉ sau ĐÚNG một lượt đăng nhập thành công bổ sung — đặc trưng RBA nhạy với độ dày lịch sử TỔNG THỂ của tài khoản, không chỉ độ quen với riêng IP/ASN lần đó. Kiểm soát: xoá lại lịch sử đăng nhập về đúng baseline SAU mỗi vòng, giữ nguyên `UserRiskProfile`.
2. **Trôi theo THỜI GIAN LỊCH**: dù đã xoá lại lịch sử ở trên, điểm vẫn tự trôi nhẹ (32 → 30 → 30 → 29) nếu các vòng cách nhau NHIỀU NGÀY — đặc trưng "tuổi tài khoản" tự tăng theo thời gian của kịch bản dù số dòng lịch sử không đổi. Kiểm soát: các vòng cách nhau vài GIÂY, không phải vài ngày.

## Giới hạn

- Chỉ MỘT tài khoản hay báo nhầm và MỘT kịch bản tấn công thật, chạy 1 lần — đủ để kiểm chứng CƠ CHẾ (ngưỡng có thực sự giảm báo nhầm theo phản hồi, có thực sự không làm mất phát hiện thật), KHÔNG đủ để ước lượng mức giảm báo nhầm trung bình trên diện rộng.
- "Đã biết chắc đây là báo nhầm" trong kịch bản là do TỰ DỰNG (biết trước ground truth), không phải quản trị viên thật phán đoán — vòng phản hồi thật phụ thuộc quản trị viên phán đoán ĐÚNG, sai sót của con người ở bước đó không mô phỏng ở đây.
- `threshold_delta` áp dụng ĐỀU cho cả ba mốc (`alert_at`/`step_up_at`/`lock_at`) — chưa thử nghiệm chỉnh riêng từng mốc (vd chỉ nới `alert_at`, giữ nguyên `lock_at`) dù có thể an toàn hơn cho các mốc nghiêm trọng.
- Script retrain chưa được lên lịch chạy tự động định kỳ thật (cron/scheduler) — hiện chạy tay hoặc gọi trực tiếp trong mô phỏng này.
- Các vòng của tài khoản hay báo nhầm cách nhau vài GIÂY (kiểm soát biến nhiễu #2 ở trên) — KHÔNG PHẢI nhịp độ đăng nhập thật của một người (thường cách nhau hàng giờ/ngày); đây là lựa chọn CÓ CHỦ ĐÍCH để cô lập đúng một hiệu ứng đang đo, không phải mô tả hành vi người dùng thật.
