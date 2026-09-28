# Ma trận phủ hành vi (MR19)

Tổng hợp **toàn bộ** hành vi tấn công mà hệ thống có cơ chế nhận diện — từ tầng 1 gốc (Tuần 3), luật tầng 2 (rule
engine v2, MR9), tới hành vi bất thường tầng 3 (ML, Tuần 7 + MR18) — cùng bằng chứng ĐO ĐƯỢC THẬT (không phải suy
đoán) cho từng hàng, lấy từ [`rule-catalog.md`](rule-catalog.md), [`hybrid-risk-engine.md`](hybrid-risk-engine.md),
[`ml-evaluation.md`](ml-evaluation.md), [`attack-scenarios-v2.md`](attack-scenarios-v2.md),
[`model-b-geo-time.md`](model-b-geo-time.md). Mục tiêu: một bảng DUY NHẤT trả lời "hành vi X có được phát hiện
không, bằng gì, đo được tới đâu" — không phải liệt kê tính năng, mà là liệt kê **bằng chứng**.

## Chú giải

- **✅** enforce/đo được, hoạt động như kỳ vọng · **🌓** `shadow` (chạy, ghi nhận, KHÔNG tự tạo alert riêng — vẫn là
  bằng chứng cho hybrid risk engine, MR11) hoặc kết quả mơ hồ · **❌** không có cơ chế / đo được là bỏ sót thật ·
  **—** không áp dụng.
- "Trọng số hybrid" = trọng số hiệu chỉnh của luật đó trong hybrid risk engine (MR11,
  [`hybrid-risk-engine.md`](hybrid-risk-engine.md)) — quyết định luật đó tự đủ tạo alert hybrid_risk hay chỉ là bằng
  chứng phụ. `blocklist_hit` là NGOẠI LỆ: GHI ĐÈ điểm 100 bất kể trọng số.

## Bảng

| Hành vi tấn công | Tầng 1 gốc (Tuần 3) | Luật tầng 2 (MR9) | Tầng 3 ML (Tuần 7 / MR18 "mô hình B") | Bằng chứng đo được thật |
|---|---|---|---|---|
| Dò mật khẩu 1 tài khoản | ✅ `brute_force` (5 lần/5') | ✅ `brute_force` (enforce, trọng số 10,1%) | — | test tích hợp (MR12) |
| Nhồi thông tin đăng nhập | ✅ `credential_stuffing` | ✅ `credential_stuffing` (enforce, trọng số **34,6%** — mạnh nhất) | — | ✅ MR18: phát hiện ở bước 10/16 |
| Rải mật khẩu chậm | ❌ | ✅ `password_spray_slow` (enforce, trọng số 10,2%) | — | ✅ MR18: phát hiện bước 1/18 (qua `ml_anomaly`, xem caveat cold-start ở `attack-scenarios-v2.md`) |
| Dò mật khẩu phân tán (botnet) | ❌ | ✅ `distributed_bruteforce` (enforce, **trọng số 0,0%** — mẫu val chỉ 2 dòng) | — | ⚠️ MR18: chỉ bắt được "TÌNH CỜ" qua `impossible_travel` (IP chọn cách xa nhau) — botnet cùng khu vực địa lý nhiều khả năng LỌT, chưa kiểm chứng trực tiếp |
| Dò danh sách tài khoản (enumeration) | ❌ | ✅ `username_enumeration` (enforce, trọng số 0,05 CHƯA hiệu chỉnh, không luật tầng 1 dự phòng) | — | ❌ MR18: **KHÔNG tạo alert nào** dù vượt hẳn ngưỡng riêng — bỏ sót thật |
| Thành công sau chuỗi sai | — (tầng 2 hành vi cũ dùng risk_score, cơ chế khác) | ✅ `success_after_failures` (enforce, trọng số 0%, mẫu val=40) | — | chưa đo riêng ở MR18 |
| Bot User-Agent | ❌ | ✅ `bot_user_agent` (enforce, chỉ dựa UA — dễ né bằng cách nói dối UA) | — | — |
| Client kịch bản (curl, python-requests...) | ❌ | ✅ `scripted_client` (enforce) | — | script demo `attack-sim/` tự khớp luật này (dùng httpx) |
| Xoay User-Agent | ❌ | ✅ `ua_rotation` (enforce, trọng số 0,05 chưa hiệu chỉnh) | — | ✅ MR18: phát hiện bước 1/9 (qua `brute_force` tầng 1 + `high_risk_score`) |
| Nhịp thử đều như máy | ❌ | 🌓 `regular_rhythm` (**shadow** — chưa kiểm chứng trên log thật) | — | — |
| Tor exit node | ❌ | ✅ `tor_exit` (enforce, cần danh sách công khai) | — | — |
| IP datacenter | ❌ | 🌓 `datacenter_ip` (**shadow** — dễ báo nhầm VPN doanh nghiệp) | — | — |
| VPN thương mại | ❌ | 🌓 `vpn_ip` (**shadow**) | — | — |
| Nguồn trong blocklist | ❌ | ✅ `blocklist_hit` (enforce, **GHI ĐÈ** điểm 100 bất kể trọng số) | — | ✅ MR16: khoá tài khoản/IP THẬT (không chỉ đề xuất), admin mở khoá qua `GET/DELETE /blocklist` |
| Di chuyển bất khả thi | ✅ `impossible_travel` (900km/h) | ✅ `impossible_travel` (enforce) | ✅ `impossible_travel_geo` (MR18, Isolation Forest recall **63,2%**) | ✅ MR18: phát hiện bước 1/2 qua CẢ hai tầng cùng lúc |
| Đăng nhập cùng lúc nhiều quốc gia | ❌ | ✅ `multi_context_simultaneous` (enforce, trọng số 0%, mẫu val=96) | — | bổ sung cho `impossible_travel` khi thiếu toạ độ |
| Tài khoản bị thử nhiều quốc gia (proxy xoay) | ❌ | 🌓 `country_hop` (**shadow**, trọng số 0%) | — | — |
| Tài khoản ngủ đông đăng nhập lại | ❌ | ✅ `dormant_account_login` (enforce, 90 ngày + đổi ngữ cảnh) | ✅ `dormant_reactivation` (MR18, Isolation Forest recall **100%**) | ✅ MR18: phát hiện bước 1/1 |
| Proxy/IP hiếm CÙNG quốc gia | ❌ | 🌓 `rare_network_login` (**shadow**, trọng số 2,6%) | — | 🌓 MR18: **MỘT MÌNH không đủ vượt ngưỡng alert** — trả lời câu hỏi để ngỏ ở `rule-catalog.md` |
| Mô phỏng tinh vi (không luật nào khớp rõ) | ❌ | ❌ (không có luật phù hợp) | 🌓 (chỉ tín hiệu ML yếu, không chắc phân biệt được với tài khoản mới) | 🌓 MR18 `targeted_mimic`: bị gắn cờ nhưng KHÔNG đủ tin cậy để khẳng định là phát hiện đúng kiểu — kết quả mơ hồ tự nó là phát hiện trung thực |
| Giờ đăng nhập lạ | — (risk_score cũ CÓ, cơ chế khác) | ❌ | ✅ `unusual_hour` (recall 58,8%, lần chạy gần nhất — dao động do thiếu random seed cố định) | `ml-evaluation.md`/`model-b-geo-time.md` |
| Vị trí lạ | — (risk_score cũ CÓ) | ❌ | ✅ `unusual_location` (recall 88,9%) | nt |
| Thiết bị lạ | ❌ | ❌ | ✅ `unusual_device` (recall 39,1% — điểm yếu đã biết từ Tuần 7) | nt |
| Đăng nhập dồn dập (rapid fire) | ❌ | ❌ | ✅ `rapid_fire` (**recall 0%** ở lần chạy MR18 — điểm yếu, xem giới hạn thiếu seed) | nt |
| Chiếm tài khoản thật (ATO, dữ liệu RBA) | — | — | — (mô hình `hybrid_cp2` riêng, không phải tầng 3 demo) | ✅ **36,8%** recall @ FPR 1% (38 ca ATO tương lai thật, `ml-evaluation-v2.md`) — mô hình duy nhất có tín hiệu đáng kể là Isolation Forest không giám sát |

## Khoảng trống đã biết (tổng hợp từ toàn bộ MR1-18, không phải mới ở MR19)

Liệt kê TRUNG THỰC — đây là những gì hệ thống **chưa** làm tốt, không che giấu để báo cáo đẹp hơn:

1. **`username_enumeration` không tạo alert được trong thực tế** (MR18) dù luật tự nó khớp đúng — trọng số hybrid
   0,05 mặc định (chưa có dữ liệu val để hiệu chỉnh) không đủ một mình, và đây là hành vi DUY NHẤT trong nhóm "đoán/dò
   mật khẩu" không có luật tầng 1 dự phòng.
2. **`distributed_bruteforce` có trọng số hybrid = 0,0** (mẫu val chỉ 2 dòng khi hiệu chỉnh, MR11) — một botnet dùng
   hạ tầng CÙNG khu vực địa lý (không kích hoạt `impossible_travel` "tình cờ") nhiều khả năng không bị phát hiện.
3. **ATO ở tài khoản CHƯA CÓ lịch sử: 0% recall ở mọi mô hình** (35% số ATO thật của RBA rơi vào nhóm này,
   `ml-evaluation-v2.md` mục 4) — khoảng trống lớn nhất của toàn hệ thống, chưa có hướng giải quyết ngoài "cần dữ
   liệu/luật khác".
4. **`rapid_fire` (tầng 3) yếu** — recall 0-43% tuỳ lần chạy, luôn là một trong hai kiểu yếu nhất từ Tuần 7.
5. **Kẻ tấn công bắt chước hoàn hảo (Targeted, cả IP)** nằm ngoài phạm vi chấm điểm theo thuộc tính đăng nhập —
   giới hạn kiến trúc đã biết từ MR6, không phải thiếu sót có thể vá bằng tinh chỉnh.
6. **5 luật ở chế độ `shadow`** (`regular_rhythm`, `country_hop`, `rare_network_login`, `datacenter_ip`, `vpn_ip`)
   chưa được kiểm chứng đủ trên log thật để bật `enforce` — vẫn là bằng chứng cho hybrid nhưng không tự báo alert
   riêng.
7. **7/9 kịch bản MR18 không dịch được sang dữ liệu tầng 3** (không có đặc trưng IP/ASN/tốc độ ở `ml/features.py`) —
   tầng 3 chỉ "thấy" được phần hành vi địa lý/thời gian của một cuộc tấn công, không thấy phần hạ tầng/tốc độ.

## Nguồn dữ liệu

Mọi con số trong bảng lấy TRỰC TIẾP từ tài liệu đã dẫn — không tính lại riêng cho bảng này. `[Đo được thật]` nghĩa là
có ít nhất một lần chạy qua CHÍNH pipeline thật (không phải suy luận từ thiết kế); ô để trống (`—`) ở cột cuối nghĩa
là cơ chế tồn tại nhưng chưa có phép đo chuyên biệt bằng kịch bản mô phỏng (khác với luật không được kích hoạt).
