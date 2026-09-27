# Hybrid risk engine — hiệu chỉnh trên RBA (MR11)

> Báo cáo TỰ SINH bởi `python -m ml.rba.hybrid_calibrate` — đừng sửa tay. Mã: [`hybrid_calibrate.py`](../backend/ml/rba/hybrid_calibrate.py), bộ gộp dùng lúc chấm điểm: [`app/detection/hybrid/combine.py`](../backend/app/detection/hybrid/combine.py). Hồ sơ: [`profiles/rba_calibrated.json`](../backend/app/detection/hybrid/profiles/rba_calibrated.json).

## 1. Cách làm

- **Điểm = noisy-OR có trọng số** của ba nguồn: xác suất mô hình `hybrid_cp2` đã hiệu chỉnh (hồi quy isotonic trên `attack_ip/val`), xác suất gộp của các luật KHÔNG thuộc nhóm danh tiếng, xác suất gộp của nhóm "Danh tiếng hạ tầng" (Tor/datacenter/VPN/blocklist). `P = 1 − (1−p_ml)(1−p_luật)(1−p_danh_tiếng)`; luật `blocklist_hit` GHI ĐÈ (điểm 100, hành động `lock`) vì đó là quyết định của quản trị viên, không phải bằng chứng xác suất.
- **Trọng số một luật** = độ chính xác đo trên `val` khi luật khớp ở bậc MẶC ĐỊNH của sổ đăng ký (dùng lại `levels.parquet` của MR10, KHÔNG replay lại): "nếu chỉ một mình luật này khớp, khả năng đúng là bao nhiêu" — dùng làm bằng chứng độc lập trong noisy-OR. ⚠️ KHÁC câu hỏi MR10 đã trả lời ("luật cộng thêm bao nhiêu recall khi ĐàCÓ mô hình", câu đó gần 0) — ở đây là độ tin cậy của luật khi ĐỨNG MỘT MÌNH, dùng để giải thích cảnh báo.
- Luật `shadow` (`country_hop`, `rare_network_login`, `regular_rhythm`, `datacenter_ip`, `vpn_ip`) vẫn là bằng chứng đầy đủ ở đây: chế độ shadow chỉ quyết định rule engine có TỰ tạo cảnh báo hay không (MR9), không phải luật vô giá trị.
- **Ngưỡng hành động** (0–100): chọn trên đăng nhập hợp lệ THÀNH CÔNG của `val` cho ba FPR mục tiêu ĐẶT TRƯỚC — 1% (`alert`) và 0,1% (`step_up`) trùng hai ngưỡng vận hành đã công bố của `hybrid_cp2` (model-card-rba.md); 0,01% (`lock`) là mức mới, chặt hơn, cho khoá tạm.

**Chất lượng hiệu chỉnh mô hình** (n=199,114 dòng val, tỉ lệ tấn công 8.399%): Brier sau hiệu chỉnh **0.0607** so với đoán theo tỉ lệ trung bình 0.0769 (thấp hơn = tốt hơn).

**Ngưỡng hành động:** `alert_at` = 32, `step_up_at` = 58, `lock_at` = 70 (thang 0–100).

## 2. Trọng số từng luật

| Luật | Nhóm | Trọng số | Đo được trên RBA? | n (dòng khớp ở val) |
|---|---|---|---|---|
| `brute_force` | Đoán và dò mật khẩu | 10.1%  [0.0%–26.3%] | có | 275 |
| `credential_stuffing` | Đoán và dò mật khẩu | 34.6%  [30.2%–40.0%] | có | 7,111 |
| `password_spray_slow` | Đoán và dò mật khẩu | 10.2%  [7.6%–13.3%] | có | 7,289 |
| `distributed_bruteforce` | Đoán và dò mật khẩu | 0.0%  [0.0%–0.0%] | có | 2 |
| `success_after_failures` | Đoán và dò mật khẩu | 0.0%  [0.0%–0.0%] | có | 40 |
| `ua_rotation` | Tự động hoá | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `dormant_account_login` | Ngữ cảnh tài khoản | 2.5%  [1.6%–3.6%] | có | 10,380 |
| `rare_network_login` | Ngữ cảnh tài khoản | 2.6%  [0.3%–5.2%] | có | 1,874 |
| `multi_context_simultaneous` | Ngữ cảnh tài khoản | 0.0%  [0.0%–0.0%] | có | 96 |
| `country_hop` | Ngữ cảnh tài khoản | 0.0%  [0.0%–0.0%] | có | 58 |
| `bot_user_agent` | Tự động hoá | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `scripted_client` | Tự động hoá | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `username_enumeration` | Đoán và dò mật khẩu | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `regular_rhythm` | Tự động hoá | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `impossible_travel` | Ngữ cảnh tài khoản | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `tor_exit` | Danh tiếng hạ tầng | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `datacenter_ip` | Danh tiếng hạ tầng | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `vpn_ip` | Danh tiếng hạ tầng | 5.0% | KHÔNG (giá trị đặt trước) | 0 |
| `blocklist_hit` | Danh tiếng hạ tầng | 5.0% | KHÔNG (giá trị đặt trước) | 0 |

## 3. Chuyển miền (val → test/late trong RBA; xem thêm mục 4 cho kẻ tấn công mô phỏng)

Recall "≥ mức" = tỉ lệ (trọng số) dòng dương tính đạt hành động đó HOẶC chặt hơn; ngưỡng chọn trên val, áp THẲNG sang test/late/ATO — không hiệu chỉnh lại.

⚠️ **So sánh phải công bằng:** điểm gộp luôn ≥ điểm chỉ-ML tại mọi dòng (bằng chứng luật chỉ CỘNG THÊM xác suất), nên so ở CÙNG một ngưỡng tuyệt đối luôn có lợi máy móc cho bộ gộp — không phải bằng chứng luật có ích (bài học từ MR10). Vì vậy cột "Chỉ ML" dưới đây dùng NGƯỠNG RIÊNG của một mình mô hình, hiệu chỉnh ở CÙNG BA FPR MỤC TIÊU trên val (`alert_at`=30, `step_up_at`=57, `lock_at`=70 — khác ngưỡng triển khai thật ở mục 1), không phải ngưỡng gộp — so sánh này mới trả lời được "luật có thêm giá trị ngoài việc chỉ nới ngưỡng mô hình" hay không.

### `attack_ip/test` (n dương = 5,709)

| Bộ | ≥ alert | ≥ step_up | = lock |
|---|---|---|---|
| Gộp (luật + ML, ngưỡng triển khai) | 43.4% [41.0%–45.9%] | 4.1% [2.5%–6.0%] | 2.2% [1.1%–3.6%] |
| Chỉ ML (ngưỡng riêng, cùng FPR mục tiêu) | 11.7% [8.1%–15.5%] | 4.0% [2.4%–5.9%] | 2.2% [1.1%–3.6%] |

### `attack_ip/late` (n dương = 7,137)

| Bộ | ≥ alert | ≥ step_up | = lock |
|---|---|---|---|
| Gộp (luật + ML, ngưỡng triển khai) | 46.1% [44.0%–48.2%] | 2.1% [1.3%–3.2%] | 1.2% [0.6%–1.9%] |
| Chỉ ML (ngưỡng riêng, cùng FPR mục tiêu) | 6.7% [4.8%–9.1%] | 2.2% [1.2%–3.3%] | 1.2% [0.6%–1.9%] |

### `ato/future` (n dương = 38)

| Bộ | ≥ alert | ≥ step_up | = lock |
|---|---|---|---|
| Gộp (luật + ML, ngưỡng triển khai) | 36.8% [22.3%–50.0%] | 7.9% [0.0%–15.8%] | 0.0% [0.0%–0.0%] |
| Chỉ ML (ngưỡng riêng, cùng FPR mục tiêu) | 31.6% [18.4%–47.4%] | 7.9% [0.0%–15.8%] | 0.0% [0.0%–0.0%] |

### `ato/all` (n dương = 130)

| Bộ | ≥ alert | ≥ step_up | = lock |
|---|---|---|---|
| Gộp (luật + ML, ngưỡng triển khai) | 29.2% [21.5%–36.4%] | 6.9% [3.0%–11.6%] | 0.0% [0.0%–0.0%] |
| Chỉ ML (ngưỡng riêng, cùng FPR mục tiêu) | 26.2% [18.6%–34.0%] | 6.2% [2.3%–10.9%] | 0.0% [0.0%–0.0%] |

**Vì sao khác kết luận của MR10 (`docs/rule-ml-overlap.md`: gộp không tăng recall ở cùng ngân sách báo nhầm)?** MR10 so hai bộ luật CỰC ĐOAN: mặc định (union thô, ngân sách báo nhầm ~18,6% — quá lớn để so công bằng) và đã tinh chỉnh riêng lẻ theo ngân sách 5/10.000 (mỗi luật gần như không còn recall một mình: bộ `tuned_enforce` chỉ 0,3% recall đứng riêng). ĐÂY khác: dùng NGUYÊN luật mặc định (nhiều recall hơn hẳn khi đứng riêng) nhưng KHÔNG lấy union thô — mỗi luật đóng góp theo ĐÚNG độ chính xác đo được (trọng số nhỏ với luật ồn), rồi ngưỡng của điểm GỘP (không phải của từng luật) được hiệu chỉnh để tự nó đạt đúng 1%/0,1%/0,01% FPR. Nhờ vậy ở mức `alert` (ngân sách lỏng nhất), phần recall thêm từ luật là THẬT (không chỉ vì union thô đốt ngân sách): 43,4% so với 11,7% trên `attack_ip/test`. Ở mức `step_up`/`lock` (ngân sách chặt), phần thêm gần như biến mất — khớp với MR10: một khi điểm ML đã đủ cao, thêm bằng chứng luật hiếm khi đổi kết quả.

## 4. Kẻ tấn công mô phỏng — CẬN DƯỚI (chỉ thành phần ML)

⚠️ Rule engine chưa từng chạy trên dòng kẻ tấn công mô phỏng (chúng không nằm trong luồng sự kiện đã replay ở MR9/10); số dưới đây giả định KHÔNG luật nào khớp, nên là CẬN DƯỚI của tỉ lệ đạt mỗi hành động — bằng chứng thật (nếu có) chỉ làm tăng, không giảm. Dùng ngưỡng TRIỂN KHAI THẬT ở mục 1 (không phải ngưỡng riêng của mục 3): câu hỏi ở đây là "hệ thống thật sẽ làm gì", không phải so sánh công bằng luật/ML.

| Loại | n | allow | alert | step_up | lock |
|---|---|---|---|---|---|
| `naive` | 2,000 | 68.0% | 13.9% | 11.2% | 6.9% |
| `vpn` | 1,995 | 77.2% | 11.1% | 8.7% | 3.0% |
| `targeted` | 1,916 | 93.4% | 4.8% | 1.8% | 0.0% |

## 5. Giới hạn

- Trọng số luật hiệu chỉnh với luật ở CẤU HÌNH MẶC ĐỊNH của sổ đăng ký, không phải hồ sơ đã tinh chỉnh của MR10 (xem `docs/rule-tuning.md`); nếu đổi cấu hình luật thì trọng số cần hiệu chỉnh lại.
- Bốn luật nhóm "Danh tiếng hạ tầng" và ba luật khác (`username_enumeration`, `regular_rhythm`, `impossible_travel`) không đánh giá được trên RBA (IP tổng hợp, không toạ độ, tên không tồn tại bị gộp — `docs/rule-tuning.md` mục 6): trọng số của chúng là giá trị đặt trước, và trong mọi số đo ở mục 3–4, thành phần "danh tiếng" luôn bằng 0 (không có dòng RBA nào để bốn luật đó khớp).
- Đường ghi đè (`blocklist_hit`) không kiểm được trên RBA (blocklist rỗng khi replay) — chỉ kiểm bằng unit test tổng hợp (`tests/test_hybrid_combine.py`).
- Chuyển miền sang "live" (log thật của web app mẫu) CHƯA làm được: cần pipeline tính đặc trưng RBA và chạy rule engine trên `login_events`, việc đó thuộc MR12 (tích hợp realtime).
- 38 ATO tương lai đã bị nhìn ở MR7 (chỉ xác nhận, không phải kiểm định độc lập); ATO của RBA có đặc điểm nhân tạo (nhà mạng hiếm — xem `rare_network_login`).
