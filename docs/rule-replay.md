# Replay rule engine v2 trên RBA

> Báo cáo TỰ SINH, đừng sửa tay. Sinh lại: `python -m app.detection.engine.replay rba --start 2020-02-03 --end 2020-08-01 --out <tệp.md>`

## 1. Dữ liệu và cách chạy

- **Nguồn:** RBA (tổng hợp, không phải log thật) — rba_full.parquet
- **Khoảng thời gian:** 2020-02-03 12:43:30 → 2020-07-31 23:59:50 (UTC), 179.5 ngày
- **Số lần thử:** 12,957,314 (5,919,605 thành công, 7,037,709 thất bại); không nhãn 11,728,367 (trong đó 5,559,076 đăng nhập thành công không nhãn — mẫu số của cột "/10.000")
- **Nhãn `is_attack_ip`:** 1,228,909 dòng từ 46,780 IP khác nhau
- **Nhãn `is_ato`:** 86 dòng từ 71 IP khác nhau
- **Thứ tự thời gian:** 0 lần thử có thời gian nhỏ hơn lần trước (nguồn đã sắp đúng thứ tự)
- **Tốc độ:** 7,204 lần thử/giây trên một tiến trình Python (1,799 giây); độ trễ engine mỗi lần thử: trung bình 0.12 ms, p50 0.10, p95 0.20, p99 0.30, lớn nhất 1396.1 ms
- **Bộ nhớ khi kết thúc:** 571,810 khoá cửa sổ còn giữ (khoá quá hạn được dọn), 2,492,848 tài khoản trong lịch sử, tiến trình 1,539 MB
- **Cấu hình:** mặc định của sổ đăng ký (chưa tinh chỉnh)
- RBA là bộ dữ liệu TỔNG HỢP (Wiefling và cộng sự, CC BY 4.0), không phải log thật: IP, nhà mạng và User-Agent đều là giá trị tổng hợp/ẩn danh. `is_attack_ip` = IP thuộc danh sách IP tấn công do người tạo bộ dữ liệu gắn; `is_ato` = 141 vụ chiếm đoạt tài khoản do họ gắn. Dòng không nhãn được coi là hợp lệ — giả định, không chắc chắn: nhà mạng có phần lớn dòng mang nhãn tấn công thì phần còn lại của nó chưa chắc hợp lệ, nên số "báo nhầm" của luật theo nhà mạng (phạm vi ASN) là CẬN TRÊN.
- RBA không có tên đăng nhập, chỉ có `user_id`; mọi lần thử vào tên KHÔNG tồn tại (user_id -4324475583306591935, chiếm 45% số dòng của toàn bộ RBA) được chuyển thành `user_key = None` với tên giả cho từng lần thử (cận TRÊN của số tên khác nhau), vì không biết tên thật. RBA không có toạ độ; có ASN (một phần là ASN nhân tạo ≥ 500000, vẫn dùng như định danh nhà mạng).
- Theo thẻ dữ liệu (docs/rba-data-card.md): timestamp có thành phần ngẫu nhiên — thứ tự và cửa sổ thô (giờ, ngày) đáng tin, cửa sổ vài phút và nhịp cách nhau vài giây chỉ là gần đúng; quốc gia bị gán ngẫu nhiên theo giá trị nên chỉ dùng được "giống hay khác", không có khoảng cách. Thời gian được coi là UTC (luật chỉ dùng khoảng cách giữa các mốc).

## 2. Số lần khớp và báo nhầm

"Báo nhầm" = khớp trên dòng KHÔNG nhãn (giả định hợp lệ). "/10.000" = số lần khớp trên dòng không nhãn, chia cho số đăng nhập thành công không nhãn, nhân 10.000. Một luật khớp tối đa một lần cho mỗi lần thử; chưa gộp cảnh báo trùng (MR13), nên luật báo ở MỖI lần thất bại sau khi chạm ngưỡng cho số lớn — cột "IP không nhãn bị khớp" (số nguồn khác nhau) phản ánh khối lượng cảnh báo sau khi gộp theo IP.

| Luật | Chế độ | Chạy | Bỏ qua | Khớp | Khớp: thành công / thất bại | Khớp trên dòng không nhãn | IP không nhãn bị khớp | /10.000 | Khớp/ngày (không nhãn) |
|---|---|---:|---:|---:|---|---:|---:|---:|---:|
| `brute_force` | enforce | 12,957,314 | 0 | 11,344 | 0 / 11,344 | 9,338 | 3,124 | 16.8 | 52 |
| `credential_stuffing` | enforce | 12,957,314 | 0 | 1,277,523 | 0 / 1,277,523 | 918,411 | 14,508 | 1,652.1 | 5,117 |
| `password_spray_slow` | enforce | 12,957,314 | 0 | 2,133,877 | 0 / 2,133,877 | 1,957,285 | 474,939 | 3,520.9 | 10,906 |
| `distributed_bruteforce` | enforce | 12,957,314 | 0 | 131 | 0 / 131 | 40 | 30 | 0.1 | 0 |
| `username_enumeration` | enforce | 12,957,314 | 0 | 115,281 | 0 / 115,281 | 107,188 | 8,535 | 192.8 | 597 |
| `success_after_failures` | enforce | 8,014,962 | 4,942,352 | 1,133 | 1,133 / 0 | 999 | 670 | 1.8 | 6 |
| `bot_user_agent` | enforce | 12,957,314 | 0 | 78,091 | 24 / 78,067 | 68,643 | 1,650 | 123.5 | 382 |
| `scripted_client` | enforce | 12,957,314 | 0 | 1,822 | 36 / 1,786 | 1,522 | 1,013 | 2.7 | 8 |
| `ua_rotation` | enforce | 12,957,314 | 0 | 2,037 | 0 / 2,037 | 836 | 7 | 1.5 | 5 |
| `regular_rhythm` | shadow | 12,957,314 | 0 | 230 | 0 / 230 | 223 | 29 | 0.4 | 1 |
| `impossible_travel` | enforce | 0 | 12,957,314 ⚠️ | 0 | 0 / 0 | 0 | 0 | 0.0 | 0 |
| `multi_context_simultaneous` | enforce | 8,014,962 | 4,942,352 | 3,268 | 3,268 / 0 | 2,930 | 2,112 | 5.3 | 16 |
| `country_hop` | shadow | 12,957,314 | 0 | 1,351 | 577 / 774 | 727 | 383 | 1.3 | 4 |
| `dormant_account_login` | enforce | 5,522,114 | 7,435,200 | 118,689 | 118,689 / 0 | 115,547 | 91,916 | 207.9 | 644 |
| `rare_network_login` | shadow | 8,014,962 | 4,942,352 | 71,514 | 71,514 / 0 | 67,334 | 27,333 | 121.1 | 375 |
| `tor_exit` | enforce | 0 | 12,957,314 ⚠️ | 0 | 0 / 0 | 0 | 0 | 0.0 | 0 |
| `datacenter_ip` | shadow | 0 | 12,957,314 ⚠️ | 0 | 0 / 0 | 0 | 0 | 0.0 | 0 |
| `vpn_ip` | shadow | 0 | 12,957,314 ⚠️ | 0 | 0 / 0 | 0 | 0 | 0.0 | 0 |
| `blocklist_hit` | enforce | 12,957,314 | 0 | 0 | 0 / 0 | 0 | 0 | 0.0 | 0 |
| **bất kỳ luật `enforce` nào** | — | 12,957,314 | — | 3,550,449 | 123,136 / 3,427,313 | 3,013,577 | 567,619 | 5,421.0 | 16,792 |
| **bất kỳ luật nào (kể cả shadow)** | — | 12,957,314 | — | 3,621,191 | 193,736 / 3,427,455 | 3,080,162 | 593,616 | 5,540.8 | 17,163 |

Luật có nhiều phạm vi (IP, ASN) — số lần khớp chia theo phạm vi:

| Luật | Phạm vi | Khớp | Trên dòng không nhãn | Tỉ lệ không nhãn |
|---|---|---:|---:|---:|
| `credential_stuffing` | asn | 1,250,524 | 895,867 | 71.6% |
| `credential_stuffing` | ip | 26,999 | 22,544 | 83.5% |
| `password_spray_slow` | asn | 1,437,908 | 1,303,974 | 90.7% |
| `password_spray_slow` | ip | 695,969 | 653,311 | 93.9% |

## 3. Phát hiện theo nhãn

"Dòng" = tỉ lệ dòng mang nhãn mà luật khớp; "IP" = tỉ lệ IP mang nhãn mà luật khớp ÍT NHẤT MỘT lần (thước đo dễ tính hơn: luật chỉ cần bắt một lần để kịp chặn). Độ phủ của một luật trên dòng có nhãn KHÔNG phải độ chính xác: xem cột "/10.000" ở mục 2.

| Luật | `is_attack_ip`: dòng | `is_attack_ip`: IP | `is_ato`: dòng | `is_ato`: IP |
|---|---:|---:|---:|---:|
| `brute_force` | 0.2% (2,006) | 1.2% | 0.0% (0) | 0.0% |
| `credential_stuffing` | 29.2% (359,112) | 2.7% | 0.0% (0) | 0.0% |
| `password_spray_slow` | 14.4% (176,592) | 34.5% | 0.0% (0) | 0.0% |
| `distributed_bruteforce` | 0.0% (91) | 0.1% | 0.0% (0) | 0.0% |
| `username_enumeration` | 0.7% (8,093) | 2.4% | 0.0% (0) | 0.0% |
| `success_after_failures` | 0.0% (134) | 0.2% | 0.0% (0) | 0.0% |
| `bot_user_agent` | 0.8% (9,448) | 2.0% | 0.0% (0) | 0.0% |
| `scripted_client` | 0.0% (300) | 0.5% | 0.0% (0) | 0.0% |
| `ua_rotation` | 0.1% (1,201) | 0.0% | 0.0% (0) | 0.0% |
| `regular_rhythm` | 0.0% (7) | 0.0% | 0.0% (0) | 0.0% |
| `impossible_travel` | 0.0% (0) | 0.0% | 0.0% (0) | 0.0% |
| `multi_context_simultaneous` | 0.0% (337) | 0.5% | 3.5% (3) | 4.2% |
| `country_hop` | 0.1% (621) | 0.2% | 3.5% (3) | 4.2% |
| `dormant_account_login` | 0.3% (3,140) | 4.0% | 5.8% (5) | 7.0% |
| `rare_network_login` | 0.3% (4,164) | 3.1% | 66.3% (57) | 66.2% |
| `tor_exit` | 0.0% (0) | 0.0% | 0.0% (0) | 0.0% |
| `datacenter_ip` | 0.0% (0) | 0.0% | 0.0% (0) | 0.0% |
| `vpn_ip` | 0.0% (0) | 0.0% | 0.0% (0) | 0.0% |
| `blocklist_hit` | 0.0% (0) | 0.0% | 0.0% (0) | 0.0% |
| **bất kỳ luật `enforce` nào** | 43.7% (536,869) | 37.8% | 9.3% (8) | 11.3% |
| **bất kỳ luật nào (kể cả shadow)** | 44.0% (541,010) | 40.7% | 70.9% (61) | 71.8% |

## 4. Luật bị bỏ qua hoặc lỗi

| Luật | Số lần bỏ qua | Lý do | Lỗi |
|---|---:|---|---|
| `success_after_failures` | 4,942,352 | thiếu tài khoản tồn tại (không phải tên đăng nhập bịa) (4,942,352) | — |
| `impossible_travel` | 12,957,314 | thiếu toạ độ của IP (GeoLite2-City) (8,014,962); thiếu tài khoản tồn tại (không phải tên đăng nhập bịa) (4,942,352) | — |
| `multi_context_simultaneous` | 4,942,352 | thiếu tài khoản tồn tại (không phải tên đăng nhập bịa) (4,942,352) | — |
| `dormant_account_login` | 7,435,200 | thiếu tài khoản tồn tại (không phải tên đăng nhập bịa) (4,942,352); thiếu lịch sử tài khoản (DB hoặc luồng sự kiện đã phát) (2,492,848) | — |
| `rare_network_login` | 4,942,352 | thiếu tài khoản tồn tại (không phải tên đăng nhập bịa) (4,942,352) | — |
| `tor_exit` | 12,957,314 | thiếu danh sách Tor exit node (python -m scripts.update_threat_feeds) (12,957,314) | — |
| `datacenter_ip` | 12,957,314 | thiếu danh sách dải IP datacenter (12,957,314) | — |
| `vpn_ip` | 12,957,314 | thiếu danh sách dải IP VPN (12,957,314) | — |

## 5. Lưu ý riêng của nguồn dữ liệu

| Luật | Lưu ý |
|---|---|
| `brute_force` | Tên đăng nhập là `user_id`. Lần thử vào tên không tồn tại có tên giả riêng cho từng lần nên không bao giờ chạm ngưỡng theo tên: luật chỉ thấy dò mật khẩu tài khoản CÓ THẬT. |
| `credential_stuffing` | Số tên khác nhau của một IP/ASN bị THỔI PHỒNG: mỗi lần sai vào tên không tồn tại được đếm như một tên mới (RBA gộp các tên đó nên không phân biệt được). |
| `password_spray_slow` | Số tên khác nhau bị thổi phồng như `credential_stuffing` (mỗi lần sai vào tên không tồn tại đếm như một tên mới). |
| `distributed_bruteforce` | Chỉ thấy tài khoản có thật (tên giả của lần thử vào tên không tồn tại không bao giờ trùng giữa các IP). |
| `username_enumeration` | Chỉ là cận trên, không kiểm chứng được: RBA gộp mọi tên không tồn tại vào một `user_id`, adapter đặt tên giả riêng cho từng lần thử nên IP có nhiều lần sai vào tên không tồn tại đều trông như đang dò nhiều tên. |
| `success_after_failures` | Chỉ áp dụng cho tài khoản có thật; đếm lần sai theo `user_id`. |
| `bot_user_agent` | `device_type = bot` do thư viện phân tích UA của bộ dữ liệu gán (~6,5% số dòng trên toàn bộ RBA); không đồng nghĩa với tấn công. |
| `scripted_client` | User-Agent của RBA gồm chuỗi trình duyệt tổng hợp và một số chuỗi công cụ/bot có thật (python-requests, Java, các bot thu thập) do bộ dữ liệu gắn cho lưu lượng bot; tỉ lệ và cách dùng công cụ trong log thật sẽ khác nên kết quả không suy ra được cho lưu lượng thật. |
| `regular_rhythm` | Nhịp vài giây không đáng tin trên RBA vì timestamp có thành phần ngẫu nhiên (thẻ dữ liệu); luật shadow, kết quả không nói lên hiệu quả với log thật. |
| `impossible_travel` | Không đánh giá được: RBA không có toạ độ nên luật bị bỏ qua vì thiếu `geo`. |
| `multi_context_simultaneous` | Quốc gia của RBA gán ngẫu nhiên theo giá trị (chỉ dùng được "khác nhau") và cửa sổ 10 phút chịu thành phần ngẫu nhiên của timestamp. |
| `country_hop` | Quốc gia của RBA gán ngẫu nhiên theo giá trị: chỉ dùng được "khác nhau", không phản ánh di chuyển thật. |
| `dormant_account_login` | Điều kiện "thiết bị mới" gần như luôn đúng trên RBA: User-Agent tổng hợp đổi liên tục (khoảng 52% đăng nhập hợp lệ có UA chưa từng thấy ở tài khoản, docs/rba-evaluation.md) nên số báo nhầm bị THỔI PHỒNG; luật cần lịch sử ≥ 90 ngày của chính tài khoản trong lần chạy nên chỉ khớp được từ ngày thứ 90 kể từ đầu lần chạy. |
| `rare_network_login` | Đánh giá mang tính VÒNG TRÒN: ATO của RBA đến từ nhà mạng hiếm một cách nhân tạo (xem ghi chú luật và docs/rba-data-card.md). Giá trị thật đo bằng mô phỏng ở MR18. |
| `tor_exit` | Không đánh giá được: IP trong RBA là tổng hợp nên danh sách Tor công khai không áp dụng (mặc định chưa nạp danh sách → luật bị bỏ qua). |
| `datacenter_ip` | Không đánh giá được: IP trong RBA là tổng hợp nên danh sách datacenter công khai không áp dụng (mặc định chưa nạp danh sách → luật bị bỏ qua). |
| `vpn_ip` | Không đánh giá được: IP trong RBA là tổng hợp nên danh sách VPN công khai không áp dụng (mặc định chưa nạp danh sách → luật bị bỏ qua). |
| `blocklist_hit` | Không áp dụng: blocklist rỗng trong replay (không có quản trị viên nào đặt mục chặn). |

## 6. Ví dụ (đọc để hiểu luật khớp ở đâu, không phải mẫu đại diện)

- `brute_force` (trên dòng có nhãn) 2020-02-04 03:21:42 · 188.116.36.168 · `5955841859812228872` · thất bại — Dò mật khẩu '5955841859812228872': 5 lần sai/5 phút (ngưỡng 5).
- `brute_force` (trên dòng có nhãn) 2020-02-04 04:54:21 · 66.248.237.143 · `6284528728997198756` · thất bại — Dò mật khẩu '6284528728997198756': 5 lần sai/5 phút (ngưỡng 5).
- `brute_force` (trên dòng có nhãn) 2020-02-04 15:32:08 · 209.236.117.126 · `666580368949218065` · thất bại — Dò mật khẩu '666580368949218065': 5 lần sai/5 phút (ngưỡng 5).
- `brute_force` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:36:10 · 109.247.52.197 · `8578757305244579057` · thất bại — Dò mật khẩu '8578757305244579057': 5 lần sai/5 phút (ngưỡng 5).
- `brute_force` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:48:27 · 139.164.143.46 · `1015865328882831091` · thất bại — Dò mật khẩu '1015865328882831091': 5 lần sai/5 phút (ngưỡng 5).
- `brute_force` (trên dòng không nhãn — báo nhầm) 2020-02-03 14:36:43 · 212.8.251.254 · `-2145592600608307367` · thất bại — Dò mật khẩu '-2145592600608307367': 5 lần sai/5 phút (ngưỡng 5).
- `credential_stuffing` (trên dòng có nhãn) 2020-02-03 12:50:46 · 66.248.237.23 · `?488` · thất bại — ASN 393398 thử 40 tài khoản khác nhau, 40 lần sai/5 phút (ngưỡng 20 TK / 40 lần).
- `credential_stuffing` (trên dòng có nhãn) 2020-02-03 12:50:46 · 66.248.237.177 · `-4382863011087706525` · thất bại — ASN 393398 thử 40 tài khoản khác nhau, 41 lần sai/5 phút (ngưỡng 20 TK / 40 lần).
- `credential_stuffing` (trên dòng có nhãn) 2020-02-03 12:50:53 · 66.248.237.86 · `?501` · thất bại — ASN 393398 thử 41 tài khoản khác nhau, 42 lần sai/5 phút (ngưỡng 20 TK / 40 lần).
- `credential_stuffing` (trên dòng không nhãn — báo nhầm) 2020-02-03 12:50:39 · 170.39.76.12 · `1349386967657679351` · thất bại — ASN 393398 thử 40 tài khoản khác nhau, 40 lần sai/5 phút (ngưỡng 20 TK / 40 lần).
- `credential_stuffing` (trên dòng không nhãn — báo nhầm) 2020-02-03 12:50:49 · 170.39.78.28 · `?492` · thất bại — ASN 393398 thử 41 tài khoản khác nhau, 42 lần sai/5 phút (ngưỡng 20 TK / 40 lần).
- `credential_stuffing` (trên dòng không nhãn — báo nhầm) 2020-02-03 12:51:26 · 170.39.76.53 · `-8370145398639134653` · thất bại — ASN 393398 thử 39 tài khoản khác nhau, 40 lần sai/5 phút (ngưỡng 20 TK / 40 lần).
- `password_spray_slow` (trên dòng có nhãn) 2020-02-03 12:49:25 · 66.248.237.166 · `-3195202553993376366` · thất bại — ASN 393398 thử 40 tài khoản trong 24 giờ, mỗi tài khoản ≤ 3 lần: rải mật khẩu qua nhiều IP.
- `password_spray_slow` (trên dòng có nhãn) 2020-02-03 12:49:36 · 38.135.39.47 · `8825144655502918256` · thất bại — ASN 393398 thử 41 tài khoản trong 24 giờ, mỗi tài khoản ≤ 3 lần: rải mật khẩu qua nhiều IP.
- `password_spray_slow` (trên dòng có nhãn) 2020-02-03 12:50:46 · 66.248.237.23 · `?488` · thất bại — ASN 393398 thử 52 tài khoản trong 24 giờ, mỗi tài khoản ≤ 3 lần: rải mật khẩu qua nhiều IP.
- `password_spray_slow` (trên dòng không nhãn — báo nhầm) 2020-02-03 12:48:11 · 156.52.83.9 · `?299` · thất bại — ASN 29695 thử 40 tài khoản trong 24 giờ, mỗi tài khoản ≤ 3 lần: rải mật khẩu qua nhiều IP.
- `password_spray_slow` (trên dòng không nhãn — báo nhầm) 2020-02-03 12:48:18 · 109.247.40.98 · `-5040153906075840422` · thất bại — ASN 29695 thử 41 tài khoản trong 24 giờ, mỗi tài khoản ≤ 3 lần: rải mật khẩu qua nhiều IP.
- `password_spray_slow` (trên dòng không nhãn — báo nhầm) 2020-02-03 12:48:27 · 156.52.26.234 · `?315` · thất bại — ASN 29695 thử 42 tài khoản trong 24 giờ, mỗi tài khoản ≤ 3 lần: rải mật khẩu qua nhiều IP.
- `distributed_bruteforce` (trên dòng có nhãn) 2020-02-18 11:47:07 · 10.0.3.90 · `-1700404434109112095` · thất bại — Tài khoản '-1700404434109112095' bị 8 lần sai từ 7 IP khác nhau/60 phút (dò phân tán; ngưỡng 5 IP / 8 lần).
- `distributed_bruteforce` (trên dòng có nhãn) 2020-02-18 11:47:07 · 10.0.3.255 · `-1700404434109112095` · thất bại — Tài khoản '-1700404434109112095' bị 9 lần sai từ 7 IP khác nhau/60 phút (dò phân tán; ngưỡng 5 IP / 8 lần).
- `distributed_bruteforce` (trên dòng có nhãn) 2020-02-19 14:55:49 · 10.0.3.87 · `5092097438364757091` · thất bại — Tài khoản '5092097438364757091' bị 13 lần sai từ 5 IP khác nhau/60 phút (dò phân tán; ngưỡng 5 IP / 8 lần).
- `distributed_bruteforce` (trên dòng không nhãn — báo nhầm) 2020-02-27 11:40:05 · 46.212.219.235 · `4613732175576721141` · thất bại — Tài khoản '4613732175576721141' bị 11 lần sai từ 5 IP khác nhau/60 phút (dò phân tán; ngưỡng 5 IP / 8 lần).
- `distributed_bruteforce` (trên dòng không nhãn — báo nhầm) 2020-03-10 05:54:29 · 176.107.156.135 · `-833552365251048055` · thất bại — Tài khoản '-833552365251048055' bị 8 lần sai từ 5 IP khác nhau/60 phút (dò phân tán; ngưỡng 5 IP / 8 lần).
- `distributed_bruteforce` (trên dòng không nhãn — báo nhầm) 2020-03-17 07:03:27 · 176.107.136.21 · `1449119677329605658` · thất bại — Tài khoản '1449119677329605658' bị 8 lần sai từ 6 IP khác nhau/60 phút (dò phân tán; ngưỡng 5 IP / 8 lần).
- `username_enumeration` (trên dòng có nhãn) 2020-02-03 14:05:06 · 209.236.125.82 · `?6780` · thất bại — IP 209.236.125.82 thử 8 tên đăng nhập không tồn tại/10 phút (dò danh sách tài khoản; ngưỡng 8).
- `username_enumeration` (trên dòng có nhãn) 2020-02-03 15:19:52 · 10.0.4.24 · `?13198` · thất bại — IP 10.0.4.24 thử 8 tên đăng nhập không tồn tại/10 phút (dò danh sách tài khoản; ngưỡng 8).
- `username_enumeration` (trên dòng có nhãn) 2020-02-03 15:22:29 · 10.0.4.23 · `?13439` · thất bại — IP 10.0.4.23 thử 8 tên đăng nhập không tồn tại/10 phút (dò danh sách tài khoản; ngưỡng 8).
- `username_enumeration` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:09:25 · 170.39.77.197 · `?1962` · thất bại — IP 170.39.77.197 thử 8 tên đăng nhập không tồn tại/10 phút (dò danh sách tài khoản; ngưỡng 8).
- `username_enumeration` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:18:15 · 10.0.110.44 · `?2745` · thất bại — IP 10.0.110.44 thử 8 tên đăng nhập không tồn tại/10 phút (dò danh sách tài khoản; ngưỡng 8).
- `username_enumeration` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:44:04 · 92.221.138.201 · `?4992` · thất bại — IP 92.221.138.201 thử 8 tên đăng nhập không tồn tại/10 phút (dò danh sách tài khoản; ngưỡng 8).
- `success_after_failures` (trên dòng có nhãn) 2020-02-03 18:51:39 · 38.135.39.170 · `8145562822160797599` · thành công — Đăng nhập thành công '8145562822160797599' sau 5 lần sai/10 phút từ 1 IP (có thể đã đoán trúng mật khẩu).
- `success_after_failures` (trên dòng có nhãn) 2020-02-04 04:55:13 · 66.248.237.143 · `6284528728997198756` · thành công — Đăng nhập thành công '6284528728997198756' sau 5 lần sai/10 phút từ 1 IP (có thể đã đoán trúng mật khẩu).
- `success_after_failures` (trên dòng có nhãn) 2020-02-05 12:00:46 · 10.0.11.231 · `1473374944184242980` · thành công — Đăng nhập thành công '1473374944184242980' sau 6 lần sai/10 phút từ 1 IP (có thể đã đoán trúng mật khẩu).
- `success_after_failures` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:38:53 · 92.221.38.248 · `-4178644299125349497` · thành công — Đăng nhập thành công '-4178644299125349497' sau 5 lần sai/10 phút từ 1 IP (có thể đã đoán trúng mật khẩu).
- `success_after_failures` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:50:14 · 139.164.143.46 · `1015865328882831091` · thành công — Đăng nhập thành công '1015865328882831091' sau 5 lần sai/10 phút từ 1 IP (có thể đã đoán trúng mật khẩu).
- `success_after_failures` (trên dòng không nhãn — báo nhầm) 2020-02-03 16:50:03 · 77.222.220.228 · `-3354783701641589653` · thành công — Đăng nhập thành công '-3354783701641589653' sau 5 lần sai/10 phút từ 1 IP (có thể đã đoán trúng mật khẩu).
- `bot_user_agent` (trên dòng có nhãn) 2020-02-03 12:58:24 · 10.0.3.150 · `?1097` · thất bại — User-Agent là bot/công cụ tự động: RankingBot2 -- https://github.com/das-group/rba-d….
- `bot_user_agent` (trên dòng có nhãn) 2020-02-03 15:37:10 · 185.237.250.88 · `?14677` · thất bại — User-Agent là bot/công cụ tự động: Mozilla/5.0 (compatible; SurdotlyBot/1.0; +https:….
- `bot_user_agent` (trên dòng có nhãn) 2020-02-03 15:58:18 · 10.0.3.226 · `?16426` · thất bại — User-Agent là bot/công cụ tự động: RankingBot2 -- https://github.com/das-group/rba-d….
- `bot_user_agent` (trên dòng không nhãn — báo nhầm) 2020-02-03 15:12:56 · 10.3.136.133 · `?12596` · thất bại — User-Agent là bot/công cụ tự động: Mozilla/5.0 (compatible; MetaJobBot; https://gith….
- `bot_user_agent` (trên dòng không nhãn — báo nhầm) 2020-02-03 15:12:57 · 103.68.137.21 · `?12600` · thất bại — User-Agent là bot/công cụ tự động: Mozilla/5.0 (compatible; MetaJobBot; https://gith….
- `bot_user_agent` (trên dòng không nhãn — báo nhầm) 2020-02-03 15:51:28 · 46.29.195.83 · `?15855` · thất bại — User-Agent là bot/công cụ tự động: Mozilla/5.0 (compatible; special_archiver/3.1.1 +….
- `scripted_client` (trên dòng có nhãn) 2020-02-06 18:04:08 · 188.116.36.239 · `?255400` · thất bại — Client kịch bản/công cụ 'java/': Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_202).
- `scripted_client` (trên dòng có nhãn) 2020-02-06 19:58:20 · 103.214.99.76 · `?263556` · thất bại — Client kịch bản/công cụ 'curl/': curl/7.52.1.
- `scripted_client` (trên dòng có nhãn) 2020-02-07 12:46:50 · 103.7.52.59 · `?306824` · thất bại — Client kịch bản/công cụ 'curl/': curl/7.52.1.
- `scripted_client` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:57:38 · 202.129.255.175 · `?6130` · thất bại — Client kịch bản/công cụ 'java/': Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_202).
- `scripted_client` (trên dòng không nhãn — báo nhầm) 2020-02-03 20:43:01 · 92.220.156.193 · `2658997216708235413` · thành công — Client kịch bản/công cụ 'headlesschrome': Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) A….
- `scripted_client` (trên dòng không nhãn — báo nhầm) 2020-02-04 06:23:57 · 170.39.77.212 · `?52522` · thất bại — Client kịch bản/công cụ 'java/': Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_202).
- `ua_rotation` (trên dòng có nhãn) 2020-07-10 18:05:49 · 89.251.69.48 · `?11463584` · thất bại — IP 89.251.69.48 đổi 5 User-Agent khác nhau trong 129 lần sai/10 phút (xoay UA để né nhận diện).
- `ua_rotation` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:59:31 · 10.0.77.226 · `?6289` · thất bại — IP 10.0.77.226 đổi 6 User-Agent khác nhau trong 8 lần sai/10 phút (xoay UA để né nhận diện).
- `ua_rotation` (trên dòng không nhãn — báo nhầm) 2020-02-09 09:16:24 · 79.160.194.212 · `?421735` · thất bại — IP 79.160.194.212 đổi 5 User-Agent khác nhau trong 8 lần sai/10 phút (xoay UA để né nhận diện).
- `ua_rotation` (trên dòng không nhãn — báo nhầm) 2020-03-02 14:31:26 · 190.111.112.141 · `?2121279` · thất bại — IP 190.111.112.141 đổi 8 User-Agent khác nhau trong 8 lần sai/10 phút (xoay UA để né nhận diện).
- `regular_rhythm` (trên dòng có nhãn) 2020-04-27 13:30:07 · 10.0.8.253 · `?6129373` · thất bại — IP 10.0.8.253: 10 lần sai gần nhất cách nhau đều ~2.10s (lệch 11%) — nhịp của máy.
- `regular_rhythm` (trên dòng có nhãn) 2020-05-20 07:52:27 · 185.53.155.173 · `?7788267` · thất bại — IP 185.53.155.173: 10 lần sai gần nhất cách nhau đều ~2.03s (lệch 7%) — nhịp của máy.
- `regular_rhythm` (trên dòng có nhãn) 2020-06-27 08:20:33 · 10.0.39.62 · `?10427842` · thất bại — IP 10.0.39.62: 10 lần sai gần nhất cách nhau đều ~1.78s (lệch 12%) — nhịp của máy.
- `regular_rhythm` (trên dòng không nhãn — báo nhầm) 2020-02-13 13:40:40 · 170.39.77.150 · `?768023` · thất bại — IP 170.39.77.150: 10 lần sai gần nhất cách nhau đều ~1.40s (lệch 15%) — nhịp của máy.
- `regular_rhythm` (trên dòng không nhãn — báo nhầm) 2020-02-18 08:00:40 · 193.227.122.39 · `?1118886` · thất bại — IP 193.227.122.39: 10 lần sai gần nhất cách nhau đều ~5.41s (lệch 9%) — nhịp của máy.
- `regular_rhythm` (trên dòng không nhãn — báo nhầm) 2020-02-19 16:29:01 · 10.3.84.247 · `?1238152` · thất bại — IP 10.3.84.247: 10 lần sai gần nhất cách nhau đều ~4.92s (lệch 10%) — nhịp của máy.
- `multi_context_simultaneous` (trên dòng có nhãn) 2020-02-03 18:04:27 · 10.0.22.67 · `-8869738254590967829` · thành công — Tài khoản '-8869738254590967829' đăng nhập thành công từ 2 quốc gia (NO, SI) trong 10 phút.
- `multi_context_simultaneous` (trên dòng có nhãn) 2020-02-03 20:26:34 · 10.0.34.126 · `-691021044583380055` · thành công — Tài khoản '-691021044583380055' đăng nhập thành công từ 2 quốc gia (NL, SK) trong 10 phút.
- `multi_context_simultaneous` (trên dòng có nhãn) 2020-02-04 13:20:26 · 91.229.249.251 · `5275342476876008525` · thành công — Tài khoản '5275342476876008525' đăng nhập thành công từ 2 quốc gia (ID, PL) trong 10 phút.
- `multi_context_simultaneous` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:35:50 · 113.21.67.250 · `5483971821854404030` · thành công — Tài khoản '5483971821854404030' đăng nhập thành công từ 2 quốc gia (IN, NO) trong 10 phút.
- `multi_context_simultaneous` (trên dòng không nhãn — báo nhầm) 2020-02-03 13:48:53 · 10.3.69.54 · `5453207491643834361` · thành công — Tài khoản '5453207491643834361' đăng nhập thành công từ 2 quốc gia (IR, NO) trong 10 phút.
- `multi_context_simultaneous` (trên dòng không nhãn — báo nhầm) 2020-02-03 15:19:38 · 10.0.159.39 · `6847955908981413121` · thành công — Tài khoản '6847955908981413121' đăng nhập thành công từ 2 quốc gia (ID, US) trong 10 phút.
- `country_hop` (trên dòng có nhãn) 2020-02-04 06:43:15 · 178.17.182.142 · `-4729570456393762911` · thành công — Tài khoản '-4729570456393762911' bị thử từ 3 quốc gia trong 24 giờ (ngưỡng 3).
- `country_hop` (trên dòng có nhãn) 2020-02-06 05:40:03 · 91.240.236.92 · `4130074439166519892` · thành công — Tài khoản '4130074439166519892' bị thử từ 4 quốc gia trong 24 giờ (ngưỡng 3).
- `country_hop` (trên dòng có nhãn) 2020-02-06 05:48:35 · 10.0.9.44 · `4130074439166519892` · thành công — Tài khoản '4130074439166519892' bị thử từ 4 quốc gia trong 24 giờ (ngưỡng 3).
- `country_hop` (trên dòng không nhãn — báo nhầm) 2020-02-04 20:24:27 · 10.2.61.67 · `9012483692226189510` · thành công — Tài khoản '9012483692226189510' bị thử từ 3 quốc gia trong 24 giờ (ngưỡng 3).
- `country_hop` (trên dòng không nhãn — báo nhầm) 2020-02-06 05:36:27 · 10.3.226.113 · `4130074439166519892` · thành công — Tài khoản '4130074439166519892' bị thử từ 3 quốc gia trong 24 giờ (ngưỡng 3).
- `country_hop` (trên dòng không nhãn — báo nhầm) 2020-02-06 15:09:39 · 10.0.159.128 · `-4725483962609120813` · thành công — Tài khoản '-4725483962609120813' bị thử từ 3 quốc gia trong 24 giờ (ngưỡng 3).
- `dormant_account_login` (trên dòng có nhãn) 2020-05-04 12:03:14 · 209.236.123.116 · `4837337122944133942` · thành công — Tài khoản '4837337122944133942' ngủ đông 91 ngày rồi đăng nhập lại (thiết bị mới).
- `dormant_account_login` (trên dòng có nhãn) 2020-05-04 23:43:22 · 209.236.125.127 · `-5131454459102535265` · thành công — Tài khoản '-5131454459102535265' ngủ đông 91 ngày rồi đăng nhập lại (thiết bị mới).
- `dormant_account_login` (trên dòng có nhãn) 2020-05-05 04:03:32 · 103.230.153.32 · `-7727590959985386152` · thành công — Tài khoản '-7727590959985386152' ngủ đông 91 ngày rồi đăng nhập lại (thiết bị mới).
- `dormant_account_login` (trên dòng không nhãn — báo nhầm) 2020-05-04 05:03:46 · 77.222.195.243 · `4942292199433133511` · thành công — Tài khoản '4942292199433133511' ngủ đông 90 ngày rồi đăng nhập lại (thiết bị mới).
- `dormant_account_login` (trên dòng không nhãn — báo nhầm) 2020-05-04 05:20:22 · 94.247.168.120 · `-2635272103481538687` · thành công — Tài khoản '-2635272103481538687' ngủ đông 90 ngày rồi đăng nhập lại (thiết bị mới).
- `dormant_account_login` (trên dòng không nhãn — báo nhầm) 2020-05-04 06:10:16 · 81.167.64.27 · `5226380226270543623` · thành công — Tài khoản '5226380226270543623' ngủ đông 91 ngày rồi đăng nhập lại (thiết bị mới).
- `rare_network_login` (trên dòng có nhãn) 2020-02-03 21:36:24 · 155.133.207.147 · `7573539760852918317` · thành công — Đăng nhập từ nhà mạng cực hiếm AS62365: 0 lần trong 20,466 lượt thành công (0.0000%; ngưỡng 0.0020%).
- `rare_network_login` (trên dòng có nhãn) 2020-02-03 21:57:46 · 191.52.140.20 · `-1670319114615675352` · thành công — Đăng nhập từ nhà mạng cực hiếm AS263282: 0 lần trong 20,937 lượt thành công (0.0000%; ngưỡng 0.0020%).
- `rare_network_login` (trên dòng có nhãn) 2020-02-03 23:03:06 · 91.149.139.179 · `-2483116652128402443` · thành công — Đăng nhập từ nhà mạng cực hiếm AS31143: 0 lần trong 21,736 lượt thành công (0.0000%; ngưỡng 0.0020%).
- `rare_network_login` (trên dòng không nhãn — báo nhầm) 2020-02-03 21:29:51 · 167.250.233.179 · `4634409309422314975` · thành công — Đăng nhập từ nhà mạng cực hiếm AS265211: 0 lần trong 20,324 lượt thành công (0.0000%; ngưỡng 0.0020%).
- `rare_network_login` (trên dòng không nhãn — báo nhầm) 2020-02-03 21:30:04 · 10.3.91.156 · `-5475204052477615330` · thành công — Đăng nhập từ nhà mạng cực hiếm AS43949: 0 lần trong 20,326 lượt thành công (0.0000%; ngưỡng 0.0020%).
- `rare_network_login` (trên dòng không nhãn — báo nhầm) 2020-02-03 21:35:11 · 10.3.207.50 · `2367003554100206934` · thành công — Đăng nhập từ nhà mạng cực hiếm AS39284: 0 lần trong 20,436 lượt thành công (0.0000%; ngưỡng 0.0020%).
