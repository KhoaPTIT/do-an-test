# Tinh chỉnh ngưỡng luật trên train RBA (MR10)

> Báo cáo TỰ SINH bởi `python -m ml.rba.rule_tuning tune` (sau `collect`) — đừng sửa tay. Mã: [`rule_tuning.py`](../backend/ml/rba/rule_tuning.py), [`rule_tuning_report.py`](../backend/ml/rba/rule_tuning_report.py). Hồ sơ cấu hình luật: [`profiles/rba_train_tuned.json`](../backend/app/detection/engine/profiles/rba_train_tuned.json).

## 1. Cách làm, quy trình sửa và những gì cần đọc kèm

- **Đối tượng:** ngưỡng của các luật ở [`rule-catalog.md`](rule-catalog.md) (giá trị mặc định là giá trị đặt trước, chưa từng đo trên dữ liệu — xem [`rule-replay.md`](rule-replay.md)). Mỗi luật có một *bậc thang* tham số từ lỏng đến chặt sao cho lần khớp lồng nhau; luật hai điều kiện (số lần sai và số tên) quét dọc một tia tỉ lệ, luật hai phạm vi (IP, ASN) có hai bậc thang riêng; các tham số còn lại giữ mặc định.
- **Dữ liệu:** một lượt replay toàn bộ RBA, chấm các dòng thuộc mẫu ML (tài khoản có thật; lần thử vào tên không tồn tại nằm ngoài mẫu) với ĐÚNG trọng số dân số và định nghĩa dương/âm của khung đánh giá ML, để số của luật và của mô hình so được ([`rule-ml-overlap.md`](rule-ml-overlap.md)).
- **Quy trình đặt trước (chỉ train):** bậc LỎNG NHẤT có tỉ lệ khớp trên dòng bình thường ≤ **5 lần trên 10.000 đăng nhập hợp lệ thành công** ở train (ngân sách đặt trước khi xem kết quả; 2 và 10 chỉ để xem độ nhạy). Nhãn tấn công và ATO KHÔNG tham gia chọn: chúng chỉ định nghĩa "dòng bình thường" và để báo cáo val/test/late.
- **Quy trình sửa (train ∧ val):** cùng ngân sách nhưng ở CẢ train và val. ⚠️ Được thêm SAU khi thấy quy trình đặt trước không giữ được ở test/late với 2 bậc thang (`credential_stuffing/asn`, `dormant_account_login`), nên số của quy trình sửa không còn là ước lượng "sạch" về mặt thiết kế quy trình (chưa tham số nào được khớp vào test); số của quy trình đặt trước mới là ước lượng chưa bị ảnh hưởng. Hai bậc thang còn bị loại khỏi hồ sơ cấu hình vì cơ chế, không phải vì điểm (mục 4).
- **Chỉ số:** *khớp/10.000* = trọng số các lần luật khớp trên dòng bình thường (không thuộc IP tấn công, mọi kết quả đăng nhập) chia cho trọng số đăng nhập hợp lệ thành công, nhân 10.000 — cùng mẫu số với "cảnh báo nhầm trên 10.000 đăng nhập" của mô hình; *recall* = tỉ lệ trọng số dòng thuộc IP tấn công (phân vùng tương ứng) mà luật khớp. Khoảng tin cậy 95% lấy mẫu lại theo cụm IP.
- ⚠️ Dòng không nhãn coi là bình thường nên *khớp/10.000* là **cận trên** của báo nhầm (nhà mạng có nhiều IP tấn công thì các dòng còn lại chưa chắc hợp lệ). RBA là dữ liệu tổng hợp; ngưỡng ở đây tinh chỉnh cho RBA, không tự nhiên áp cho hệ thống thật. Khung mẫu ML chỉ có tài khoản có thật, nên lưu lượng đoán mật khẩu vào tên không tồn tại (45% số dòng của RBA, nơi các luật đoán mật khẩu có nhiều đất dụng võ nhất) nằm NGOÀI phép đo này.

Cỡ mẫu: train: 47,978 dòng tấn công, 5,103,380 đăng nhập hợp lệ thành công (đã trọng số); val: 1,996 dòng tấn công, 917,099 đăng nhập hợp lệ thành công (đã trọng số); test: 5,709 dòng tấn công, 2,783,223 đăng nhập hợp lệ thành công (đã trọng số); late: 7,137 dòng tấn công, 2,494,327 đăng nhập hợp lệ thành công (đã trọng số); ATO: 92 quá khứ + 38 tương lai.

## 2. Kết quả theo từng luật (ngân sách 5/10.000)

| Bậc thang | Mặc định: tham số | khớp/10.000 train → test | **Chỉ train (đặt trước)** | khớp/10.000 train → test | recall test | **Train ∧ val (sửa)** | khớp/10.000 train / val → test | recall test | ATO tương lai | Hồ sơ |
|---|---|---|---|---|---|---|---|---|---|---|
| `brute_force` | `threshold=5` | 16.4 → 14.5 | **`threshold=8`** | 3.3 → 3.0 [2.1–4.0] | 0.0% [0.0%–0.0%] | **`threshold=8`** | 3.3 / 2.9 → 3.0 [2.1–4.0] | 0.0% [0.0%–0.0%] | 0/38 | ✔ |
| `credential_stuffing/ip` | `min_fails=10, min_users=5` | 0.6 → 0.8 | **`min_fails=8, min_users=4`** | 2.5 → 2.9 [2.3–3.6] | 0.0% [0.0%–0.1%] | **`min_fails=8, min_users=4`** | 2.5 / 2.7 → 2.9 [2.3–3.6] | 0.0% [0.0%–0.1%] | 0/38 | ✔ |
| `credential_stuffing/asn` | `asn_min_fails=40, asn_min_users=20` | 556.7 → 898.9 | **`asn_min_fails=120, asn_min_users=60`** | 0.4 → 29.4 [26.9–32.3] | 1.0% [0.7%–1.4%] | **`asn_min_fails=120, asn_min_users=60`** | 0.4 / 0.3 → 29.4 [26.9–32.3] | 1.0% [0.7%–1.4%] | 0/38 | loại (mục 4) |
| `password_spray_slow/ip` | `min_users=15` | 23.6 → 47.5 | **`min_users=50`** | 2.6 → 2.2 [0.5–5.0] | 0.0% [0.0%–0.0%] | **`min_users=50`** | 2.6 / 2.9 → 2.2 [0.5–5.0] | 0.0% [0.0%–0.0%] | 0/38 | ✔ |
| `password_spray_slow/asn` | `asn_min_users=40` | 540.5 → 487.5 | **không chọn được** (bậc chặt nhất `asn_min_users=200` vẫn 283.4) | — | — | **không chọn được** (bậc chặt nhất `asn_min_users=200` vẫn 283.4) | — | — | — | shadow |
| `distributed_bruteforce` | `min_fails=8, min_ips=5` | 0.1 → 0.0 | **`min_fails=4, min_ips=3`** | 4.1 → 2.9 [2.3–3.6] | 0.2% [0.0%–0.3%] | **`min_fails=4, min_ips=3`** | 4.1 / 3.8 → 2.9 [2.3–3.6] | 0.2% [0.0%–0.3%] | 0/38 | ✔ |
| `success_after_failures` | `min_fails=5` | 1.5 → 1.7 | **`min_fails=5`** (= mặc định) | 1.5 → 1.7 [1.2–2.3] | 0.0% [0.0%–0.0%] | **`min_fails=5`** (= mặc định) | 1.5 / 2.3 → 1.7 [1.2–2.3] | 0.0% [0.0%–0.0%] | 0/38 | ✔ |
| `ua_rotation` | `min_fails=8, min_distinct_ua=5` | 0.1 → 0.2 | **`min_fails=4, min_distinct_ua=3`** | 2.2 → 2.7 [1.6–4.2] | 0.0% [0.0%–0.1%] | **`min_fails=4, min_distinct_ua=3`** | 2.2 / 2.1 → 2.7 [1.6–4.2] | 0.0% [0.0%–0.1%] | 0/38 | ✔ |
| `dormant_account_login` | `dormant_days=90` | 228.9 → 973.3 | **`dormant_days=180`** | 0.0 → 288.4 [282.1–294.4] | 1.0% [0.8%–1.3%] | **`dormant_days=270`** | 0.0 / 0.0 → 14.1 [12.7–15.3] | 0.0% [0.0%–0.1%] | 0/38 | loại (mục 4) |
| `rare_network_login` | `max_share=2e-05` | 120.1 → 109.4 | **không chọn được** (bậc chặt nhất `max_share=0` vẫn 6.6) | — | — | **không chọn được** (bậc chặt nhất `max_share=0` vẫn 6.6) | — | — | — | shadow |
| `multi_context_simultaneous` | `window_s=600` | 4.8 → 5.3 | **`window_s=600`** (= mặc định) | 4.8 → 5.3 [4.5–6.2] | 0.0% [0.0%–0.1%] | **`window_s=600`** (= mặc định) | 4.8 / 4.8 → 5.3 [4.5–6.2] | 0.0% [0.0%–0.1%] | 1/38 | ✔ |
| `country_hop` | `min_countries=3` | 1.5 → 5.3 | **`min_countries=3`** (= mặc định) | 1.5 → 5.3 [2.7–10.0] | 0.0% [0.0%–0.1%] | **`min_countries=3`** (= mặc định) | 1.5 / 2.6 → 5.3 [2.7–10.0] | 0.0% [0.0%–0.1%] | 0/38 | ✔ |
| `bot_user_agent` | `(không tham số)` | 0.0 → 0.0 | **`(không tham số)`** (= mặc định) | 0.0 → 0.0 [0.0–0.1] | 0.0% [0.0%–0.0%] | **`(không tham số)`** (= mặc định) | 0.0 / 0.0 → 0.0 [0.0–0.1] | 0.0% [0.0%–0.0%] | 0/38 | ✔ |
| `scripted_client` | `(không tham số)` | 0.0 → 0.0 | **`(không tham số)`** (= mặc định) | 0.0 → 0.0 [0.0–0.0] | 0.0% [0.0%–0.0%] | **`(không tham số)`** (= mặc định) | 0.0 / 0.0 → 0.0 [0.0–0.0] | 0.0% [0.0%–0.0%] | 0/38 | ✔ |

Chuyển giao của quy trình đặt trước (khớp/10.000 trên test ≤ 3 lần ngân sách = 15): **giữ được 10**, **không giữ được 2** (`credential_stuffing/asn`, `dormant_account_login`).

Bậc chọn được ở ngân sách 2 / 5 / 10 — chỉ train | train ∧ val (số thứ tự bậc từ lỏng đến chặt; — = không chọn được): `brute_force` 6 / 5 / 4 | 6 / 5 / 4; `credential_stuffing/ip` 4 / 3 / 3 | 4 / 3 / 3; `credential_stuffing/asn` 6 / 6 / 6 | 6 / 6 / 6; `password_spray_slow/ip` 8 / 7 / 6 | 8 / 7 / 6; `password_spray_slow/asn` — / — / — | — / — / —; `distributed_bruteforce` 2 / 1 / 1 | 2 / 1 / 1; `success_after_failures` 4 / 4 / 3 | 5 / 4 / 3; `ua_rotation` 2 / 1 / 1 | 2 / 1 / 1; `dormant_account_login` 6 / 6 / 6 | 7 / 7 / 7; `rare_network_login` — / — / 11 | — / — / 11; `multi_context_simultaneous` 5 / 3 / 1 | 5 / 3 / 1; `country_hop` 2 / 2 / 2 | 3 / 2 / 2; `bot_user_agent` 1 / 1 / 1 | 1 / 1 / 1; `scripted_client` 1 / 1 / 1 | 1 / 1 / 1.

## 3. Bộ luật gộp (có ít nhất một luật khớp)

`mặc định (enforce)` = các luật mặc định enforce ở giá trị mặc định (chính là bộ luật của MR9 nhưng đo trên khung mẫu ML); `chỉ train (enforce)` = các luật enforce ở bậc của quy trình đặt trước; `hồ sơ (enforce)` = quy trình sửa, trừ các bậc thang bị loại; `hồ sơ (cả shadow)` thêm các luật mặc định shadow (`country_hop`, `rare_network_login`) nếu chọn được.

| Bộ luật | Phân vùng | khớp/10.000 | recall dòng tấn công |
|---|---|---|---|
| mặc định (enforce) | train | 1,356.4 | 26.4% |
| mặc định (enforce) | val | 2,069.6 | 36.5% |
| mặc định (enforce) | test | 2,387.3 [2,351.7–2,421.1] | 38.0% [36.3%–40.0%] |
| mặc định (enforce) | late | 3,291.5 | 44.0% |
| chỉ train (enforce) | train | 20.9 | 0.5% |
| chỉ train (enforce) | val | 110.3 | 0.2% |
| chỉ train (enforce) | test | 337.5 [330.1–344.4] | 2.3% [1.8%–2.8%] |
| chỉ train (enforce) | late | 865.8 | 10.7% |
| hồ sơ (enforce) | train | 20.5 | 0.5% |
| hồ sơ (enforce) | val | 20.9 | 0.0% |
| hồ sơ (enforce) | test | 19.9 [17.1–23.5] | 0.3% [0.1%–0.4%] |
| hồ sơ (enforce) | late | 29.1 | 1.6% |
| hồ sơ (cả shadow) | train | 21.6 | 0.6% |
| hồ sơ (cả shadow) | val | 23.0 | 0.0% |
| hồ sơ (cả shadow) | test | 24.5 [20.1–30.0] | 0.3% [0.1%–0.4%] |
| hồ sơ (cả shadow) | late | 33.5 | 1.7% |

ATO (92 quá khứ trước 09/2020 và 38 tương lai; **`rare_network_login` vòng tròn với cách RBA sinh ATO**, xem ghi chú luật):

| Bộ luật | ATO quá khứ | ATO tương lai | ATO tất cả |
|---|---|---|---|
| mặc định (enforce) | 12/92 | 5/38 | 17/130 |
| chỉ train (enforce) | 5/92 | 3/38 | 8/130 |
| hồ sơ (enforce) | 4/92 | 1/38 | 5/130 |
| hồ sơ (cả shadow) | 6/92 | 1/38 | 7/130 |

## 4. Bậc thang bị loại khỏi hồ sơ cấu hình

Chọn được bậc ở train (và val) nhưng không đưa vào hồ sơ vì lý do CƠ CHẾ dưới đây; số đo dẫn ra để tự kiểm tra (khớp/10.000 ở bậc mặc định và ở bậc quy trình sửa chọn, theo train → val → test → late).

| Bậc thang | Lý do | Bậc mặc định | Bậc quy trình sửa chọn |
|---|---|---|---|
| `credential_stuffing/asn` | số lần sai và số tên tuyệt đối của một nhà mạng phụ thuộc lưu lượng của nó, mà lưu lượng thay đổi theo thời gian; cần điều kiện tương đối (tỉ lệ sai) chứ không phải ngưỡng tuyệt đối | `asn_min_fails=40, asn_min_users=20`: 556.7 → 684.1 → 898.9 → 1,557.6 | `asn_min_fails=120, asn_min_users=60`: 0.4 → 0.3 → 29.4 → 345.9 |
| `dormant_account_login` | số tài khoản đã có ≥ N ngày lịch sử tăng dần theo tuổi của log nên tỉ lệ khớp tăng dần: ngưỡng chọn trên đoạn đầu của log luôn quá lạc quan | `dormant_days=90`: 228.9 → 827.2 → 973.3 → 1,243.9 | `dormant_days=270`: 0.0 → 0.0 → 14.1 → 168.9 |

Không chọn được bậc nào ở ngân sách chính (riêng ngưỡng không đủ; cần thêm điều kiện, ví dụ chuẩn hoá theo lưu lượng): `password_spray_slow/asn`, `rare_network_login`. Trong hồ sơ, luật mất hết phạm vi chuyển sang `shadow`.

## 5. Chi tiết từng bậc thang

◀ = bậc mặc định; ✔ = bậc chọn của quy trình đặt trước (chỉ train); ✅ = bậc chọn của quy trình sửa (train ∧ val). Các cột phân vùng: khớp/10.000 | recall dòng tấn công.

#### `brute_force`

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `threshold=3` | 92.7 \| 1.6% | 81.7 \| 1.3% | 88.1 \| 1.0% | 110.0 \| 1.4% | 0/92 | 0/38 |
| 2 | `threshold=4` | 32.8 \| 0.7% | 27.1 \| 0.3% | 30.0 \| 0.3% | 41.7 \| 0.7% | 0/92 | 0/38 |
| 3 ◀ | `threshold=5` | 16.4 \| 0.4% | 12.9 \| 0.1% | 14.5 \| 0.1% | 22.6 \| 0.3% | 0/92 | 0/38 |
| 4 | `threshold=6` | 9.3 \| 0.2% | 6.8 \| 0.1% | 8.1 \| 0.0% | 13.8 \| 0.2% | 0/92 | 0/38 |
| 5 ✔ ✅ | `threshold=8` | 3.3 \| 0.1% | 2.9 \| 0.0% | 3.0 \| 0.0% | 6.3 \| 0.1% | 0/92 | 0/38 |
| 6 | `threshold=10` | 1.4 \| 0.1% | 1.3 \| 0.0% | 1.2 \| 0.0% | 3.4 \| 0.0% | 0/92 | 0/38 |
| 7 | `threshold=15` | 0.4 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 0.0% | 0.7 \| 0.0% | 0/92 | 0/38 |
| 8 | `threshold=20` | 0.2 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.3 \| 0.0% | 0/92 | 0/38 |
| 9 | `threshold=30` | 0.1 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 0.0% | 0/92 | 0/38 |
| 10 | `threshold=50` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |

#### `credential_stuffing/ip` — phạm vi IP; tỉ lệ 2 lần sai : 1 tên như mặc định; phạm vi ASN tắt

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `min_fails=4, min_users=2` | 69.9 \| 1.1% | 60.7 \| 0.9% | 74.3 \| 1.3% | 99.1 \| 2.6% | 0/92 | 0/38 |
| 2 | `min_fails=6, min_users=3` | 11.1 \| 0.2% | 9.1 \| 0.1% | 10.9 \| 0.2% | 16.9 \| 1.3% | 0/92 | 0/38 |
| 3 ✔ ✅ | `min_fails=8, min_users=4` | 2.5 \| 0.0% | 2.7 \| 0.0% | 2.9 \| 0.0% | 3.6 \| 1.3% | 0/92 | 0/38 |
| 4 ◀ | `min_fails=10, min_users=5` | 0.6 \| 0.0% | 0.7 \| 0.0% | 0.8 \| 0.0% | 1.1 \| 1.3% | 0/92 | 0/38 |
| 5 | `min_fails=15, min_users=8` | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.1 \| 1.3% | 0/92 | 0/38 |
| 6 | `min_fails=20, min_users=10` | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 1.3% | 0/92 | 0/38 |
| 7 | `min_fails=30, min_users=15` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 1.3% | 0/92 | 0/38 |
| 8 | `min_fails=50, min_users=25` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 1.3% | 0/92 | 0/38 |
| 9 | `min_fails=100, min_users=50` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 1.3% | 0/92 | 0/38 |

#### `credential_stuffing/asn` — phạm vi ASN; số tên khác nhau tối đa 200 (CAP); phạm vi IP tắt

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `asn_min_fails=20, asn_min_users=10` | 791.5 \| 30.0% | 829.3 \| 34.8% | 980.0 \| 34.4% | 1,626.7 \| 40.6% | 0/92 | 0/38 |
| 2 | `asn_min_fails=30, asn_min_users=15` | 711.6 \| 27.2% | 786.9 \| 33.6% | 952.9 \| 33.5% | 1,586.8 \| 39.9% | 0/92 | 0/38 |
| 3 ◀ | `asn_min_fails=40, asn_min_users=20` | 556.7 \| 21.4% | 684.1 \| 29.8% | 898.9 \| 31.4% | 1,557.6 \| 39.3% | 0/92 | 0/38 |
| 4 | `asn_min_fails=60, asn_min_users=30` | 159.8 \| 6.1% | 263.0 \| 12.7% | 603.0 \| 20.8% | 1,473.9 \| 37.3% | 0/92 | 0/38 |
| 5 | `asn_min_fails=80, asn_min_users=40` | 18.2 \| 0.7% | 22.5 \| 1.1% | 251.0 \| 9.1% | 1,229.3 \| 31.4% | 0/92 | 0/38 |
| 6 ✔ ✅ | `asn_min_fails=120, asn_min_users=60` | 0.4 \| 0.0% | 0.3 \| 0.0% | 29.4 \| 1.0% | 345.9 \| 9.3% | 0/92 | 0/38 |
| 7 | `asn_min_fails=160, asn_min_users=80` | 0.2 \| 0.0% | 0.3 \| 0.0% | 3.3 \| 0.1% | 47.2 \| 2.6% | 0/92 | 0/38 |
| 8 | `asn_min_fails=240, asn_min_users=120` | 0.1 \| 0.0% | 0.3 \| 0.0% | 1.9 \| 0.1% | 3.5 \| 1.3% | 0/92 | 0/38 |
| 9 | `asn_min_fails=400, asn_min_users=200` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 0.0% | 0.1 \| 0.0% | 0/92 | 0/38 |

#### `password_spray_slow/ip` — phạm vi IP (24 giờ, ≤ 3 lần sai/tài khoản, ≤ 120 lần/giờ); phạm vi ASN tắt

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `min_users=5` | 549.5 \| 17.6% | 560.7 \| 19.4% | 793.2 \| 25.6% | 1,557.4 \| 36.4% | 0/92 | 0/38 |
| 2 | `min_users=8` | 204.6 \| 6.3% | 214.7 \| 6.8% | 381.0 \| 12.4% | 1,059.3 \| 23.6% | 0/92 | 0/38 |
| 3 | `min_users=10` | 99.8 \| 2.9% | 112.7 \| 3.4% | 213.2 \| 6.6% | 722.0 \| 15.6% | 0/92 | 0/38 |
| 4 ◀ | `min_users=15` | 23.6 \| 0.6% | 24.1 \| 0.3% | 47.5 \| 1.2% | 207.0 \| 3.9% | 0/92 | 0/38 |
| 5 | `min_users=20` | 11.6 \| 0.3% | 9.6 \| 0.0% | 17.0 \| 0.1% | 48.9 \| 0.9% | 0/92 | 0/38 |
| 6 | `min_users=30` | 6.8 \| 0.1% | 6.0 \| 0.0% | 6.0 \| 0.0% | 8.3 \| 0.1% | 0/92 | 0/38 |
| 7 ✔ ✅ | `min_users=50` | 2.6 \| 0.0% | 2.9 \| 0.0% | 2.2 \| 0.0% | 5.3 \| 0.0% | 0/92 | 0/38 |
| 8 | `min_users=80` | 0.6 \| 0.0% | 1.6 \| 0.0% | 1.0 \| 0.0% | 3.6 \| 0.0% | 0/92 | 0/38 |
| 9 | `min_users=150` | 0.1 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 0.0% | 0.3 \| 0.0% | 0/92 | 0/38 |

#### `password_spray_slow/asn` — phạm vi ASN; số tên khác nhau tối đa 200 (CAP); phạm vi IP tắt

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `asn_min_users=20` | 620.0 \| 4.9% | 612.8 \| 5.7% | 573.5 \| 4.5% | 540.6 \| 2.3% | 0/92 | 0/38 |
| 2 ◀ | `asn_min_users=40` | 540.5 \| 4.2% | 531.6 \| 4.9% | 487.5 \| 4.0% | 456.9 \| 1.7% | 0/92 | 0/38 |
| 3 | `asn_min_users=60` | 489.4 \| 3.8% | 486.0 \| 4.6% | 441.8 \| 3.5% | 407.2 \| 1.2% | 0/92 | 0/38 |
| 4 | `asn_min_users=80` | 449.9 \| 3.6% | 451.9 \| 4.5% | 406.3 \| 3.1% | 373.8 \| 0.8% | 0/92 | 0/38 |
| 5 | `asn_min_users=100` | 420.3 \| 3.4% | 414.6 \| 4.4% | 372.4 \| 3.0% | 344.7 \| 0.6% | 0/92 | 0/38 |
| 6 | `asn_min_users=150` | 358.8 \| 3.3% | 351.0 \| 4.3% | 314.0 \| 2.7% | 265.1 \| 0.4% | 0/92 | 0/38 |
| 7 | `asn_min_users=200` | 283.4 \| 3.1% | 278.7 \| 3.7% | 232.6 \| 2.4% | 186.7 \| 0.4% | 0/92 | 0/38 |

#### `distributed_bruteforce`

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 ✔ ✅ | `min_fails=4, min_ips=3` | 4.1 \| 0.2% | 3.8 \| 0.0% | 2.9 \| 0.2% | 5.1 \| 0.1% | 0/92 | 0/38 |
| 2 | `min_fails=6, min_ips=4` | 0.6 \| 0.0% | 0.8 \| 0.0% | 0.4 \| 0.0% | 0.6 \| 0.1% | 0/92 | 0/38 |
| 3 ◀ | `min_fails=8, min_ips=5` | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.0 \| 0.0% | 0.3 \| 0.0% | 0/92 | 0/38 |
| 4 | `min_fails=12, min_ips=8` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 0.0% | 0/92 | 0/38 |
| 5 | `min_fails=16, min_ips=10` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 6 | `min_fails=24, min_ips=15` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 7 | `min_fails=40, min_ips=25` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 8 | `min_fails=80, min_ips=50` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |

#### `success_after_failures`

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `min_fails=2` | 125.0 \| 1.2% | 124.9 \| 1.8% | 117.0 \| 1.1% | 126.4 \| 1.3% | 2/92 | 1/38 |
| 2 | `min_fails=3` | 24.4 \| 0.2% | 26.8 \| 0.5% | 22.4 \| 0.1% | 23.5 \| 0.2% | 0/92 | 0/38 |
| 3 | `min_fails=4` | 5.6 \| 0.1% | 6.4 \| 0.1% | 5.4 \| 0.0% | 6.1 \| 0.1% | 0/92 | 0/38 |
| 4 ◀ ✔ ✅ | `min_fails=5` | 1.5 \| 0.0% | 2.3 \| 0.0% | 1.7 \| 0.0% | 1.6 \| 0.0% | 0/92 | 0/38 |
| 5 | `min_fails=6` | 0.6 \| 0.0% | 0.6 \| 0.0% | 0.5 \| 0.0% | 0.7 \| 0.0% | 0/92 | 0/38 |
| 6 | `min_fails=8` | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.2 \| 0.0% | 0/92 | 0/38 |
| 7 | `min_fails=10` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 8 | `min_fails=15` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 9 | `min_fails=25` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |

#### `ua_rotation`

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 ✔ ✅ | `min_fails=4, min_distinct_ua=3` | 2.2 \| 0.0% | 2.1 \| 0.0% | 2.7 \| 0.0% | 3.8 \| 0.0% | 0/92 | 0/38 |
| 2 | `min_fails=6, min_distinct_ua=4` | 0.1 \| 0.0% | 0.4 \| 0.0% | 0.6 \| 0.0% | 0.3 \| 0.0% | 0/92 | 0/38 |
| 3 ◀ | `min_fails=8, min_distinct_ua=5` | 0.1 \| 0.0% | 0.0 \| 0.0% | 0.2 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 4 | `min_fails=12, min_distinct_ua=7` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.1 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 5 | `min_fails=16, min_distinct_ua=10` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 6 | `min_fails=24, min_distinct_ua=15` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |
| 7 | `min_fails=40, min_distinct_ua=25` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |

#### `dormant_account_login` — luôn kèm điều kiện quốc gia/thiết bị mới

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `dormant_days=14` | 1,741.6 \| 3.7% | 3,011.9 \| 5.5% | 3,031.4 \| 6.3% | 3,198.4 \| 5.0% | 27/92 | 15/38 |
| 2 | `dormant_days=30` | 1,097.0 \| 2.4% | 2,215.6 \| 4.2% | 2,249.3 \| 5.1% | 2,491.5 \| 4.0% | 24/92 | 13/38 |
| 3 | `dormant_days=60` | 510.3 \| 1.2% | 1,311.1 \| 2.7% | 1,447.4 \| 3.5% | 1,709.8 \| 3.1% | 15/92 | 8/38 |
| 4 ◀ | `dormant_days=90` | 228.9 \| 0.6% | 827.2 \| 1.8% | 973.3 \| 2.6% | 1,243.9 \| 2.5% | 8/92 | 4/38 |
| 5 | `dormant_days=120` | 83.3 \| 0.2% | 506.8 \| 1.2% | 670.9 \| 2.0% | 910.3 \| 1.9% | 4/92 | 4/38 |
| 6 ✔ | `dormant_days=180` | 0.0 \| 0.0% | 89.1 \| 0.2% | 288.4 \| 1.0% | 493.7 \| 1.1% | 1/92 | 2/38 |
| 7 ✅ | `dormant_days=270` | 0.0 \| 0.0% | 0.0 \| 0.0% | 14.1 \| 0.0% | 168.9 \| 0.5% | 0/92 | 0/38 |
| 8 | `dormant_days=365` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 6.3 \| 0.0% | 0/92 | 0/38 |

#### `rare_network_login` — chặt = tỉ lệ toàn hệ thống của ASN càng nhỏ; 0 = chưa từng thấy

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `max_share=0.001` | 893.8 \| 5.7% | 847.3 \| 4.1% | 812.1 \| 3.7% | 784.8 \| 2.4% | 85/92 | 38/38 |
| 2 | `max_share=0.0005` | 678.8 \| 4.4% | 625.7 \| 3.3% | 596.1 \| 3.0% | 548.1 \| 1.8% | 82/92 | 38/38 |
| 3 | `max_share=0.0002` | 461.5 \| 2.9% | 436.4 \| 2.3% | 414.3 \| 2.3% | 387.0 \| 1.4% | 80/92 | 34/38 |
| 4 | `max_share=0.0001` | 322.2 \| 2.2% | 309.0 \| 1.7% | 290.7 \| 2.0% | 273.3 \| 1.1% | 68/92 | 30/38 |
| 5 | `max_share=5e-05` | 218.3 \| 1.5% | 208.4 \| 1.3% | 194.9 \| 1.6% | 176.1 \| 0.9% | 68/92 | 30/38 |
| 6 ◀ | `max_share=2e-05` | 120.1 \| 0.7% | 119.2 \| 0.3% | 109.4 \| 0.5% | 101.3 \| 0.4% | 59/92 | 25/38 |
| 7 | `max_share=1e-05` | 74.2 \| 0.4% | 74.9 \| 0.1% | 69.6 \| 0.3% | 62.3 \| 0.2% | 57/92 | 24/38 |
| 8 | `max_share=5e-06` | 46.1 \| 0.2% | 44.3 \| 0.0% | 39.5 \| 0.1% | 38.0 \| 0.1% | 42/92 | 19/38 |
| 9 | `max_share=2e-06` | 25.4 \| 0.1% | 24.0 \| 0.0% | 21.5 \| 0.1% | 20.2 \| 0.1% | 22/92 | 11/38 |
| 10 | `max_share=1e-06` | 15.3 \| 0.0% | 14.5 \| 0.0% | 13.5 \| 0.1% | 13.3 \| 0.0% | 16/92 | 5/38 |
| 11 | `max_share=0` | 6.6 \| 0.0% | 3.0 \| 0.0% | 2.3 \| 0.0% | 1.8 \| 0.0% | 9/92 | 2/38 |

#### `multi_context_simultaneous` — chặt = cửa sổ ngắn hơn

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `window_s=1800` | 8.0 \| 0.1% | 7.9 \| 0.0% | 8.7 \| 0.0% | 5.9 \| 0.1% | 6/92 | 2/38 |
| 2 | `window_s=900` | 6.0 \| 0.1% | 6.1 \| 0.0% | 6.5 \| 0.0% | 4.6 \| 0.0% | 5/92 | 2/38 |
| 3 ◀ ✔ ✅ | `window_s=600` | 4.8 \| 0.1% | 4.8 \| 0.0% | 5.3 \| 0.0% | 3.9 \| 0.0% | 4/92 | 1/38 |
| 4 | `window_s=300` | 3.0 \| 0.0% | 2.7 \| 0.0% | 3.2 \| 0.0% | 2.4 \| 0.0% | 1/92 | 0/38 |
| 5 | `window_s=120` | 1.2 \| 0.0% | 1.0 \| 0.0% | 1.1 \| 0.0% | 0.8 \| 0.0% | 0/92 | 0/38 |
| 6 | `window_s=60` | 0.4 \| 0.0% | 0.2 \| 0.0% | 0.5 \| 0.0% | 0.4 \| 0.0% | 0/92 | 0/38 |
| 7 | `window_s=30` | 0.2 \| 0.0% | 0.0 \| 0.0% | 0.2 \| 0.0% | 0.3 \| 0.0% | 0/92 | 0/38 |

#### `country_hop`

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 | `min_countries=2` | 38.7 \| 0.8% | 33.8 \| 0.4% | 40.7 \| 0.3% | 36.0 \| 0.6% | 13/92 | 6/38 |
| 2 ◀ ✔ ✅ | `min_countries=3` | 1.5 \| 0.1% | 2.6 \| 0.0% | 5.3 \| 0.0% | 5.1 \| 0.0% | 3/92 | 0/38 |
| 3 | `min_countries=4` | 0.4 \| 0.0% | 1.1 \| 0.0% | 1.3 \| 0.0% | 1.3 \| 0.0% | 0/92 | 0/38 |
| 4 | `min_countries=5` | 0.2 \| 0.0% | 0.5 \| 0.0% | 0.1 \| 0.0% | 0.2 \| 0.0% | 0/92 | 0/38 |
| 5 | `min_countries=6` | 0.1 \| 0.0% | 0.1 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |

#### `bot_user_agent` — không có tham số

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 ◀ ✔ ✅ | `(không tham số)` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0/92 | 0/38 |

#### `scripted_client` — không có tham số quét được (danh sách chuỗi công cụ cố định)

| Bậc | Tham số | train | val | test | late | ATO quá khứ | ATO tương lai |
|---|---|---|---|---|---|---|---|
| 1 ◀ ✔ ✅ | `(không tham số)` | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.0 \| 0.0% | 0.2 \| 0.0% | 0/92 | 0/38 |

## 6. Luật không đánh giá được trên RBA

| Luật | Lý do |
|---|---|
| `username_enumeration` | chỉ khớp ở lần thử vào tên không tồn tại; RBA gộp các lần đó vào một user_id (45% số dòng), bị loại khỏi mẫu ML nên không có dòng nào để so với mô hình |
| `regular_rhythm` | dựa vào nhịp cách nhau vài giây, còn timestamp của RBA có thành phần ngẫu nhiên (thẻ dữ liệu) |
| `impossible_travel` | RBA không có toạ độ |
| `tor_exit` | IP của RBA là tổng hợp, danh sách Tor công khai không áp dụng |
| `datacenter_ip` | IP của RBA là tổng hợp, danh sách datacenter công khai không áp dụng |
| `vpn_ip` | IP của RBA là tổng hợp, danh sách VPN công khai không áp dụng |
| `blocklist_hit` | không có mục chặn do quản trị viên đặt |

## 7. Giới hạn

- Quét một chiều cho mỗi luật; tổ hợp nhiều tham số chưa được tối ưu chung. Số tên khác nhau đếm tối đa 200 (`indexes.CAP`) nên bậc chặt nhất của hai luật phạm vi ASN dừng ở 200.
- Bậc chọn được ngay cả ở bậc lỏng nhất (bậc 1) nghĩa là bậc thang chưa đủ lỏng để thấy điểm cân bằng; bậc không chọn được nghĩa là riêng ngưỡng không đủ, luật cần thêm điều kiện (ví dụ chuẩn hoá theo lưu lượng của nhà mạng).
- Thời gian trong RBA có thành phần ngẫu nhiên, quốc gia gán ngẫu nhiên, User-Agent tổng hợp đổi liên tục (khiến `dormant_account_login` và `rare_network_login` báo nhiều) — xem [`rule-replay.md`](rule-replay.md) mục 1 và 5.
- Giai đoạn `late` (12/2020–02/2021) có phân phối đổi so với train (lưu lượng tấn công tăng, tỉ lệ đăng nhập thành công giảm): chênh lệch train → late cho biết ngưỡng chịu trôi phân phối đến đâu.
