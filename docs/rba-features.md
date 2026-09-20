# Đặc trưng v2 (MR3)

50 đặc trưng dùng chung cho huấn luyện trên RBA và cho luồng đăng nhập thật. Mã: [`features.py`](../backend/ml/rba/features.py) (đặc tả), [`features_sql.py`](../backend/ml/rba/features_sql.py) (đường nhanh DuckDB), [`build_features.py`](../backend/ml/rba/build_features.py) (dựng bảng cho mẫu RBA).

## 1. Nguyên tắc

**Một định nghĩa, hai cách tính.** `features.py` là đặc tả bằng Python thuần: cho một sự kiện và quá khứ của nó, trả về đặc trưng. Luồng realtime (MR12) dựng quá khứ từ DB rồi gọi cùng hàm. `features_sql.py` tính đúng các đặc trưng đó bằng window function DuckDB để chạy trên 31 triệu dòng. Hai bên **được chứng minh bằng test là cho cùng kết quả**, nên không có "lệch train/serve".

**Chống rò rỉ tương lai.**
- "Trước đó" = sự kiện có timestamp (micro-giây) **nhỏ hơn hẳn** sự kiện hiện tại. Sự kiện cùng micro-giây loại trừ lẫn nhau.
- Cửa sổ thời gian là `(t − W, t)`, mở ở đầu cũ: sự kiện cách đúng `W` không được tính.
- Không có đặc trưng nào dùng nhãn (`Is Attack IP`, `Is Account Takeover`). Đặc trưng theo IP mô tả **hành vi** của IP (số user bị thử, tỉ lệ thất bại...), không phải danh tính IP hay việc nó có nằm trong danh sách tấn công.
- Test chứng minh: thêm sự kiện tương lai không làm đổi đặc trưng của sự kiện cũ (trên dữ liệu ngẫu nhiên và trên dữ liệu RBA thật).

**Tài khoản không tồn tại.** Trong RBA là "thùng chứa" `-4324475583306591935` (14 triệu lần thử); trong hệ thống của dự án là `user_id = NULL`. Với sự kiện này, đặc trưng theo user là NaN; đặc trưng cấp IP/ASN và độ hiếm toàn cục vẫn tính. Những sự kiện đó **vẫn được đếm** vào cửa sổ IP/ASN (chúng là phần lớn lưu lượng tấn công).

**Lịch sử chỉ tính lần đăng nhập thành công** khi đánh giá "mới lạ" (theo Freeman et al.): một quốc gia chỉ từng xuất hiện ở lần thất bại vẫn là lạ. Riêng nhịp/tần suất tính trên mọi lần thử.

**Khởi động (warm-up).** Đếm toàn cục lũy kế còn quá ít trong 14 ngày đầu (trước 17/02/2020), nên các dòng đó có cờ `in_warmup` và **không dùng làm dòng huấn luyện/đánh giá** (vẫn góp vào lịch sử).

## 2. Danh mục đặc trưng

Ký hiệu: `t` = thời điểm sự kiện; `S` = các lần đăng nhập **thành công** trước đó của tài khoản; NaN = không xác định.

### `cur` — sự kiện hiện tại (2)
| Đặc trưng | Ý nghĩa |
|---|---|
| `cur_success` | lần này thành công (1) hay thất bại (0) |
| `cur_device_code` | mobile 0, desktop 1, tablet 2, bot 3, unknown 4, thiếu 5 |

### `novelty` — có mới so với lịch sử thành công của tài khoản không (9)
`new_country`, `new_asn`, `new_ip`, `new_ua`, `new_browser`, `new_os`, `new_device`, `new_browser_family`, `new_os_family`: 1 nếu giá trị chưa từng xuất hiện trong `S`, ngược lại 0. Bản `*_family` bỏ số phiên bản (`Chrome 90.0` → `Chrome`) vì đổi phiên bản là chuyện thường của người dùng thật, còn đổi họ trình duyệt/hệ điều hành đáng ngờ hơn. Tài khoản chưa có lần thành công nào: mọi cờ = 1 (đọc cùng `u_n_success`).

### `history` — độ dày lịch sử, phục vụ cold-start (3)
`u_n_attempts`, `u_n_success` (số lần thử / thành công trước đó), `u_age_days` (số ngày từ lần thử đầu tiên). 39,7% user RBA chỉ có 1 lần đăng nhập nên mô hình phải biết khi nào đang thiếu lịch sử.

### `rhythm` — nhịp và tần suất của tài khoản (8)
`u_secs_since_last`, `u_secs_since_last_success`, `u_fail_streak` (số lần thất bại liên tiếp ngay trước, tính từ lần thành công gần nhất), `u_attempts_1h`, `u_attempts_24h`, `u_fails_24h`, `u_distinct_ips_24h`, `u_distinct_countries_7d`.

### `freeman` — log-tỉ-số khả năng theo từng thuộc tính (8)
Theo Freeman et al. (NDSS 2016): mức độ giá trị hiện tại **điển hình của dân số** hơn là **điển hình của riêng tài khoản này**. Với thuộc tính `a` có giá trị `v`:

```
p_g(v)  = (đếm toàn cục lần đăng nhập thành công của tài khoản thật có giá trị v + 1) / (tổng + 1)
p_u(v)  = (số lần v trong S + α·p_g(v)) / (|S| + α)          α = 1, làm mịn về phía p_g
llr_a   = ln p_g(v) − ln p_u(v)
```
Dương = lạ với chính tài khoản này (càng dương càng đáng ngờ); âm = quen thuộc. Tài khoản chưa có lịch sử: `p_u = p_g` nên `llr = 0` (không có thông tin). Thuộc tính: `ip, country, asn, ua, browser, os, device`; `llr_sum` là tổng (đây cũng là baseline Freeman ở MR5). Đưa từng thành phần vào mô hình thay vì nhân cứng để mô hình tự học trọng số.

### `rarity` — độ hiếm toàn cục (7)
`rare_a = −ln p_g(v)` cho cùng 7 thuộc tính. Không cần lịch sử của tài khoản nên vẫn có ý nghĩa với user mới.

### `infra_ip` — hành vi của IP trong 24h qua, trên mọi sự kiện (7)
`ip_attempts_1h`, `ip_attempts_24h`, `ip_fail_ratio_24h`, `ip_distinct_users_24h` (số tài khoản thật khác nhau bị thử), `ip_unknown_attempts_24h` (số lần thử vào tài khoản không tồn tại), `ip_distinct_ua_24h`, `ip_prior_attempts_all` (tổng số lần IP này từng xuất hiện).

### `infra_asn` — hành vi của ASN trong 24h qua (6)
`asn_attempts_1h`, `asn_attempts_24h`, `asn_fail_ratio_24h`, `asn_distinct_users_24h`, `asn_distinct_ips_24h`, `asn_unknown_share_24h`. NaN khi không biết ASN (ví dụ chưa có file GeoLite2-ASN).

## 3. Dùng trong luồng thật (MR12)

Luồng thật dựng `HistorySummary` bằng truy vấn DB rồi gọi `features_from_summary`:

| Thành phần | Nguồn |
|---|---|
| `user_events` | lịch sử `login_events` của tài khoản (chỉ trước thời điểm hiện tại) |
| `ip_events`, `ip_prior_attempts_all` | `login_events` cùng IP trong 24h, và đếm tổng |
| `asn_events` | `login_events` cùng ASN trong 24h (cần cột `asn` và file GeoLite2-ASN) |
| `global_counts` | đếm các lần đăng nhập thành công của tài khoản thật theo từng giá trị thuộc tính; làm mới định kỳ (xấp xỉ có chủ đích: số đếm toàn cục "tính đến lần làm mới gần nhất") |

Trình duyệt/hệ điều hành phải theo cùng dạng chuỗi như RBA (`họ + phiên bản`, ví dụ `Chrome Mobile 46.0.2490`): `parse_user_agent()` ([`device.py`](../backend/app/utils/device.py)) trả họ và phiên bản riêng để ghép lại.

## 4. Tái lập và kiểm chứng

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.build_features   # -> ml/data/rba/rba_model_table.parquet (chạy nền, vài chục phút)
venv\Scripts\python.exe -m pytest tests/test_rba_features.py tests/test_rba_features_equivalence.py tests/test_rba_features_real_data.py
```

| Test | Chứng minh |
|---|---|
| `test_rba_features.py` | ngữ nghĩa từng nhóm, tính tay trên ca nhỏ (biên cửa sổ, sự kiện trùng giờ, chuỗi thất bại, LLR...) |
| `test_rba_features_equivalence.py` | SQL = đặc tả Python trên ~1.270 sự kiện ngẫu nhiên có cố ý trùng micro-giây, sát biên 1h/24h/7d, tài khoản không tồn tại, ASN/quốc gia/UA thiếu. Đã kiểm tra test **bắt được lỗi cố ý**: đổi biên cửa sổ làm lệch 15 đặc trưng, coi sự kiện cùng giờ là "trước đó" làm lệch 31 đặc trưng |
| `test_rba_features_equivalence.py` (rò rỉ) | thêm sự kiện tương lai không đổi đặc trưng cũ |
| `test_rba_features_real_data.py` | cùng phép so trên lát 60.000 dòng RBA thật và kiểm tra rò rỉ trên dữ liệu thật |

## 5. Ghi chú kỹ thuật

- Trên DuckDB, `COUNT(*) FILTER (WHERE …) OVER (… RANGE UNBOUNDED PRECEDING …)` chạy theo đường bậc hai trên partition lớn (347 giây cho 3 triệu dòng ở một thuộc tính); `SUM(CASE WHEN … THEN 1 ELSE 0 END)` cho cùng kết quả trong 12 giây. Bản SQL dùng cách thứ hai.
- Đếm toàn cục lũy kế tính bằng "gom theo (giá trị, thời điểm) rồi cộng dồn ROWS" thay vì window RANGE: cho cùng kết quả, xử lý đúng sự kiện trùng micro-giây và nhanh hơn 3–11 lần (cửa sổ "tổng": 27 → 2,4 giây cho 3 triệu dòng).
- Giai đoạn hạ tầng (cửa sổ IP/ASN, chỉ nhìn lại ≤ 24h) chia theo **khối thời gian** ~3 triệu dòng, mỗi khối kèm 24h ngữ cảnh phía trước: kết quả giống hệt tính một lượt (test với 3 cỡ khối), nhưng thời gian gần tuyến tính và bộ nhớ bị chặn. Tính một lượt trên 31 triệu dòng chạy siêu tuyến tính, tranh RAM với các ứng dụng khác và có lúc treo hơn 12 phút.
- Một số đặc trưng có tỉ lệ NaN cao **có chủ đích** (ví dụ mọi đặc trưng theo user với tài khoản không tồn tại). LightGBM xử lý NaN trực tiếp; mô hình không hỗ trợ NaN (Isolation Forest, LOF, Autoencoder) sẽ được điền giá trị ở bước huấn luyện (MR6).
- Đặc trưng địa lý và giờ trong ngày **không có** ở đây vì RBA không hỗ trợ (xem [`rba-data-card.md`](rba-data-card.md) mục 4); chúng thuộc mô hình B trên simulator (MR6).

## 6. Kết quả dựng trên dữ liệu thật

Chạy `python -m ml.rba.build_features` (31.269.264 dòng nguồn, đầu ra cho mẫu 2.707.021 dòng): **30 phút**, bảng `rba_model_table.parquet` 222 MiB (61 cột: 50 đặc trưng float32 + metadata + cờ `in_warmup`; 103.672 dòng warm-up, 3,8%). Thời gian: đếm toàn cục ~8 phút, hạ tầng ~15 phút (11 khối thời gian), theo user và ghi ~5 phút.

Kiểm chứng trên bảng đã dựng: đối chiếu với đặc tả Python ở 40 dòng có lịch sử (0 lệch); 6 bất biến trong `tests/test_rba_model_table.py` (khớp mẫu từng dòng, không vô cực, số đếm không âm, `u_n_success ≤ u_n_attempts`, số lần thử của một tài khoản không bao giờ giảm theo thời gian...).

Tỉ lệ NaN (đều có chủ đích): `ip_fail_ratio_24h` 47% (IP không có lượt nào khác trong 24h), `u_secs_since_last_success` 22% (chưa từng thành công), `u_age_days` và `u_secs_since_last` 15% (lần đầu của tài khoản), `asn_fail_ratio_24h` và `asn_unknown_share_24h` 0,5%. Mọi đặc trưng theo user đều có giá trị cho mọi dòng vì mẫu chỉ gồm tài khoản thật.

### Tín hiệu sơ bộ (chỉ nhìn trên tập `val`, chưa đụng vào `test`)

AUC đơn biến (mỗi đặc trưng đứng một mình, càng gần 1 càng phân biệt tốt):

| Nhãn | Đặc trưng mạnh nhất (AUC) |
|---|---|
| `Is Attack IP` (val, có trọng số) | `asn_fail_ratio_24h` 0,85 · `asn_unknown_share_24h` 0,83 · `ip_prior_attempts_all` 0,83 · `ip_distinct_ua_24h` 0,80 · `rare_ip` 0,80 · `rare_country` 0,78 |
| ATO (17 ca tháng 08/2020 so với 155.579 đăng nhập hợp lệ) | `rare_country` 0,99 · `rare_asn` 0,99 · `llr_country` 0,98 · `asn_distinct_users_24h` 0,98 · `new_country` 0,94 |

Quan sát trên cả 140 ATO thành công so với đăng nhập hợp lệ thành công: quốc gia mới 88% so với 16%; ASN mới 91% so với 23%; `rare_asn` trung bình 11,3 so với 2,8; hoạt động ASN 24h thấp (ATO đến từ ASN ít lưu lượng khác). **54/140 ATO nhắm vào tài khoản chưa có lần đăng nhập thành công nào** — mô hình chỉ dựa vào lịch sử cá nhân sẽ mù với nhóm này, còn độ hiếm toàn cục thì không.

⚠️ Đọc các con số này thận trọng:
1. Chỉ 17 ca ATO trên val (38 trên test): AUC đơn biến 0,98 trên 17 mẫu chưa đáng tin ở chữ số thập phân thứ hai; khoảng tin cậy sẽ có ở MR4.
2. Bộ dữ liệu là **tổng hợp** và giữ nguyên phân phối tần suất của dữ liệu gốc: việc ATO rơi vào quốc gia/ASN hiếm phản ánh cách sinh dữ liệu, chưa chắc đúng ngoài đời, nơi kẻ tấn công cố dùng ASN phổ biến (VPN cùng nước, hạ tầng dân cư). Đó là lý do MR4 mô phỏng kẻ tấn công **VPN** và **Targeted** — phép thử trung thực cho điểm yếu này.
3. Đây mới là tín hiệu từng đặc trưng riêng lẻ, chưa phải hiệu năng của mô hình (MR5–MR6).
