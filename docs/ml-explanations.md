# Giải thích cảnh báo (MR8)

Mã: [`explain.py`](../backend/ml/rba/explain.py) (SHAP, z-score, gộp yếu tố, viết câu, ngữ cảnh) · [`explain_eval.py`](../backend/ml/rba/explain_eval.py) (đo độ trung thực, bảng toàn cục, ví dụ, ngưỡng vận hành, độ trễ). Kiểm thử: `tests/test_rba_explain.py` (21), `tests/test_rba_explain_eval.py` (13), `tests/test_rba_audit.py` (thêm 2). Số liệu chạy trên giai đoạn **test** của bộ RBA tổng hợp ([`rba-data-card.md`](rba-data-card.md)); **mục 1–8 chạy trên hybrid MR6** (`python -m ml.rba.explain_eval all --hybrid hybrid`); sau khi chốt mô hình ở CP2 ([`ml-model-selection.md`](ml-model-selection.md)) các phép đo chính được lặp lại trên **`hybrid_cp2`** ở mục 9 (kết luận không đổi). Model card: [`model-card-rba.md`](model-card-rba.md).

## Tóm tắt

1. **Mỗi cảnh báo có giải thích tối đa 3 yếu tố, mỗi yếu tố một câu ngắn**, kèm so sánh "thường … → nay …" khi biết lịch sử tài khoản (ví dụ `quốc gia: thường NO → nay LV (hiếm 0.01%)`). Câu có độ dài trung vị 57–118 ký tự, dài nhất 151; không cảnh báo nào bị bỏ trống. Thành phần LightGBM dùng **SHAP** (TreeSHAP của LightGBM, trùng thư viện `shap` từng chữ số), thành phần không giám sát dùng **z-score**.
2. **Giải thích trỏ đúng thứ mô hình dựa vào.** Xoá (đưa về mức thường thấy) các yếu tố được nêu làm **99–100% cảnh báo biến mất**, trong khi xoá cùng số yếu tố ngẫu nhiên chỉ làm mất 49–90%. Chỉ xoá yếu tố đứng đầu: 80–100% so với 25–50% ngẫu nhiên. Ở thành phần không giám sát giải thích theo từng cảnh báo còn tốt hơn bảng "yếu tố quan trọng toàn cục" (báo nhầm: 83% so với 45%); ở LightGBM hai cách bằng nhau vì các cảnh báo của cùng một thành phần khá giống nhau.
3. ⚠️ **Ba yếu tố nêu ra là những yếu tố chủ đạo, không phải toàn bộ lý do.** Chỉ giữ chúng (xoá mọi yếu tố khác) thì bộ phát hiện không giám sát còn khoảng 68% điểm và chỉ 0–16% cảnh báo còn tồn tại; `ip_tan_cong` còn 66% điểm (20–49% cảnh báo còn); riêng `chiem_tai_khoan` giữ ≥ 100% điểm (90–100% cảnh báo còn). Cảnh báo sát ngưỡng nên rất nhạy với phần điểm bị bỏ.
4. **Giải thích làm lộ một điểm yếu của bộ mô phỏng kẻ tấn công** (mục 6): thành phần `chiem_tai_khoan` dựa 73% vào "IP mới" và nhiều cảnh báo nêu tỉ lệ thất bại/lịch sử của IP. Kiểm định dấu vân tay **có điều kiện** (so đăng nhập giả với đăng nhập hợp lệ *cũng dùng IP mới*) cho AUC 0,67–0,72 ở nhóm IP và 0,67–0,71 ở nhóm độ hiếm, trong khi kiểm định tổng thể ở MR6 chỉ thấy ≈ 0,5. Kết quả trên kẻ tấn công mô phỏng vì vậy là **cận trên**; bằng chứng về ATO thật (MR6–MR7) không đổi.
5. **Ngưỡng vận hành** (mục 5): 2,410 cho ~102 cảnh báo nhầm trên 10.000 đăng nhập hợp lệ thành công, 3,365 cho ~10. Độ chính xác của cảnh báo phụ thuộc gần như hoàn toàn vào tỉ lệ tấn công thật (0,26% khi 1 trên 10.000; 20,7% khi 1 trên 100), và **siết ngưỡng từ 1% xuống 0,1% không làm cảnh báo chính xác hơn** vì recall ATO tụt cùng tỉ lệ (26,3% → 2,6%).
6. **Chi phí thấp:** giải thích một cảnh báo mất ~3,6 ms (p50) / 22 ms (p95). Chỉ tính cho cảnh báo (~1% đăng nhập), làm ở tiến trình nền nên không chặn `/login`.

## 1. Cách giải thích hoạt động

### 1.1 Hai phương pháp, tuỳ thành phần đã báo động

Hybrid báo động khi bất kỳ thành phần nào có xác suất đuôi nhỏ nhất ([`ensemble.py`](../backend/ml/rba/ensemble.py)); thành phần đó quyết định cách giải thích:

| Thành phần | Mô hình | Phương pháp | Đóng góp của một đặc trưng là |
|---|---|---|---|
| `ip_tan_cong`, `chiem_tai_khoan` | LightGBM có giám sát | **SHAP** (TreeSHAP: `predict(pred_contrib=True)`) | phần điểm log-odds đặc trưng đó cộng vào so với giá trị nền; tổng đóng góp + nền = điểm thô |
| `bat_thuong` (cùng kNN, Autoencoder) | Isolation Forest không giám sát | **z-score fallback** | số độ lệch chuẩn của đặc trưng so với đăng nhập bình thường của tập huấn luyện, trong đúng không gian mô hình nhìn thấy (log1p, chuẩn hoá), chỉ tính theo hướng đáng ngờ |

- **SHAP** kiểm chứng trên 2.000 dòng thật của `gbm_attack_ip`: tổng đóng góp + giá trị nền khớp điểm thô đến 7,5·10⁻¹⁵ và khớp `shap.TreeExplainer` với sai khác 0,0. Test dùng LightGBM nhỏ trên dữ liệu tổng hợp để tái kiểm tra hai điều đó ở mọi lần chạy. Dùng bản có sẵn của LightGBM để luồng realtime không phải nạp `shap`.
- **z-score** là phương án dự phòng vì Isolation Forest không có nhãn nên không có "đóng góp vào xác suất". Hướng đáng ngờ: mặc định *giá trị cao*; *ít lịch sử* (`u_n_attempts`, `u_n_success`, `u_age_days` thấp); *cả hai hướng* với 6 đặc trưng lưu lượng nhà mạng (ATO đến từ nhà mạng lưu lượng cực thấp, tấn công hàng loạt từ nhà mạng lưu lượng cực cao đều lạ). Bỏ `cur_success` (hằng số do cổng), `cur_device_code` (mã hạng mục) và `llr_sum` (tổng của đặc trưng khác).
- `llr_sum` là tổng của bảy `llr_*`: phần SHAP của nó được **chia lại** cho các `llr_*` theo tỉ lệ phần dương của từng `llr_*` (bản `llr_*` âm = quen thuộc, không nhận phần), để giải thích nói được "quốc gia lạ" thay vì "tổng thể lạ".

### 1.2 Gộp 50 đặc trưng thành 9 yếu tố người đọc hiểu được

`new_country`, `llr_country`, `rare_country` cùng nói về quốc gia; nếu để nguyên, top-3 của một cảnh báo có thể toàn là quốc gia. Đóng góp SHAP được **cộng dồn** trong yếu tố (phép cộng giữ nguyên tổng), z-score lấy **giá trị lớn nhất** (các đặc trưng cùng yếu tố đo trùng nhau; đã thử thay bằng tổng, L2, tổng bình phương: kết quả tương đương trên cảnh báo `bat_thuong` — thăm dò một lần, không nằm trong mã).

| Yếu tố | Đặc trưng |
|---|---|
| quốc gia | `new_country`, `llr_country`, `rare_country`, `u_distinct_countries_7d` |
| nhà mạng | `new_asn`, `llr_asn`, `rare_asn` |
| IP | `new_ip`, `llr_ip`, `rare_ip`, `u_distinct_ips_24h` |
| thiết bị/trình duyệt | `cur_device_code` và 14 đặc trưng `new_*` / `llr_*` / `rare_*` của UA, trình duyệt, hệ điều hành, loại thiết bị |
| độ dày lịch sử tài khoản | `u_n_attempts`, `u_n_success`, `u_age_days` |
| nhịp đăng nhập | `u_secs_since_last`, `u_secs_since_last_success`, `u_attempts_1h`, `u_attempts_24h` |
| thất bại/dò mật khẩu | `cur_success`, `u_fail_streak`, `u_fails_24h` |
| hoạt động của IP | 7 đặc trưng `infra_ip` ([`rba-features.md`](rba-features.md)) |
| hoạt động của nhà mạng | 6 đặc trưng `infra_asn` |

**Chọn yếu tố:** lấy tối đa 3 yếu tố có điểm dương lớn nhất; bỏ yếu tố nhỏ — SHAP dưới 0,2 log-odds hoặc dưới 10% tổng phần dương; z-score dưới 1,5 độ lệch chuẩn. Ngưỡng là hằng số trong `explain.py`, không tinh chỉnh trên dữ liệu.

### 1.3 Viết câu

Định dạng ngắn giống cảnh báo hiện tại (`lệch giờ 3.2h (+20đ), vị trí lạ (+30đ)`): các yếu tố cách nhau bằng `;`, số thập phân dùng dấu chấm như chuỗi cảnh báo hiện có. Mỗi yếu tố một câu, lấy từ **đặc trưng đóng góp nhiều nhất trong yếu tố**:

| Dạng | Ví dụ | Khi nào |
|---|---|---|
| thuộc tính mới + có ngữ cảnh | `quốc gia: thường NO → nay LV (hiếm 0.01%)` | biết giá trị quen thuộc của tài khoản |
| thuộc tính mới, không ngữ cảnh | `nhà mạng mới (hiếm <0.01%, thường 13%)` | tài khoản chưa có lịch sử hoặc chưa dựng được ngữ cảnh |
| hiếm nhưng không mới | `quốc gia ít gặp: 15% (thường 65%)` | "hiếm" khi dưới 5% đăng nhập thành công của cả hệ thống, "ít gặp" nếu trên |
| quen thuộc (mô hình vẫn coi là bằng chứng) | `nhà mạng quen thuộc với tài khoản` | SHAP dương nhưng giá trị thực ra quen — không được gọi là "lạ" |
| số đếm/tỉ lệ | `IP thử 35 tài khoản/24h (thường 0)` | "thường" = trung vị đăng nhập hợp lệ thành công ở train |
| khoảng cách | `cách lần thành công trước 45 ngày (thường 2 ngày)` | "thường" là trung vị khoảng cách **riêng của tài khoản** nếu có ngữ cảnh, không thì của dân số |

**Ngữ cảnh** (`Context`, [`explain.py`](../backend/ml/rba/explain.py)): từ các lần **thành công** của tài khoản *trước* đăng nhập đang xét lấy giá trị hay gặp nhất của quốc gia, nhà mạng, trình duyệt, hệ điều hành, loại thiết bị (bỏ số phiên bản) và trung vị khoảng cách giữa các lần thành công; so với giá trị lần này. Luồng realtime (MR12) dựng nó từ `login_events` bằng cùng hàm `build_context`. Không có lịch sử thì câu chỉ có "mới"/"hiếm", không bịa "thường".

**Giá trị thiếu** có chủ đích (IP chưa có lượt thử nào khác trong 24h, tài khoản chưa từng thành công...) có câu riêng, không in `nan`.

## 2. Ví dụ trên ca thật của RBA

Ngưỡng hybrid 2,410 (FPR 1%), ba ca ở các phân vị 15/50/85% của điểm trong mỗi nhóm (không chọn ca đẹp). Cột phải dùng lịch sử tài khoản đọc từ dữ liệu gốc. Các ATO này là 3 trong 27 ATO bị báo (hybrid bỏ sót 103/130 ATO, xem [`ml-holdout-ablation.md`](ml-holdout-ablation.md)).

| Nhóm | Điểm | Loại | Giải thích (chỉ có đặc trưng) | Giải thích (thêm ngữ cảnh tài khoản) |
|---|---|---|---|---|
| ATO thật bị báo | 2.66 | đăng nhập bất thường (z-score) | nhà mạng mới (hiếm <0.01%, thường 13%); quốc gia mới (hiếm 0.04%, thường 65%); nhà mạng có 1 lượt thử/24h (thường 16k) | nhà mạng: thường AS500068 → nay AS505051 (hiếm <0.01%); quốc gia: thường NO → nay CL (hiếm 0.04%); nhà mạng có 1 lượt thử/24h (thường 16k) |
| ATO thật bị báo | 3.20 | đăng nhập bất thường (z-score) | quốc gia mới (hiếm 0.01%, thường 65%); nhà mạng mới (hiếm <0.01%, thường 13%); 5 IP khác nhau/24h (thường 0) | quốc gia: thường NO → nay LV (hiếm 0.01%); nhà mạng: thường AS207674 → nay AS61353 (hiếm <0.01%); 5 IP khác nhau/24h (thường 0) |
| ATO thật bị báo | 2.47 | đăng nhập bất thường (z-score) | nhà mạng mới (hiếm <0.01%, thường 13%); quốc gia mới (hiếm 0.12%, thường 65%); nhà mạng có 0 lượt thử/24h (thường 16k) | nhà mạng: thường AS29695 → nay AS3280 (hiếm <0.01%); quốc gia: thường NO → nay RO (hiếm 0.12%); nhà mạng có 0 lượt thử/24h (thường 16k) |
| IP tấn công bị báo | 3.02 | IP có hành vi tấn công hàng loạt (SHAP) | quốc gia mới; nhà mạng có 80% lượt thử thất bại (thường 36%); IP đã gặp 627 lần (thường 6) | quốc gia mới: US; nhà mạng có 80% lượt thử thất bại (thường 36%); IP đã gặp 627 lần (thường 6) |
| IP tấn công bị báo | 2.72 | IP có hành vi tấn công hàng loạt (SHAP) | quốc gia ít gặp: 15% (thường 65%); nhà mạng có 78% lượt thử thất bại (thường 36%); IP đã gặp 153 lần (thường 6) | quốc gia ít gặp US: 15% (thường 65%); nhà mạng có 78% lượt thử thất bại (thường 36%); IP đã gặp 153 lần (thường 6) |
| IP tấn công bị báo | 5.08 | IP có hành vi tấn công hàng loạt (SHAP) | nhà mạng có 78% lượt thử thất bại (thường 36%); quốc gia mới; IP đã gặp 689 lần (thường 6) | nhà mạng có 78% lượt thử thất bại (thường 36%); quốc gia mới: US; IP đã gặp 689 lần (thường 6) |
| Đăng nhập hợp lệ bị báo nhầm | 3.24 | nghi chiếm tài khoản (SHAP) | IP mới; cách lần thử trước 23 giây (thường 2 ngày); hệ điều hành mới | IP mới; cách lần thử trước 23 giây (thường 2 ngày); hệ điều hành: thường Mac OS X → nay iOS |
| Đăng nhập hợp lệ bị báo nhầm | 2.49 | nghi chiếm tài khoản (SHAP) | IP mới; cách lần thành công trước 8 phút (thường 3 ngày); trình duyệt lạ với tài khoản (hiếm 4.7%) | IP mới; cách lần thành công trước 8 phút (thường 3 ngày); trình duyệt lạ với tài khoản (hiếm 4.7%) |
| Đăng nhập hợp lệ bị báo nhầm | 2.72 | đăng nhập bất thường (z-score) | IP thử 154 tài khoản/24h (thường 0); nhà mạng dùng 2 IP/24h (thường 3036) | IP thử 154 tài khoản/24h (thường 0); nhà mạng dùng 2 IP/24h (thường 3036) |

Đọc các ví dụ:
- **ATO thật:** nhà mạng và quốc gia gần như chưa từng thấy (`<0.01%` đăng nhập thành công), nhà mạng gần như không có lưu lượng khác. Các ASN ≥ 500.000 (như `AS505051`) là giá trị nhân tạo do bộ dữ liệu sinh ra ([`rba-data-card.md`](rba-data-card.md)). Đây là chữ ký ATO của bộ dữ liệu tổng hợp (mục 4 và [`ml-holdout-ablation.md`](ml-holdout-ablation.md) mục 5.1), **không nên đọc là "kẻ tấn công thật thường dùng nhà mạng hiếm"**.
- **IP tấn công:** đặc điểm của IP (nhà mạng có ~80% lượt thử thất bại, IP đã xuất hiện hàng trăm lần), không phải của tài khoản; nên ngữ cảnh chỉ thêm giá trị quốc gia.
- **Báo nhầm:** người dùng đổi thiết bị (Mac → iPhone) ở IP mới, một lần khác đăng nhập từ IP đã thử 154 tài khoản trong 24h (RBA có thể chứa tấn công chưa gắn nhãn nên một phần "báo nhầm" có thể là đúng). Giải thích giúp quản trị viên nhận ra kiểu báo nhầm trong vài giây — nền tảng cho vòng phản hồi ở MR15.

## 3. Giải thích có trung thực không? Phép thử "xoá / giữ yếu tố"

Một giải thích đọc trôi chảy vẫn có thể sai. Phép thử ([`explain_eval.py`](../backend/ml/rba/explain_eval.py)): với các đăng nhập **bị hybrid báo**, đưa các yếu tố được chọn về mức thường thấy (trung vị đăng nhập hợp lệ ở train; `llr_sum` được tính lại từ các `llr_*`) rồi chấm lại **đúng thành phần đã báo**, không qua cổng. Ba cách chọn cùng số yếu tố mỗi cảnh báo:
- **Giải thích:** đúng các yếu tố nêu ra (tối đa 3);
- **Ngẫu nhiên:** bốc ngẫu nhiên trong 9 yếu tố, trung bình 5 lần bốc;
- **Quan trọng toàn cục:** những yếu tố có đóng góp trung bình cao nhất của thành phần đó, giống nhau cho mọi cảnh báo — giải thích từng ca chỉ có giá trị hơn một bảng chung nếu vượt được nhóm này.

Cảnh báo lấy ở giai đoạn test theo ngưỡng 2,410: 718 trên 5.709 dòng IP tấn công, 2.141 trên 5.911 kẻ tấn công mô phỏng, 27 trên 130 ATO thật (cả 141 ca trừ warm-up: lấy hết cho đủ mẫu, **chỉ để đo giải thích, không để đo khả năng phát hiện**), 667 trên 60.000 đăng nhập hợp lệ bốc ngẫu nhiên. Mỗi cảnh báo do thành phần có xác suất đuôi nhỏ nhất báo, nên một nhóm có thể gồm cảnh báo của nhiều thành phần; bảng chỉ liệt kê các cặp (nhóm, thành phần) có ít nhất một cảnh báo.

**Xoá các yếu tố nêu ra → phần cảnh báo BIẾN MẤT (cao = giải thích trỏ đúng thứ mô hình dựa vào)**

| Nhóm cảnh báo | Thành phần | Số cảnh báo | Yếu tố/cảnh báo | Giải thích | Ngẫu nhiên | Quan trọng toàn cục |
|---|---|---|---|---|---|---|
| IP tấn công (test) | `ip_tan_cong` | 696 | 2,94 | **100%** | 80% | 100% |
| IP tấn công (test) | `chiem_tai_khoan` | 12 | 2,25 | **100%** | 58% | 100% |
| IP tấn công (test) | `bat_thuong` | 10 | 3,00 | **100%** | 82% | 100% |
| Kẻ tấn công mô phỏng (test) | `ip_tan_cong` | 5 | 2,80 | **100%** | 84% | 100% |
| Kẻ tấn công mô phỏng (test) | `chiem_tai_khoan` | 2.069 | 2,49 | **100%** | 49% | 100% |
| Kẻ tấn công mô phỏng (test) | `bat_thuong` | 67 | 2,94 | **100%** | 78% | 99% |
| ATO thật (cả 141 ca) | `chiem_tai_khoan` | 2 | 3,00 | **100%** | 60% | 100% |
| ATO thật (cả 141 ca) | `bat_thuong` | 25 | 3,00 | **100%** | 90% | 100% |
| Đăng nhập hợp lệ (test) | `ip_tan_cong` | 98 | 2,84 | **100%** | 81% | 100% |
| Đăng nhập hợp lệ (test) | `chiem_tai_khoan` | 233 | 2,30 | **100%** | 56% | 100% |
| Đăng nhập hợp lệ (test) | `bat_thuong` | 336 | 2,85 | **99%** | 72% | 97% |

**Chỉ xoá yếu tố ĐỨNG ĐẦU → phần cảnh báo biến mất**

| Nhóm cảnh báo | Thành phần | Số cảnh báo | Yếu tố/cảnh báo | Giải thích | Ngẫu nhiên | Quan trọng toàn cục |
|---|---|---|---|---|---|---|
| IP tấn công (test) | `ip_tan_cong` | 696 | 2,94 | **100%** | 38% | 100% |
| IP tấn công (test) | `chiem_tai_khoan` | 12 | 2,25 | **100%** | 38% | 100% |
| IP tấn công (test) | `bat_thuong` | 10 | 3,00 | **90%** | 42% | 90% |
| Kẻ tấn công mô phỏng (test) | `ip_tan_cong` | 5 | 2,80 | **100%** | 36% | 100% |
| Kẻ tấn công mô phỏng (test) | `chiem_tai_khoan` | 2.069 | 2,49 | **100%** | 25% | 100% |
| Kẻ tấn công mô phỏng (test) | `bat_thuong` | 67 | 2,94 | **82%** | 37% | 73% |
| ATO thật (cả 141 ca) | `chiem_tai_khoan` | 2 | 3,00 | **100%** | 50% | 100% |
| ATO thật (cả 141 ca) | `bat_thuong` | 25 | 3,00 | **80%** | 34% | 72% |
| Đăng nhập hợp lệ (test) | `ip_tan_cong` | 98 | 2,84 | **100%** | 45% | 100% |
| Đăng nhập hợp lệ (test) | `chiem_tai_khoan` | 233 | 2,30 | **100%** | 35% | 100% |
| Đăng nhập hợp lệ (test) | `bat_thuong` | 336 | 2,85 | **83%** | 32% | 45% |

**Chỉ GIỮ các yếu tố nêu ra (xoá mọi yếu tố còn lại) → phần cảnh báo CÒN**

| Nhóm cảnh báo | Thành phần | Số cảnh báo | Yếu tố/cảnh báo | Giải thích | Ngẫu nhiên | Quan trọng toàn cục |
|---|---|---|---|---|---|---|
| IP tấn công (test) | `ip_tan_cong` | 696 | 2,94 | **49%** | 0% | 5% |
| IP tấn công (test) | `chiem_tai_khoan` | 12 | 2,25 | **92%** | 5% | 50% |
| IP tấn công (test) | `bat_thuong` | 10 | 3,00 | **0%** | 0% | 10% |
| Kẻ tấn công mô phỏng (test) | `ip_tan_cong` | 5 | 2,80 | **20%** | 0% | 0% |
| Kẻ tấn công mô phỏng (test) | `chiem_tai_khoan` | 2.069 | 2,49 | **93%** | 11% | 74% |
| Kẻ tấn công mô phỏng (test) | `bat_thuong` | 67 | 2,94 | **16%** | 1% | 10% |
| ATO thật (cả 141 ca) | `chiem_tai_khoan` | 2 | 3,00 | **100%** | 10% | 50% |
| ATO thật (cả 141 ca) | `bat_thuong` | 25 | 3,00 | **0%** | 0% | 0% |
| Đăng nhập hợp lệ (test) | `ip_tan_cong` | 98 | 2,84 | **23%** | 0% | 1% |
| Đăng nhập hợp lệ (test) | `chiem_tai_khoan` | 233 | 2,30 | **90%** | 8% | 60% |
| Đăng nhập hợp lệ (test) | `bat_thuong` | 336 | 2,85 | **10%** | 1% | 1% |

**Chỉ GIỮ các yếu tố nêu ra → điểm còn lại so với điểm gốc (điểm cảnh báo sát ngưỡng nên phép thử trên khắt khe hơn)**

| Nhóm cảnh báo | Thành phần | Số cảnh báo | Yếu tố/cảnh báo | Giải thích | Ngẫu nhiên | Quan trọng toàn cục |
|---|---|---|---|---|---|---|
| IP tấn công (test) | `ip_tan_cong` | 696 | 2,94 | **66%** | 16% | 37% |
| IP tấn công (test) | `chiem_tai_khoan` | 12 | 2,25 | **125%** | 26% | 103% |
| IP tấn công (test) | `bat_thuong` | 10 | 3,00 | **66%** | 32% | 62% |
| Kẻ tấn công mô phỏng (test) | `ip_tan_cong` | 5 | 2,80 | **67%** | 16% | 39% |
| Kẻ tấn công mô phỏng (test) | `chiem_tai_khoan` | 2.069 | 2,49 | **104%** | 25% | 87% |
| Kẻ tấn công mô phỏng (test) | `bat_thuong` | 67 | 2,94 | **69%** | 29% | 58% |
| ATO thật (cả 141 ca) | `chiem_tai_khoan` | 2 | 3,00 | **128%** | 29% | 78% |
| ATO thật (cả 141 ca) | `bat_thuong` | 25 | 3,00 | **68%** | 32% | 70% |
| Đăng nhập hợp lệ (test) | `ip_tan_cong` | 98 | 2,84 | **69%** | 21% | 43% |
| Đăng nhập hợp lệ (test) | `chiem_tai_khoan` | 233 | 2,30 | **113%** | 29% | 94% |
| Đăng nhập hợp lệ (test) | `bat_thuong` | 336 | 2,85 | **68%** | 31% | 56% |

**Đọc kết quả**
- **Cần thiết — đạt.** Xoá yếu tố nêu ra làm mất 99–100% cảnh báo (ngẫu nhiên 49–90%: cảnh báo sát ngưỡng nên xoá bất kỳ 3 trong 9 yếu tố đã làm mất nhiều; đó là lý do phải có dòng "chỉ xoá yếu tố đứng đầu", nơi ngẫu nhiên chỉ còn 25–50% và giải thích vẫn 80–100%).
- **Giải thích từng ca so với bảng toàn cục.** Ở `bat_thuong` (cảnh báo đa dạng): 83% so với 45% ở báo nhầm, 80% so với 72% ở ATO, 82% so với 73% ở kẻ tấn công mô phỏng — z-score theo từng ca có giá trị. Ở hai LightGBM: bằng nhau (100%), vì cảnh báo của một thành phần gần như luôn do cùng vài yếu tố (`chiem_tai_khoan` luôn có "IP").
- **Đủ — chỉ đạt ở `chiem_tai_khoan`.** Chỉ giữ các yếu tố nêu ra: `chiem_tai_khoan` còn 90–100% cảnh báo (giữ ≥ 100% điểm; > 100% nghĩa là các yếu tố bị bỏ đang *kéo điểm xuống*, đúng ngữ nghĩa SHAP), hơn hẳn ngẫu nhiên 5–11% và toàn cục 50–74%. `ip_tan_cong` chỉ còn 20–49% và `bat_thuong` 0–16% cảnh báo, dù giữ được khoảng 2/3 điểm. Bằng chứng của hai thành phần này trải trên nhiều yếu tố nhỏ: thăm dò một lần với top-5 thay top-3 cho `bat_thuong` (không nằm trong mã) thì còn 51–60% cảnh báo và 83–89% điểm. **Ba yếu tố nêu ra là phần chủ đạo, không phải toàn bộ.**
- **Không có cảnh báo nào không có yếu tố nào** (`empty` = 0 ở mọi nhóm).

**Độ dài câu giải thích** (ký tự; thiết kế: tối đa 3 yếu tố, mỗi yếu tố một câu ngắn; cảnh báo hiện tại như `lệch giờ 3.2h (+20đ), vị trí lạ (+30đ)` dài khoảng 40–75 ký tự):

| Nhóm cảnh báo | Số cảnh báo | Độ dài trung vị (ký tự) | p95 | Dài nhất | Không có yếu tố nào |
|---|---|---|---|---|---|
| IP tấn công (test) | 718 | 110 | 114 | 145 | 0 |
| Kẻ tấn công mô phỏng (test) | 2.141 | 57 | 100 | 148 | 0 |
| ATO thật (cả 141 ca) | 27 | 118 | 145 | 145 | 0 |
| Đăng nhập hợp lệ (test) | 667 | 91 | 140 | 151 | 0 |

## 4. Mô hình dựa vào điều gì

**Yếu tố hay đứng trong giải thích** (phần cảnh báo có yếu tố đó trong top-3):

| Nhóm cảnh báo | Thành phần | Yếu tố hay đứng trong giải thích (phần cảnh báo có yếu tố đó) |
|---|---|---|
| IP tấn công (test) | `bat_thuong` (10) | quốc gia 70%, hoạt động của nhà mạng 70%, thiết bị/trình duyệt 60%, nhà mạng 40%, nhịp đăng nhập 20% |
| IP tấn công (test) | `chiem_tai_khoan` (12) | IP 100%, thiết bị/trình duyệt 58%, nhịp đăng nhập 50%, hoạt động của IP 17% |
| IP tấn công (test) | `ip_tan_cong` (696) | hoạt động của nhà mạng 100%, quốc gia 69%, hoạt động của IP 60%, nhà mạng 38%, IP 28% |
| Kẻ tấn công mô phỏng (test) | `bat_thuong` (67) | hoạt động của nhà mạng 84%, thiết bị/trình duyệt 60%, nhà mạng 48%, quốc gia 43%, hoạt động của IP 36% |
| Kẻ tấn công mô phỏng (test) | `chiem_tai_khoan` (2.069) | IP 100%, thiết bị/trình duyệt 68%, nhịp đăng nhập 37%, hoạt động của IP 27%, quốc gia 15% |
| Kẻ tấn công mô phỏng (test) | `ip_tan_cong` (5) | hoạt động của nhà mạng 100%, quốc gia 60%, hoạt động của IP 60%, nhà mạng 40%, IP 20% |
| ATO thật (cả 141 ca) | `bat_thuong` (25) | quốc gia 96%, nhà mạng 96%, hoạt động của nhà mạng 92%, nhịp đăng nhập 8%, thiết bị/trình duyệt 4% |
| ATO thật (cả 141 ca) | `chiem_tai_khoan` (2) | IP 100%, thiết bị/trình duyệt 100%, hoạt động của IP 50%, quốc gia 50% |
| Đăng nhập hợp lệ (test) | `bat_thuong` (336) | hoạt động của nhà mạng 67%, quốc gia 55%, thiết bị/trình duyệt 44%, hoạt động của IP 43%, nhà mạng 33% |
| Đăng nhập hợp lệ (test) | `chiem_tai_khoan` (233) | IP 100%, thiết bị/trình duyệt 61%, nhịp đăng nhập 37%, hoạt động của IP 26%, quốc gia 3% |
| Đăng nhập hợp lệ (test) | `ip_tan_cong` (98) | hoạt động của nhà mạng 100%, quốc gia 64%, hoạt động của IP 61%, nhà mạng 36%, IP 22% |

**SHAP toàn cục** của hai LightGBM (đóng góp tuyệt đối trung bình theo yếu tố; `ip_tan_cong` trên 30.000 đăng nhập test bốc ngẫu nhiên có trọng số dân số, `chiem_tai_khoan` trên đăng nhập hợp lệ có lịch sử cộng kẻ tấn công mô phỏng):

**`ip_tan_cong`** — đóng góp SHAP tuyệt đối trung bình theo yếu tố:

| Yếu tố | Đóng góp trung bình (log-odds) | Tỉ trọng | Phần đăng nhập mà yếu tố đẩy điểm LÊN |
|---|---|---|---|
| quốc gia | 0,545 | 37,4% | 33,1% |
| hoạt động của nhà mạng | 0,458 | 31,5% | 35,8% |
| hoạt động của IP | 0,197 | 13,5% | 21,0% |
| IP | 0,142 | 9,7% | 47,9% |
| nhà mạng | 0,080 | 5,5% | 17,3% |
| thiết bị/trình duyệt | 0,022 | 1,5% | 51,3% |
| thất bại/dò mật khẩu | 0,005 | 0,4% | 27,4% |
| độ dày lịch sử tài khoản | 0,004 | 0,3% | 56,7% |
| nhịp đăng nhập | 0,002 | 0,2% | 39,2% |

**`chiem_tai_khoan`** — đóng góp SHAP tuyệt đối trung bình theo yếu tố:

| Yếu tố | Đóng góp trung bình (log-odds) | Tỉ trọng | Phần đăng nhập mà yếu tố đẩy điểm LÊN |
|---|---|---|---|
| IP | 3,253 | 72,9% | 48,6% |
| nhịp đăng nhập | 0,310 | 6,9% | 38,5% |
| thiết bị/trình duyệt | 0,246 | 5,5% | 60,6% |
| hoạt động của IP | 0,224 | 5,0% | 57,9% |
| nhà mạng | 0,158 | 3,5% | 40,8% |
| hoạt động của nhà mạng | 0,098 | 2,2% | 52,4% |
| quốc gia | 0,082 | 1,8% | 76,2% |
| độ dày lịch sử tài khoản | 0,061 | 1,4% | 72,9% |
| thất bại/dò mật khẩu | 0,029 | 0,7% | 89,6% |


Điều đọc được:
- `ip_tan_cong` dựa chủ yếu vào **quốc gia** (37%) và **hoạt động của nhà mạng** (32%: tỉ lệ thất bại, số IP khác nhau), rồi hoạt động của IP (14%). Khớp mục 4.1 của [`ml-holdout-ablation.md`](ml-holdout-ablation.md) (nhóm độ hiếm đứng một mình còn hơn cả 50 đặc trưng).
- `chiem_tai_khoan` **dựa 73% vào "IP"** (`new_ip`, `llr_ip`), phần còn lại rải đều (nhịp 7%, thiết bị 5,5%, hoạt động IP 5%). Nghĩa là về thực chất mô hình này là "IP mới, ở khoảng cách ngắn từ lần thành công trước, cộng vài tương tác" — đúng như MR7 kết luận từ ablation ([`ml-holdout-ablation.md`](ml-holdout-ablation.md) mục 4.2).
- ATO thật bị bộ không giám sát bắt hầu hết qua **quốc gia hiếm + nhà mạng hiếm + nhà mạng ít lưu lượng** (96% / 96% / 92% số ca), không qua thiết bị hay nhịp: đây là chữ ký nhân tạo của bộ dữ liệu, không phải bằng chứng cho khả năng tổng quát ngoài đời.

## 5. Ngưỡng vận hành, cảnh báo nhầm và độ chính xác của cảnh báo

Ngưỡng chọn **chỉ trên đăng nhập hợp lệ thành công của val**, chuyển nguyên sang test và late (không chọn lại). Hai mức cố định:

| FPR mục tiêu (val) | Ngưỡng | FPR thực tế val / test / late | Cảnh báo nhầm / 10 nghìn đăng nhập | Recall ATO thật tương lai (38) | Recall IP tấn công (test) | Recall mô phỏng naive | Recall mô phỏng vpn | Recall mô phỏng targeted |
|---|---|---|---|---|---|---|---|---|
| 1,0% | 2,410 | 1,00% / 1,02% / 0,93% | 102 | 26,3% | 12,0% | 48,9% | 39,7% | 19,4% |
| 0,1% | 3,365 | 0,10% / 0,10% / 0,11% | 10 | 2,6% | 3,9% | 27,0% | 17,7% | 6,2% |

Độ chính xác của cảnh báo (phần cảnh báo là tấn công thật) theo tỉ lệ tấn công giả định trong số đăng nhập thành công, dùng recall ATO thật tương lai:

| Tỉ lệ tấn công | FPR 1,0% | FPR 0,1% |
|---|---|---|
| 1 trên 10.000 | 0,26% | 0,25% |
| 1 trên 1.000 | 2,53% | 2,48% |
| 1 trên 100 | 20,74% | 20,44% |

- Số liệu là **FPR trên đăng nhập hợp lệ thành công** (khớp thứ mà quản trị viên thấy: cảnh báo nhầm trên mỗi 10.000 lần đăng nhập thành công). Recall ở đây lấy theo ngưỡng chuyển từ val nên hơi khác con số MR6 (26,3 / 12,3 / 47,1 / 37,2 / 17,8%) vốn dùng ngưỡng chọn trên chính âm tính của test.
- **Ngưỡng chuyển tốt:** FPR thực tế 1,00% / 1,02% / 0,93% (val / test / late) cho mục tiêu 1%, và 0,10% / 0,10% / 0,11% cho mục tiêu 0,1%.
- **Độ chính xác của cảnh báo là vấn đề của tỉ lệ nền, không của mô hình.** Ở FPR 1% và recall ATO 26,3%: cứ 10.000 lần đăng nhập có 1 lần là chiếm tài khoản thì chỉ 0,26% cảnh báo là thật. Bộ RBA có 141 ATO trên 31 triệu dòng (0,0005%), nên trên chính dữ liệu này độ chính xác còn thấp hơn nhiều; số ở bảng chỉ là các kịch bản giả định để thấy quy mô.
- **Siết ngưỡng xuống 0,1% không cải thiện độ chính xác** (0,25% so với 0,26%) vì recall ATO cũng tụt cùng 10 lần: điểm hybrid của ATO tập trung sát ngưỡng 1%, không nằm xa phía trên. Muốn ít cảnh báo nhầm hơn mà không mất recall phải cải thiện *mô hình* (tách tốt hơn), không phải nâng ngưỡng.
- Hai mức ngưỡng là đầu vào của chính sách hành động ở MR11 (cho qua / cảnh báo / xác thực thêm / khoá tạm): mức 1% hợp với "cảnh báo hoặc xác thực thêm" (~102 lần/10.000), mức 0,1% mới hợp với hành động mạnh hơn (~10 lần/10.000). Không được khoá tài khoản tự động chỉ dựa vào một điểm mô hình (xem [`model-card-rba.md`](model-card-rba.md) mục 1).

## 6. Điều giải thích làm lộ ra: dấu vân tay "có điều kiện" của kẻ tấn công mô phỏng

Đọc SHAP toàn cục thấy `chiem_tai_khoan` dựa 73% vào IP, và trong 15–25% cảnh báo trên kẻ tấn công mô phỏng có câu kiểu `IP có 0% lượt thử thất bại (thường 33%)` — không phải điều một quản trị viên coi là đáng ngờ. Hỏi lại "kẻ tấn công mô phỏng có khác đăng nhập thật ở IP không?":

- **Kiểm định tổng thể (MR6): không.** So với *mọi* đăng nhập hợp lệ có lịch sử, các nhóm hạ tầng và độ hiếm cho AUC ≈ 0,5.
- **Nhưng kẻ tấn công mô phỏng luôn dùng IP mới** với tài khoản, còn chỉ ~41% đăng nhập hợp lệ như vậy. Trong số đăng nhập dùng IP mới, IP của kẻ tấn công (mượn từ đăng nhập thật của người khác) có lịch sử hoạt động nhiều hơn: có ít nhất một lượt thử khác trong 24h ở 39–45% đăng nhập giả so với 29% đăng nhập hợp lệ; và tỉ lệ thất bại của IP đúng bằng 0% ở 18–21% đăng nhập giả so với 7% đăng nhập hợp lệ.
- **Kiểm định có điều kiện** (`python -m ml.rba.audit conditional`, thêm ở MR8): so đăng nhập giả với đăng nhập hợp lệ **cũng dùng IP mới**, cùng giai đoạn, chấm trên user chưa dùng khi học:

AUC (recall ở FPR 1%), giai đoạn **test**; cột `n` = số đăng nhập giả có IP mới:

| Kiểu | n | `cur` | `history` | `rhythm` | `rarity` | `infra_ip` | `infra_asn` | `novelty` | `freeman` | tất cả |
|---|---|---|---|---|---|---|---|---|---|---|
| naive | 2.000 | 0,550 (0,5%) | 0,594 (3,5%) | 0,653 (9,7%) | 0,695 (7,9%) | 0,719 (12,9%) | 0,574 (2,5%) | 0,819 (22,5%) | 0,868 (29,9%) | 0,926 (45,7%) |
| vpn | 1.989 | 0,556 (0,0%) | 0,586 (3,8%) | 0,670 (10,0%) | 0,671 (8,4%) | 0,675 (10,4%) | 0,573 (1,7%) | 0,786 (4,2%) | 0,853 (17,7%) | 0,916 (35,6%) |
| targeted | 1.893 | 0,545 (0,0%) | 0,570 (3,6%) | 0,651 (8,2%) | 0,690 (7,1%) | 0,674 (10,2%) | 0,590 (2,0%) | 0,635 (0,0%) | 0,657 (6,6%) | 0,806 (22,7%) |

Cùng phép thử ở ba giai đoạn (AUC; recall ở FPR 1% trong ngoặc):

| Kiểu | `infra_ip` train | val | test | `rarity` train | val | test |
|---|---|---|---|---|---|---|
| naive | 0,714 (16,3%) | 0,685 (13,2%) | 0,719 (12,9%) | 0,707 (8,1%) | 0,676 (5,5%) | 0,695 (7,9%) |
| vpn | 0,687 (11,4%) | 0,681 (7,2%) | 0,675 (10,4%) | 0,698 (7,0%) | 0,691 (5,4%) | 0,671 (8,4%) |
| targeted | 0,678 (10,4%) | 0,677 (10,4%) | 0,674 (10,2%) | 0,713 (7,2%) | 0,697 (7,3%) | 0,690 (7,1%) |

  Tiêu chí của MR6 (AUC ≥ 0,6 hoặc recall ≥ 10% = còn dấu vân tay) **không đạt** ở `infra_ip` và `rarity` (đặc trưng chính: `ip_prior_attempts_all`, `ip_fail_ratio_24h`, `rare_ip`), ở cả train, val và test (AUC 0,67–0,72). `rhythm` (0,64–0,68) phần lớn là tương tác thật "IP mới × khoảng cách ngắn" ([`rba-evaluation.md`](rba-evaluation.md) mục 5.3). Kiểm định tổng thể bỏ sót vì gộp đăng nhập dùng IP mới với 59% đăng nhập không dùng IP mới.
- **Ảnh hưởng đến kết quả:** ablation MR7 của mô hình `gbm_attacker_sim` đứng riêng (FPR 1%, Naive / VPN / Targeted): tất cả đặc trưng 59,1 / 50,9 / 28,5%; bỏ nhóm `infra_ip` 52,7 / 44,2 / 21,6%; bỏ thêm `rarity` và `infra_asn` 47,3 / 39,4 / 16,1%; chỉ giữ các nhóm quan hệ với lịch sử tài khoản 47,7 / 37,7 / 16,2%. Nghĩa là **tối đa khoảng 6–12 điểm** (11–43% tương đối) recall trên kẻ tấn công mô phỏng có thể do "nhận ra IP mượn". Recall trên ATO thật của mô hình này vốn 0% nên số ATO của hybrid không bị ảnh hưởng.
- **Nguyên nhân gốc (chưa sửa):** IP kẻ tấn công lấy từ đăng nhập thật của người khác (lần đầu sau thời điểm gốc) — đã sửa nhiều lỗi trước bằng cách này nhưng phân phối "lịch sử của IP" vẫn khác phân phối của IP *mới thật* của người dùng hợp lệ. Cách sửa theo nguyên tắc: chỉ mượn IP từ các đăng nhập mà chính chủ của chúng cũng đang dùng IP mới (để phân phối hạ tầng khớp với đăng nhập hợp lệ dùng IP mới), rồi sinh lại, huấn luyện lại và đo lại MR6–MR7. **Chưa làm** — cần quyết định ở CP2 (danh sách quyết định ở [`checklist.md`](checklist.md)); trong lúc chờ, mọi con số trên kẻ tấn công mô phỏng đọc là cận trên.

## 7. Giới hạn — những điều không được tuyên bố

1. **Giải thích mô tả điều mô hình dựa vào, không phải nguyên nhân thật của cuộc tấn công.** Không viết "kẻ tấn công dùng nhà mạng hiếm" mà chỉ "nhà mạng hiếm" là yếu tố chính của điểm.
2. **Ba yếu tố không phải toàn bộ lý do** (mục 3, phép thử "chỉ giữ"): đúng nhất với `chiem_tai_khoan`, chỉ khoảng 2/3 điểm với hai thành phần còn lại.
3. **Độ trung thực đo trên đúng các mô hình và dữ liệu tổng hợp này**; nếu đổi mô hình hoặc tập đặc trưng phải chạy lại `python -m ml.rba.explain_eval faithfulness`.
4. **z-score dự phòng không phải "đóng góp vào xác suất":** hai đặc trưng cùng lệch không cộng dồn được như SHAP; chỉ dùng để xếp thứ tự và nêu giá trị so với mức thường thấy.
5. **"Thường" là trung vị của cả dân số** (đăng nhập hợp lệ thành công ở train) khi không có ngữ cảnh riêng — không phải mức thường của tài khoản đó.
6. **Ngữ cảnh chỉ đến từ lần đăng nhập thành công**; tài khoản mới (35% ATO trong bộ dữ liệu) không có "thường".
7. **Ngữ cảnh chưa kiểm chứng trên luồng realtime**: mới dùng dữ liệu RBA đọc từ file gốc; MR12 nối với `login_events` và cần test riêng độ khớp.
8. **Kết quả trên kẻ tấn công mô phỏng là cận trên** (mục 6); bằng chứng ngoài duy nhất vẫn là 38 ATO tương lai của bộ dữ liệu.
9. **Chưa đo giải thích với người đọc thật** (độ hiểu, tốc độ xử lý cảnh báo): thí nghiệm này cần quản trị viên, không làm được trên dữ liệu tổng hợp.

## 8. Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.explain_eval all --hybrid hybrid    # mục 1–8 (hybrid MR6, ~3 phút); ghi ml/artifacts/rba_mr8/*.json và ml/artifacts/rba/explain_reference.json
venv\Scripts\python.exe -m ml.rba.explain_eval all                    # mục 9 (hybrid chốt ở CP2, mặc định); ghi ml/artifacts/rba_cp2/explain/*.json
venv\Scripts\python.exe -m ml.rba.explain_eval faithfulness           # riêng phép thử xoá/giữ yếu tố
venv\Scripts\python.exe -m ml.rba.audit conditional        # kiểm định dấu vân tay có điều kiện (thêm `trainval` để chạy train, val)
venv\Scripts\python.exe -m pytest tests/test_rba_explain.py tests/test_rba_explain_eval.py tests/test_rba_audit.py
```

`ExplainReference` (mức "thường thấy") lưu ở `ml/artifacts/rba/explain_reference.json` kèm **chữ ký danh sách đặc trưng** (`feature_signature()`, hiện `2e54756a441c`, phiên bản đặc trưng `v2`); nạp lại sẽ báo lỗi nếu danh sách đặc trưng đã đổi.

## 9. Sau CP2: giải thích trên hybrid chốt (`hybrid_cp2`)

Cùng phép đo, cùng mã, chạy lại trên `hybrid_cp2` (`gbm_attack_ip` MR6 + `gbm_attacker_sim_cp2` 28 đặc trưng + `isolation_forest_cp2` 43 đặc trưng). Cảnh báo lấy ở test theo ngưỡng 2,391: 723 trên 5.709 dòng IP tấn công, 1.454 trên 5.911 kẻ tấn công mô phỏng, 38 trên 130 ATO thật, 609 trên 60.000 đăng nhập hợp lệ bốc ngẫu nhiên. Phép thử xoá/giữ yếu tố chỉ chọn trong các yếu tố mà thành phần THẬT SỰ có đặc trưng (thành phần đã bỏ nhóm đặc trưng không bị "xoá" một yếu tố nó không dùng). Cột: **GT** giải thích, **NN** ngẫu nhiên, **TC** quan trọng toàn cục.

| Nhóm cảnh báo | Thành phần | Số cảnh báo | Xoá cả k yếu tố → mất cảnh báo (GT / NN) | Chỉ xoá yếu tố đầu → mất cảnh báo (GT / NN / TC) | Chỉ giữ k yếu tố → còn cảnh báo (GT / NN) | Điểm còn lại (GT) |
|---|---|---|---|---|---|---|
| IP tấn công (test) | `ip_tan_cong` | 697 | **100%** / 79% | **100%** / 39% / 100% | **49%** / 1% | 66% |
| IP tấn công (test) | `chiem_tai_khoan` | 13 | **100%** / 74% | **100%** / 43% / 100% | **69%** / 2% | 103% |
| IP tấn công (test) | `bat_thuong` | 13 | **100%** / 95% | **100%** / 52% / 85% | **0%** / 0% | 71% |
| Kẻ tấn công mô phỏng (test) | `ip_tan_cong` | 6 | **100%** / 90% | **100%** / 40% / 100% | **17%** / 0% | 66% |
| Kẻ tấn công mô phỏng (test) | `chiem_tai_khoan` | 1.399 | **100%** / 71% | **100%** / 35% / 100% | **84%** / 7% | 92% |
| Kẻ tấn công mô phỏng (test) | `bat_thuong` | 49 | **100%** / 78% | **78%** / 40% / 76% | **20%** / 2% | 69% |
| ATO thật (cả 141 ca) | `chiem_tai_khoan` | 5 | **100%** / 84% | **100%** / 32% / 100% | **100%** / 0% | 96% |
| ATO thật (cả 141 ca) | `bat_thuong` | 33 | **100%** / 88% | **67%** / 30% / 36% | **0%** / 0% | 66% |
| Đăng nhập hợp lệ (test) | `ip_tan_cong` | 99 | **100%** / 82% | **100%** / 42% / 100% | **25%** / 1% | 69% |
| Đăng nhập hợp lệ (test) | `chiem_tai_khoan` | 216 | **100%** / 77% | **100%** / 40% / 100% | **66%** / 5% | 94% |
| Đăng nhập hợp lệ (test) | `bat_thuong` | 294 | **100%** / 81% | **78%** / 35% / 56% | **15%** / 2% | 68% |

- **Cần thiết — vẫn đạt:** xoá các yếu tố nêu ra làm mất 99–100% cảnh báo (ngẫu nhiên 71–95%); chỉ xoá yếu tố đứng đầu: 100% ở hai LightGBM, 67–100% ở Isolation Forest (ngẫu nhiên 30–52%, toàn cục 36–85%) — z-score theo từng ca vẫn hơn bảng toàn cục ở cảnh báo đa dạng (ATO 67% so với 36%, báo nhầm 78% so với 56%).
- **Đủ — vẫn không:** `ip_tan_cong` còn 17–49% cảnh báo khi chỉ giữ ba yếu tố (còn ~2/3 điểm), `bat_thuong` 0–20% (~2/3 điểm). `chiem_tai_khoan` giờ dùng 28 đặc trưng nên chỉ còn 66–100% cảnh báo (điểm còn 92–103%), thấp hơn bản MR6 (90–100%) vì có ít yếu tố hơn để gộp. Kết luận cũ giữ nguyên: ba yếu tố là phần chủ đạo, không phải toàn bộ.
- **Yếu tố hay đứng đầu:** `chiem_tai_khoan` luôn có "IP" (100%), rồi thiết bị/trình duyệt (62–81%) và nhịp (56–62%); ATO thật bị Isolation Forest bắt qua quốc gia (97%), nhà mạng (94%) và hoạt động của nhà mạng (94%) — không đổi so với MR6.

**Độ dài câu giải thích** (ký tự):

| Nhóm cảnh báo | Số cảnh báo | Độ dài trung vị (ký tự) | p95 | Dài nhất | Không có yếu tố nào |
|---|---|---|---|---|---|
| IP tấn công (test) | 723 | 110 | 114 | 145 | 0 |
| Kẻ tấn công mô phỏng (test) | 1.454 | 57 | 96 | 147 | 0 |
| ATO thật (cả 141 ca) | 38 | 118 | 145 | 145 | 0 |
| Đăng nhập hợp lệ (test) | 609 | 96 | 143 | 147 | 0 |

Độ trễ giải thích từng cảnh báo một (150 cảnh báo): **4,5 ms (p50) / 9,8 ms (p95)** cho phần giải thích, 55,6 ms (p50) / 63,6 ms (p95) gồm cả chấm điểm lại ba thành phần.

Ngưỡng vận hành, độ chính xác cảnh báo theo tỉ lệ tấn công và so trước/sau: [`ml-model-selection.md`](ml-model-selection.md) mục 6.
