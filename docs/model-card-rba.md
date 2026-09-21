# Model card — chấm điểm rủi ro đăng nhập trên bộ RBA (MR6)

Phiên bản: đặc trưng `v2` (50 đặc trưng, [`rba-features.md`](rba-features.md)) · huấn luyện 21/09/2026 · mã: [`backend/ml/rba/`](../backend/ml/rba/) · kết quả đầy đủ và phân tích: [`ml-evaluation-v2.md`](ml-evaluation-v2.md) · khung đo: [`rba-evaluation.md`](rba-evaluation.md). Đây là model card **sơ bộ của MR6**; MR8 bổ sung giải thích (SHAP) và chốt ngưỡng vận hành.

## 1. Dùng để làm gì — và không dùng để làm gì

**Dùng để** chấm điểm rủi ro cho MỘT lần đăng nhập từ 50 đặc trưng tính trên lịch sử TRƯỚC thời điểm đó (thuộc tính đăng nhập, độ mới lạ so với hồ sơ tài khoản, nhịp/tần suất, hoạt động của IP và nhà mạng), để (a) yêu cầu xác thực thêm, (b) cảnh báo quản trị viên, (c) kết hợp với rule engine thành hệ thống lai.

**Không dùng để**
1. tự động khoá tài khoản mà không có bước xác thực lại — mọi mô hình ở đây đều báo nhầm (hybrid: 1% đăng nhập hợp lệ ở ngưỡng chuẩn);
2. suy ra hiệu năng ngoài đời — dữ liệu huấn luyện là **tổng hợp** ([`rba-data-card.md`](rba-data-card.md) mục 2) và tác giả bộ dữ liệu ghi rõ không dùng làm hệ thống phát hiện xâm nhập thật;
3. phát hiện tấn công dựa trên địa lý/giờ trong ngày — RBA không có giờ và toạ độ đáng tin, phần đó thuộc mô hình B ở MR18;
4. thay thế rule: mô hình lai dùng cả hai (luật hạ tầng ở MR9 bù cho những gì mô hình này không thấy).

## 2. Dữ liệu

| | |
|---|---|
| Nguồn | RBA (Wiefling, Dürmuth, Lo Iacono — ACM TOPS 2022), CC BY 4.0, **tổng hợp** |
| Kích thước dùng | 2.707.021 dòng / 401.092 user (mẫu phân tầng theo user, giữ nguyên lịch sử) từ 31,27 triệu dòng |
| Chia | theo thời gian: train 02–07/2020 · val 08/2020 · test 09–11/2020 · late 12/2020–02/2021 (kiểm tra trôi phân phối); nhãn IP tấn công chia thêm theo **nhóm IP** (70/15/15) |
| Nhãn | `Is Attack IP` (lưu lượng tấn công hàng loạt, 82.975 IP) và `Is Account Takeover` (chỉ **141** dòng / 138 user, 38 ca ở tương lai) |
| Trọng số | `pop_weight` quy mọi chỉ số về dân số 4,3 triệu user và tỉ lệ tấn công tự nhiên |
| Loại khỏi mô hình | 14 ngày đầu (warm-up), 2 "user" khổng lồ (14 triệu và 70 nghìn sự kiện), đặc trưng địa lý/giờ |
| Kẻ tấn công mô phỏng | train 11.739 + val 4.423 (học và chọn), test 5.911 (đánh giá), theo [`rba-evaluation.md`](rba-evaluation.md) mục 5 |

**141 ca ATO thật không bao giờ được dùng để học, chọn siêu tham số, dừng sớm, chọn ngưỡng hay hiệu chỉnh** — chỉ để chấm điểm cuối cùng.

## 3. Các mô hình

Mọi mô hình là hàm `bảng đặc trưng → điểm rủi ro`, đi qua đúng cùng các bài kiểm tra như baseline MR5.

| Tên | Loại | Học từ | Vai trò |
|---|---|---|---|
| `gbm_attack_ip` | LightGBM có giám sát | nhãn `Is Attack IP` của train (IP tách rời val/test) | bắt lưu lượng tấn công hàng loạt: dò/nhồi mật khẩu, IP có hành vi tấn công |
| `gbm_attacker_sim` | LightGBM có giám sát | kẻ tấn công **mô phỏng** (nạn nhân ở train) so với đăng nhập hợp lệ của tài khoản có lịch sử | bắt chiếm tài khoản bằng mật khẩu đúng: thuộc tính/IP lạ so với hồ sơ nạn nhân |
| `gbm_combined` | LightGBM | cả hai nguồn dương tính; tỉ trọng ρ = 0,25 chọn trên val | một mô hình duy nhất cho cả hai kiểu |
| `gbm_combined_global` | LightGBM | như trên nhưng chỉ đặc trưng toàn cục (`cur`, `rarity`, `infra_ip`, `infra_asn`) | đo giá trị của **cá nhân hoá** |
| `knn_distance` | không giám sát | khoảng cách trung bình tới 10 láng giềng gần nhất trong 30.000 đăng nhập bình thường của train | phát hiện "khác lạ so với bình thường" không cần nhãn |
| `autoencoder` | không giám sát | mạng 32-12-32 tái tạo đăng nhập bình thường (300.000 dòng train) | như trên |
| `isolation_forest` | không giám sát | 300 cây trên 400.000 đăng nhập bình thường của train | như trên |
| **`hybrid`** | kết hợp | ba thành phần ở dưới qua "cổng" điều kiện, hiệu chỉnh trên val | báo động khi **bất kỳ** bộ phát hiện nào thấy bằng chứng cực đoan |

**Hybrid.** Điểm mỗi thành phần được đổi thành xác suất đuôi (tỉ lệ đăng nhập hợp lệ của val có điểm ≥ điểm này); điểm hybrid = −log₁₀ của xác suất đuôi nhỏ nhất. Thành phần:

| Thành phần | Mô hình | Cổng | Bắt gì |
|---|---|---|---|
| `ip_tan_cong` | `gbm_attack_ip` | không (mọi đăng nhập) | lưu lượng tấn công IP hàng loạt (11,8% IP tấn công ở FPR 1%) |
| `chiem_tai_khoan` | `gbm_attacker_sim` | đăng nhập **thành công** của tài khoản **đã có lịch sử** | chiếm tài khoản (47,2% / 38,0% / 19,1% Naive / VPN / Targeted mô phỏng) |
| `bat_thuong` | `isolation_forest` | đăng nhập **thành công** | lạ so với bình thường, không cần nhãn (23,7% ATO thật tương lai) |

Lý do chọn dạng này thay vì stacking học tự do: không cần nhãn ATO để ghép, ngưỡng có nghĩa vận hành (mức báo nhầm), và mỗi thành phần vẫn giải thích được riêng. Cái giá: mỗi bộ phát hiện chiếm một phần ngân sách báo nhầm nên recall trên từng họ thấp hơn bộ chuyên dụng ở cùng tổng FPR ([`ml-evaluation-v2.md`](ml-evaluation-v2.md) mục 6).

**LightGBM:** learning rate 0,05 · 63 lá · `min_data_in_leaf` 200 · feature/bagging fraction 0,8 · L2 = 10 · dừng sớm theo PR-AUC có trọng số trên val (chịu 60 vòng) · hạt giống cố định `20260922`. Đặc trưng quan trọng nhất (tỉ trọng gain): `gbm_attack_ip` — `ip_prior_attempts_all` 25%, `asn_fail_ratio_24h` 22%, `rare_country` 20%; `gbm_attacker_sim` — `new_ip` 17%, `llr_sum` 14%, `llr_ip` 11%, `u_secs_since_last_success` 11%.

## 4. Quy trình huấn luyện và các quy tắc chống rò rỉ

1. Đặc trưng chỉ nhìn sự kiện **strictly trước** thời điểm chấm (test rò rỉ tự động, [`rba-features.md`](rba-features.md)).
2. Mô hình học từ `train`; dừng sớm, chọn ρ, chọn thành phần hybrid, hiệu chỉnh và chọn ngưỡng chỉ dùng `val`; `test` và `late` chỉ để báo cáo.
3. IP tấn công tách rời giữa train/val/test (không học thuộc blocklist); `Is Attack IP` **không** là đặc trưng đầu vào.
4. Kẻ tấn công mô phỏng dùng để học/chọn có đăng nhập gốc ở giai đoạn train/val; bộ đánh giá ở giai đoạn test; user có ATO thật bị loại khỏi nạn nhân ở cả ba bộ.
5. **Trước khi tin kết quả trên kẻ tấn công mô phỏng, chạy `python -m ml.rba.audit`** (tách riêng train, val, test): nó tách đăng nhập giả khỏi đăng nhập thật theo từng nhóm đặc trưng; nhóm cur/history/rhythm/rarity/infra phải ≈ 0,5, nếu không bộ mô phỏng còn "dấu vân tay" mà mô hình sẽ học thay cho tấn công thật. Bộ hiện tại đạt (AUC 0,48–0,56, recall ≤ 1,6% ở các nhóm đó); phiên bản đầu của tôi đã không đạt và mô hình học từ nó đạt recall 100% giả tạo ([`rba-evaluation.md`](rba-evaluation.md) mục 5).
6. Ngưỡng cảnh báo chọn trên đăng nhập hợp lệ của val cho một FPR mục tiêu, sau đó **chuyển nguyên ngưỡng** sang test/late để đo FPR thực tế (không chọn lại).

## 5. Kết quả tóm tắt (giai đoạn test, FPR 1%, trọng số dân số)

| Họ tấn công | Hybrid | Tier 2 hiện tại | Luật tinh chỉnh | Freeman | Isolation Forest |
|---|---|---|---|---|---|
| ATO thật tương lai (38 ca) — recall | **26,3%** [13–39] | 0% | 0% | 15,8% [7–29] | 42,1% [26–55] |
| ATO thật tương lai — ROC-AUC | **0,923** [0,87–0,96] | 0,532 | 0,735 | 0,759 | 0,953 |
| IP tấn công (test) — recall | **12,3%** | 0,2% | 3,9% | 0,3% | 0,7% |
| Kẻ tấn công Naive / VPN / Targeted (mô phỏng) — recall | **47,1% / 37,2% / 17,8%** | 1,1 / 1,2 / 1,6% | 5,4 / 0,1 / 0,5% | 35,0 / 26,5 / 1,5% | 11,8 / 6,0 / 0,5% |

Bảng đầy đủ (13 mô hình × 11 bài, ROC-AUC, PR-AUC, recall, xác thực lại, khoảng tin cậy): [`rba-baseline-comparison.md`](rba-baseline-comparison.md).

## 6. Ngưỡng và hiệu chỉnh

| Mục tiêu (chọn trên val) | Ngưỡng hybrid (−log₁₀ xác suất đuôi) | FPR thực tế test / late | Recall ATO thật tương lai |
|---|---|---|---|
| 1% đăng nhập hợp lệ | 2,410 | 0,92% / 0,85% (bài IP tấn công) | 26,3% |
| 0,1% đăng nhập hợp lệ | 3,365 | 0,08% / 0,09% | 2,6% |

Hiệu chỉnh xác suất (isotonic, học trên val) cho `gbm_attack_ip`: Brier test 0,0532 so với 0,0604 (thô) và 0,0726 (đoán theo tỉ lệ trung bình); ở giai đoạn trôi phân phối `late` xác suất dưới ước lượng (nhóm cao nhất: dự đoán 34,7%, thực tế 38,4%) nên cần hiệu chỉnh lại định kỳ. Chi tiết: [`ml-evaluation-v2.md`](ml-evaluation-v2.md) mục 5.

## 7. Giới hạn đã biết

1. **Dữ liệu tổng hợp.** Mọi con số là "trên bộ RBA tổng hợp". ATO thật của bộ dữ liệu dùng nhà mạng hiếm bất thường (nghi đặc điểm nhân tạo), có thể làm bộ phát hiện không giám sát **lạc quan**.
2. **Chỉ 38 ATO tương lai** — khoảng tin cậy rộng; thứ hạng Isolation Forest so với hybrid không kết luận được.
3. **Mô hình có giám sát không bắt được ATO thật** (recall 0% ở FPR 1% cho `gbm_attack_ip`, `gbm_attacker_sim`): hai nguồn nhãn có sẵn không giống ATO thật. Hybrid có được khả năng này chỉ nhờ thành phần không giám sát.
4. **Tài khoản chưa có lịch sử**: hybrid không báo nhầm chúng nhiều hơn mức chung (0,56%), nhưng ATO ở đó (35% số ATO) hầu như không bị phát hiện (0/46 ở hybrid).
5. **Kẻ tấn công mô phỏng** hoà lẫn về hạ tầng, đăng nhập đúng nhịp của nạn nhân, Targeted biết trọn hồ sơ phiên; mô hình học từ họ mô phỏng nên có lợi thế; kẻ tấn công bắt chước cả IP nằm ngoài phạm vi. Kiểm định dấu vân tay chỉ bắt được lối tắt theo nhóm đặc trưng.
6. **Trôi phân phối**: recall giảm ở `late` (IP tấn công 12,1% → 7,1% ở ngưỡng cố định) dù mức báo nhầm giữ đúng; cần huấn luyện lại và hiệu chỉnh lại định kỳ.
7. **Chưa đo "kiểu tấn công mới"** (giấu một họ khỏi tập huấn luyện) và chưa có giải thích từng cảnh báo — MR7 và MR8.

## 8. Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.attackers && venv\Scripts\python.exe -m ml.rba.attackers --period trainval
venv\Scripts\python.exe -m ml.rba.audit && venv\Scripts\python.exe -m ml.rba.audit trainval
venv\Scripts\python.exe -m ml.rba.train                                   # ml/artifacts/rba/ (không commit; sinh lại được)
venv\Scripts\python.exe -m ml.rba.report all --n-boot 300
venv\Scripts\python.exe -m ml.rba.analysis gbm_attack_ip gbm_attacker_sim hybrid
```
