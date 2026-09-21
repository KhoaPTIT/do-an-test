# Model card — chấm điểm rủi ro đăng nhập trên bộ RBA (MR6, hoàn thiện ở MR8)

Mã: [`backend/ml/rba/`](../backend/ml/rba/) · kết quả đầy đủ và phân tích: [`ml-evaluation-v2.md`](ml-evaluation-v2.md) · kiểm chứng "kiểu tấn công mới", ablation, phân tích lỗi: [`ml-holdout-ablation.md`](ml-holdout-ablation.md) · giải thích cảnh báo và ngưỡng vận hành: [`ml-explanations.md`](ml-explanations.md) · khung đo: [`rba-evaluation.md`](rba-evaluation.md).

| | |
|---|---|
| Phiên bản đặc trưng | `v2`: 50 đặc trưng ([`rba-features.md`](rba-features.md)), chữ ký danh sách `2e54756a441c` (`feature_signature()`; bảng "thường thấy" của giải thích từ chối nạp nếu chữ ký lệch) |
| Mô hình | huấn luyện 21/09/2026 bằng `python -m ml.rba.train`; artifact ở `backend/ml/artifacts/rba/` (không commit, sinh lại được); hạt giống cố định |
| Ngưỡng vận hành | hybrid **2,410** (báo nhầm 1%) và **3,365** (0,1%), chọn chỉ trên đăng nhập hợp lệ thành công của val (mục 6) |
| Giải thích | SHAP cho LightGBM, z-score cho bộ không giám sát, câu tiếng Việt kèm "thường … → nay …" (mục 7) |
| Trạng thái | dùng **offline** để đánh giá; chưa nối vào luồng `/login` (MR12). Luồng realtime hiện chạy tầng 3 cũ (Isolation Forest 9 đặc trưng trên dữ liệu tự sinh) |

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
5. **Trước khi tin kết quả trên kẻ tấn công mô phỏng, chạy `python -m ml.rba.audit`** (tách riêng train, val, test): nó tách đăng nhập giả khỏi đăng nhập thật theo từng nhóm đặc trưng; nhóm cur/history/rhythm/rarity/infra phải ≈ 0,5, nếu không bộ mô phỏng còn "dấu vân tay" mà mô hình sẽ học thay cho tấn công thật. Bộ hiện tại đạt (AUC 0,48–0,56, recall ≤ 1,6% ở các nhóm đó); phiên bản đầu của tôi đã không đạt và mô hình học từ nó đạt recall 100% giả tạo ([`rba-evaluation.md`](rba-evaluation.md) mục 5). **Ở MR8 kiểm định thêm chế độ có điều kiện** (`python -m ml.rba.audit conditional`, chỉ so với đăng nhập hợp lệ cũng dùng IP mới) và bộ hiện tại **không đạt** ở nhóm IP và độ hiếm (AUC 0,67–0,72): xem mục 8.10.
6. Ngưỡng cảnh báo chọn trên đăng nhập hợp lệ của val cho một FPR mục tiêu, sau đó **chuyển nguyên ngưỡng** sang test/late để đo FPR thực tế (không chọn lại).

## 5. Kết quả tóm tắt (giai đoạn test, FPR 1%, trọng số dân số)

| Họ tấn công | Hybrid | Tier 2 hiện tại | Luật tinh chỉnh | Freeman | Isolation Forest |
|---|---|---|---|---|---|
| ATO thật tương lai (38 ca) — recall | **26,3%** [13–39] | 0% | 0% | 15,8% [7–29] | 42,1% [26–55] |
| ATO thật tương lai — ROC-AUC | **0,923** [0,87–0,96] | 0,532 | 0,735 | 0,759 | 0,953 |
| IP tấn công (test) — recall | **12,3%** | 0,2% | 3,9% | 0,3% | 0,7% |
| Kẻ tấn công Naive / VPN / Targeted (mô phỏng) — recall | **47,1% / 37,2% / 17,8%** | 1,1 / 1,2 / 1,6% | 5,4 / 0,1 / 0,5% | 35,0 / 26,5 / 1,5% | 11,8 / 6,0 / 0,5% |

Bảng đầy đủ (13 mô hình × 11 bài, ROC-AUC, PR-AUC, recall, xác thực lại, khoảng tin cậy): [`rba-baseline-comparison.md`](rba-baseline-comparison.md).

## 6. Ngưỡng vận hành và hiệu chỉnh

Ngưỡng hybrid (−log₁₀ xác suất đuôi nhỏ nhất) chọn **chỉ trên đăng nhập hợp lệ thành công của val**, chuyển nguyên sang test/late (không chọn lại). Nguồn: `python -m ml.rba.explain_eval operating`.

| Mục tiêu (chọn trên val) | Ngưỡng | FPR thực tế val / test / late | Cảnh báo nhầm / 10 nghìn đăng nhập | Recall ATO thật tương lai | Recall IP tấn công | Recall Naive / VPN / Targeted (mô phỏng) |
|---|---|---|---|---|---|---|
| 1% | **2,410** | 1,00% / 1,02% / 0,93% | 102 | 26,3% | 12,0% | 48,9 / 39,7 / 19,4% |
| 0,1% | **3,365** | 0,10% / 0,10% / 0,11% | 10 | 2,6% | 3,9% | 27,0 / 17,7 / 6,2% |

- Đo trên **đăng nhập hợp lệ thành công**; trên bài IP tấn công (âm tính gồm cả đăng nhập thất bại) FPR thực tế là 0,92% / 0,85% (test / late) cho mục tiêu 1% và 0,08% / 0,09% cho 0,1%. Recall ở bảng dùng ngưỡng chuyển từ val nên hơi khác các con số 26,3 / 12,3 / 47,1 / 37,2 / 17,8% của mục 5 (ngưỡng chọn trên chính âm tính của test).
- **Độ chính xác của cảnh báo phụ thuộc tỉ lệ tấn công thật**: với recall ATO 26,3% và FPR 1%, chỉ 0,26% cảnh báo là thật khi tấn công chiếm 1 trên 10.000 đăng nhập thành công, 2,5% khi 1 trên 1.000, 20,7% khi 1 trên 100. **Siết ngưỡng xuống 0,1% không làm cảnh báo chính xác hơn** (0,25% ở 1 trên 10.000) vì recall ATO tụt cùng tỉ lệ; cải thiện độ chính xác cần mô hình tách tốt hơn ([`ml-explanations.md`](ml-explanations.md) mục 5).
- Gợi ý cho chính sách ở MR11: mức 1% (~102 cảnh báo nhầm/10 nghìn) hợp với "cảnh báo" hoặc "yêu cầu xác thực thêm"; mức 0,1% (~10/10 nghìn) mới hợp với hành động mạnh hơn. Không khoá tài khoản tự động chỉ dựa vào điểm mô hình.

Hiệu chỉnh xác suất (isotonic, học trên val) cho `gbm_attack_ip`: Brier test 0,0532 so với 0,0604 (thô) và 0,0726 (đoán theo tỉ lệ trung bình); ở giai đoạn trôi phân phối `late` xác suất dưới ước lượng (nhóm cao nhất: dự đoán 34,7%, thực tế 38,4%) nên cần hiệu chỉnh lại định kỳ. Chi tiết: [`ml-evaluation-v2.md`](ml-evaluation-v2.md) mục 5.

## 7. Giải thích từng cảnh báo (MR8)

Mỗi cảnh báo có tối đa **3 yếu tố**, mỗi yếu tố một câu ngắn kiểu `quốc gia: thường NO → nay LV (hiếm 0.01%); nhà mạng mới (hiếm <0.01%, thường 13%)` (trung vị 57–118 ký tự, dài nhất 151). Chi tiết, ví dụ và kiểm chứng: [`ml-explanations.md`](ml-explanations.md).

- **Phương pháp:** thành phần LightGBM (`ip_tan_cong`, `chiem_tai_khoan`) → SHAP (TreeSHAP, trùng thư viện `shap` từng chữ số); Isolation Forest (`bat_thuong`) → z-score so với đăng nhập bình thường của train. 50 đặc trưng gộp thành 9 yếu tố (quốc gia, nhà mạng, IP, thiết bị/trình duyệt, độ dày lịch sử, nhịp, thất bại, hoạt động của IP, hoạt động của nhà mạng).
- **Ngữ cảnh "thường … → nay …":** dựng từ lịch sử **thành công** của tài khoản trước đăng nhập đó (`build_context`); không có lịch sử thì chỉ nói "mới"/"hiếm" và so với mức thường thấy của dân số.
- **Độ trung thực** (phép thử xoá yếu tố, giai đoạn test, 3 nhóm cảnh báo × 3 thành phần): xoá các yếu tố nêu ra làm **99–100% cảnh báo biến mất** (ngẫu nhiên 49–90%); chỉ xoá yếu tố đứng đầu 80–100% (ngẫu nhiên 25–50%).
- **Nhưng ba yếu tố không phải toàn bộ lý do:** chỉ giữ chúng thì bộ không giám sát còn khoảng 68% điểm (0–16% cảnh báo còn), `ip_tan_cong` 66% (20–49%), riêng `chiem_tai_khoan` ≥ 100% (90–100%).
- **Chi phí:** ~3,6 ms (p50) / 22 ms (p95) cho một cảnh báo; chỉ tính cho cảnh báo, làm ở tiến trình nền.
- Câu chỉ **mô tả điều mô hình dựa vào**, không khẳng định nguyên nhân thật; "thường" là mức của dân số nếu thiếu ngữ cảnh riêng.

## 8. Giới hạn đã biết

1. **Dữ liệu tổng hợp.** Mọi con số là "trên bộ RBA tổng hợp". ATO thật của bộ dữ liệu dùng nhà mạng hiếm bất thường (nghi đặc điểm nhân tạo), có thể làm bộ phát hiện không giám sát **lạc quan**.
2. **Chỉ 38 ATO tương lai** — khoảng tin cậy rộng; thứ hạng Isolation Forest so với hybrid không kết luận được.
3. **Mô hình có giám sát không bắt được ATO thật** (recall 0% ở FPR 1% cho `gbm_attack_ip`, `gbm_attacker_sim`): hai nguồn nhãn có sẵn không giống ATO thật. Hybrid có được khả năng này chỉ nhờ thành phần không giám sát.
4. **Tài khoản chưa có lịch sử**: hybrid không báo nhầm chúng nhiều hơn mức chung (0,56%), nhưng ATO ở đó (35% số ATO) hầu như không bị phát hiện (0/46 ở hybrid).
5. **Kẻ tấn công mô phỏng** (xem cả mục 10 bên dưới) hoà lẫn về hạ tầng, đăng nhập đúng nhịp của nạn nhân, Targeted biết trọn hồ sơ phiên; mô hình học từ họ mô phỏng nên có lợi thế; kẻ tấn công bắt chước cả IP nằm ngoài phạm vi. Kiểm định dấu vân tay chỉ bắt được lối tắt theo nhóm đặc trưng.
6. **Trôi phân phối**: recall giảm ở `late` (IP tấn công 12,1% → 7,1% ở ngưỡng cố định) dù mức báo nhầm giữ đúng; cần huấn luyện lại và hiệu chỉnh lại định kỳ.
7. **Không tổng quát sang họ IP tấn công chưa thấy** (MR7, [`ml-holdout-ablation.md`](ml-holdout-ablation.md)): giấu một họ khỏi huấn luyện thì `gbm_attack_ip` bắt 0,0–1,1% họ đó ở 5/6 họ bắt được khi đã thấy (15–56%); bộ phát hiện không nhãn tối đa 10,1%. Với kẻ tấn công mô phỏng tổng quát một phần (giữ 30–91%). Hệ thống cần huấn luyện lại khi có họ mới; **không tuyên bố phát hiện được tấn công mới**.
8. **Trên ATO của RBA một luật `rare_asn` không học bắt 65,8% (38 ca tương lai), hơn hybrid (26,3%)**: chẩn đoán chọn sau khi thấy ATO nên không công bằng, nhưng cho thấy ATO của bộ dữ liệu "dễ" theo một dấu hiệu duy nhất; không được dùng con số hybrid trên ATO để tuyên bố AI hơn luật.
9. **Giới hạn với Targeted**: bắt 58,9% khi kẻ tấn công đăng nhập trong 1 phút sau lần thành công trước, 6,5% khi cách > 30 ngày.
10. **Bộ mô phỏng còn dấu vân tay có điều kiện** (MR8): kẻ tấn công mô phỏng luôn dùng IP mới; so với đăng nhập hợp lệ *cũng dùng IP mới*, các nhóm `infra_ip` (AUC 0,67–0,72, recall 7–16% ở FPR 1%) và `rarity` (AUC 0,67–0,71) tách được ở cả train, val và test, trong khi kiểm định tổng thể chỉ thấy ≈ 0,5. Ablation MR7 cho thấy tối đa khoảng 6–12 điểm recall trên kẻ tấn công mô phỏng của `gbm_attacker_sim` (59,1 / 50,9 / 28,5% → 47,3 / 39,4 / 16,1% khi bỏ `rarity`, `infra_asn`, `infra_ip`) có thể do "nhận ra IP mượn". **Mọi recall trên kẻ tấn công mô phỏng là cận trên**; ATO thật không bị ảnh hưởng ([`ml-explanations.md`](ml-explanations.md) mục 6). Chưa sửa — cần quyết định ở CP2.
11. **Ba yếu tố của giải thích không phải toàn bộ lý do của cảnh báo** (mục 7): với `ip_tan_cong` và `bat_thuong` chúng chỉ giải thích khoảng 2/3 điểm.
12. **Độ chính xác của cảnh báo** thấp khi tấn công hiếm (mục 6): ở FPR 1%, 0,26% cảnh báo là thật nếu tấn công chiếm 1 trên 10.000 đăng nhập.

## 9. Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.attackers && venv\Scripts\python.exe -m ml.rba.attackers --period trainval
venv\Scripts\python.exe -m ml.rba.audit && venv\Scripts\python.exe -m ml.rba.audit trainval
venv\Scripts\python.exe -m ml.rba.audit conditional                      # thêm `trainval` để chạy train, val
venv\Scripts\python.exe -m ml.rba.train                                   # ml/artifacts/rba/ (không commit; sinh lại được)
venv\Scripts\python.exe -m ml.rba.report all --n-boot 300
venv\Scripts\python.exe -m ml.rba.analysis gbm_attack_ip gbm_attacker_sim hybrid
venv\Scripts\python.exe -m ml.rba.explain_eval all                       # giải thích, ngưỡng vận hành, độ trễ (ml/artifacts/rba_mr8/)
```
