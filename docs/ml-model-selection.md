# Chốt mô hình ở CP2 (MR8b)

Mã: [`selection.py`](../backend/ml/rba/selection.py) · kiểm thử: `tests/test_rba_selection.py` (12). Đây là phần **đổi mô hình** sau khi chủ dự án duyệt D1, D2 và D3 ở CP2 ([`checklist.md`](checklist.md)); MR8 chỉ giải thích mô hình, không đổi. Số liệu chạy trên bộ RBA **tổng hợp** ([`rba-data-card.md`](rba-data-card.md)), giai đoạn test, trọng số dân số, trừ khi ghi khác. Bản MR6 giữ nguyên dưới tên cũ (`hybrid`, `gbm_attacker_sim`, `isolation_forest`) để so trước/sau; bản chốt có hậu tố `_cp2`.

## Tóm tắt

1. **Hybrid chốt (`hybrid_cp2`)** gồm `gbm_attack_ip` (bản MR6, 50 đặc trưng), `gbm_attacker_sim_cp2` (28 đặc trưng quan hệ với lịch sử tài khoản) và `isolation_forest_cp2` (43 đặc trưng, bỏ nhóm `infra_ip`). Ngưỡng vận hành mới 2,391 (báo nhầm 1%) và 3,345 (0,1%).
2. **Bắt ATO thật tốt hơn:** recall ở FPR 1% trên 38 ATO tương lai **26,3% [13–39] → 36,8% [21–51]**, trên cả 130 ATO 23,8% → 31,5%, ROC-AUC 0,923 → 0,934. Khoảng tin cậy còn chồng nhau (chỉ 38 ca): đây là hướng cải thiện có căn cứ, chưa phải khác biệt được chứng minh.
3. **Bắt kẻ tấn công mô phỏng kém hơn — đúng như dự kiến:** 47,1 / 37,2 / 17,8% → 36,4 / 27,0 / 8,4% (Naive / VPN / Targeted). Đó là phần recall trước đây nhờ "nhận ra IP mượn" (kiểm định có điều kiện ở MR8, [`ml-explanations.md`](ml-explanations.md) mục 6); số mới là ước lượng trung thực hơn, vẫn là **cận trên** cho kẻ tấn công thật.
4. **IP tấn công không đổi:** 12,3% → 12,4% (test), 7,3% → 7,2% (late) — vì đề xuất bỏ nhóm `infra_asn` khỏi `gbm_attack_ip` (chọn trên val, PR-AUC +0,007) bị **phủ quyết theo `late`**: recall ở giai đoạn trôi phân phối tụt 11,1% → 6,5% nên giữ bản MR6. ⚠️ Quy tắc phủ quyết được thêm **sau khi đã thấy kết quả**; bản ứng viên vẫn lưu (`gbm_attack_ip_cp2`) để đảo lại nếu muốn.
5. **Độ chính xác cảnh báo ở mức nghiêm ngặt 0,1% đã hơn:** 0,74% (trước 0,25%) nếu tấn công chiếm 1 trên 10.000 đăng nhập, vì recall ATO ở mức này tăng gần gấp ba (2,6% → 7,9%).
6. ⚠️ **Hai điều không được bỏ qua:** (a) 38 ATO tương lai đã bị xem ở MR7 (ablation Isolation Forest), nên chúng xác nhận chứ không "trong sạch"; việc chọn nhóm đặc trưng dùng **92 ca quá khứ** và cho cùng hướng cải thiện (35,9% → 51,1%). (b) ATO của RBA đến từ nhà mạng/quốc gia hiếm một cách nhân tạo: chọn đặc trưng để bắt ATO của bộ dữ liệu này thiên về nhóm phát hiện độ hiếm; đúng cho dữ liệu này, chưa chắc ngoài đời.

## 1. Ai được dùng dữ liệu nào

| Quyết định | Dữ liệu dùng để chọn | Cố ý KHÔNG dùng |
|---|---|---|
| D1 — `gbm_attacker_sim` chỉ dùng nhóm quan hệ với lịch sử (`novelty`, `freeman`, `rhythm`, `history`) | không có tìm kiếm; căn cứ là kiểm định dấu vân tay có điều kiện và ablation MR7 | ATO, `test`, `late` |
| D2a — Isolation Forest bỏ nhóm đặc trưng nào | **92 ATO quá khứ** (trước 09/2020, không warm-up) so với đăng nhập hợp lệ thành công của `val` | 38 ATO tương lai (chỉ báo cáo cuối; đã bị nhìn ở MR7) |
| D2b — `gbm_attack_ip` bỏ nhóm đặc trưng nào | PR-AUC nhãn IP tấn công trên `val` (không ATO) | ATO, `test` |
| Phủ quyết theo `late` (thêm sau) | recall ở `attack_ip/late` (giai đoạn trôi) | — |
| Hiệu chỉnh hybrid, ngưỡng vận hành | đăng nhập hợp lệ của `val` (như MR6) | mọi thứ khác |

**Loại trừ lùi có kiểm định ghép cặp** (`backward_select`): mỗi vòng thử bỏ *một* nhóm đặc trưng còn lại; nhận nhóm cho điểm tốt nhất **chỉ khi** cận dưới một phía 95% của hiệu số so với cấu hình hiện tại > 0, hiệu số tính bằng bootstrap **ghép cặp** trên cùng các cụm dương tính (ATO theo tài khoản, IP tấn công theo IP) lấy lại mẫu 300 lần; dừng khi không nhóm nào đạt hoặc sau 2 vòng, để hạn chế chọn theo nhiễu của 92 ca.

## 2. D1 — mô hình chiếm tài khoản chỉ dùng đặc trưng quan hệ với lịch sử

`gbm_attacker_sim_cp2` dùng 28 đặc trưng của bốn nhóm `novelty`, `freeman`, `rhythm`, `history` và **bỏ** `cur`, `rarity`, `infra_ip`, `infra_asn`. Lý do (không rút ra từ kết quả huấn luyện): kiểm định dấu vân tay có điều kiện cho thấy hạ tầng IP và độ hiếm còn tách được đăng nhập giả khỏi đăng nhập hợp lệ dùng IP mới (AUC 0,67–0,72), mà hai nhóm đó vốn do `ip_tan_cong` và `bat_thuong` đảm nhiệm. PR-AUC trên val của chính bài kẻ tấn công mô phỏng tụt 0,468 → 0,318 vì val cũng mang dấu vân tay đó — cùng lý do khiến **không** chọn theo val ở bước này.

Recall ở FPR 1% (bản MR6 → bản chốt), giai đoạn test:

| Mô hình | IP tấn công (test) | IP tấn công (late) | ATO tương lai (38) | ATO cả 130 | Naive (mô phỏng) | VPN (mô phỏng) | Targeted (mô phỏng) |
|---|---|---|---|---|---|---|---|
| `gbm_attacker_sim` (MR6, 50 đặc trưng) | 4,0% [3,4%–4,7%] | 3,3% [2,7%–3,9%] | 0,0% [0,0%–0,0%] | 0,0% [0,0%–0,0%] | 59,1% [57%–61%] | 50,9% [49%–53%] | 28,5% [26%–30%] |
| `gbm_attacker_sim_cp2` (28 đặc trưng) | 0,4% [0,2%–0,7%] | 0,7% [0,5%–1,0%] | 2,6% [0,0%–7,9%] | 3,1% [0,8%–5,5%] | 47,7% [45%–50%] | 37,7% [36%–40%] | 16,2% [15%–18%] |
| `isolation_forest` (MR6, 50 đặc trưng) | 0,7% [0,5%–1,0%] | 2,2% [0,6%–5,0%] | 42,1% [26%–55%] | 43,1% [34%–51%] | 11,8% [10%–13%] | 6,0% [5%–7%] | 0,5% [0,2%–0,7%] |
| `isolation_forest_cp2` (43, bỏ `infra_ip`) | 0,8% [0,6%–1,1%] | 1,1% [0,5%–1,7%] | 57,9% [42%–74%] | 55,4% [47%–63%] | 13,2% [12%–14%] | 7,5% [6%–9%] | 0,1% [0,0%–0,2%] |
| `gbm_attack_ip` (MR6 — giữ, sau phủ quyết) | 15,0% [11%–20%] | 11,1% [8%–15%] | 0,0% [0,0%–0,0%] | 0,0% [0,0%–0,0%] | 1,1% [0,7%–1,5%] | 1,1% [0,6%–1,4%] | 0,7% [0,4%–1,2%] |
| ứng viên `gbm_attack_ip_cp2` (44, bỏ `infra_asn`) — bị phủ quyết | 14,6% [11%–19%] | 6,5% [5%–9%] | 0,0% [0,0%–0,0%] | 0,0% [0,0%–0,0%] | 1,0% [0,6%–1,5%] | 0,9% [0,5%–1,2%] | 0,7% [0,4%–1,1%] |

Recall trên kẻ tấn công mô phỏng tụt đúng như ablation MR7 dự báo cho cấu hình này (47,7 / 37,7 / 16,2%). Trên ATO thật mô hình vẫn gần như không bắt được (1 trên 38 ca).

## 3. D2a — Isolation Forest chọn nhóm đặc trưng trên 92 ATO quá khứ

**Isolation Forest (bản nhẹ 100 cây), 92 ATO quá khứ so với đăng nhập hợp lệ thành công của val** — 92 ca dương, 155.579 âm; chỉ số chọn: `recall@fpr=0.01`; nhận nhóm khi cận dưới một phía 95% của hiệu số ghép cặp > 0

Vòng 1: cấu hình hiện tại 8 nhóm (50 đặc trưng) — `recall@fpr=0.01` 0,3587, ROC-AUC 0,9249, PR-AUC 0,0024, recall@1% 35,9%

| Bỏ nhóm | Số đặc trưng còn | `recall@fpr=0.01` | Hiệu số | Cận dưới | ROC-AUC | PR-AUC | Recall@1% | Nhận |
|---|---|---|---|---|---|---|---|---|
| `infra_ip` | 43 | 0,5109 | +0,1522 | +0,0967 | 0,9428 | 0,0057 | 51,1% | **có** |
| `cur` | 48 | 0,3587 | +0,0000 | -0,0544 | 0,9037 | 0,0031 | 35,9% |  |
| `freeman` | 42 | 0,3587 | +0,0000 | -0,0646 | 0,9340 | 0,0025 | 35,9% |  |
| `history` | 47 | 0,3261 | -0,0326 | -0,0978 | 0,9254 | 0,0028 | 32,6% |  |
| `rhythm` | 42 | 0,2935 | -0,0652 | -0,1196 | 0,9323 | 0,0019 | 29,3% |  |
| `rarity` | 43 | 0,1522 | -0,2065 | -0,2717 | 0,8256 | 0,0008 | 15,2% |  |
| `infra_asn` | 44 | 0,1087 | -0,2500 | -0,3263 | 0,7898 | 0,0008 | 10,9% |  |
| `novelty` | 41 | 0,0978 | -0,2609 | -0,3335 | 0,9233 | 0,0010 | 9,8% |  |

Vòng 2: cấu hình hiện tại 7 nhóm (43 đặc trưng) — `recall@fpr=0.01` 0,5109, ROC-AUC 0,9428, PR-AUC 0,0057, recall@1% 51,1%

| Bỏ nhóm | Số đặc trưng còn | `recall@fpr=0.01` | Hiệu số | Cận dưới | ROC-AUC | PR-AUC | Recall@1% | Nhận |
|---|---|---|---|---|---|---|---|---|
| `freeman` | 35 | 0,5217 | +0,0109 | -0,0330 | 0,9515 | 0,0065 | 52,2% |  |
| `rhythm` | 35 | 0,4565 | -0,0543 | -0,0979 | 0,9493 | 0,0036 | 45,7% |  |
| `cur` | 41 | 0,4457 | -0,0652 | -0,1003 | 0,9407 | 0,0049 | 44,6% |  |
| `history` | 40 | 0,4022 | -0,1087 | -0,1739 | 0,9505 | 0,0034 | 40,2% |  |
| `novelty` | 34 | 0,3587 | -0,1522 | -0,2198 | 0,9616 | 0,0032 | 35,9% |  |
| `rarity` | 36 | 0,3370 | -0,1739 | -0,2418 | 0,9204 | 0,0027 | 33,7% |  |
| `infra_asn` | 37 | 0,3370 | -0,1739 | -0,2422 | 0,8990 | 0,0023 | 33,7% |  |

Kết quả: giữ `cur`, `novelty`, `history`, `rhythm`, `freeman`, `rarity`, `infra_asn`; bỏ `infra_ip`

Kết quả: **bỏ nhóm `infra_ip`**. Hai nhóm quan trọng nhất cho Isolation Forest là `novelty` và `infra_asn` (bỏ đi recall tụt còn 9,8% và 10,9%), khớp ablation MR7 ([`ml-holdout-ablation.md`](ml-holdout-ablation.md) mục 4.3) nhưng ở đây trên tập chọn **độc lập** với 38 ca tương lai.

**Xác nhận trên 38 ATO tương lai** (bản đầy đủ 300 cây; đã bị nhìn ở MR7): recall ở FPR 1% của Isolation Forest **42,1% [26–55] → 57,9% [42–74]**, ROC-AUC 0,953 → 0,963; trên cả 130 ATO 43,1% → 55,4%. Mức cải thiện trên tập chọn (+15,2 điểm) và trên 38 ca (+15,8 điểm) gần bằng nhau, nhưng đừng đọc con số 57,9% như ước lượng độc lập cho triển khai. Cái giá: Isolation Forest mất khả năng bắt IP tấn công hàng loạt (ROC-AUC `attack_ip/test` 0,685 → 0,534) — vai trò đó thuộc `ip_tan_cong`.

## 4. D2b — `gbm_attack_ip` chọn nhóm đặc trưng trên val, rồi phủ quyết theo `late`

**gbm_attack_ip, PR-AUC nhãn IP tấn công trên val** — 1.996 ca dương, 197.118 âm; chỉ số chọn: `pr_auc`; nhận nhóm khi cận dưới một phía 95% của hiệu số ghép cặp > 0

Vòng 1: cấu hình hiện tại 8 nhóm (50 đặc trưng) — `pr_auc` 0,5466, ROC-AUC 0,9254, PR-AUC 0,5466, recall@1% 19,6%

| Bỏ nhóm | Số đặc trưng còn | `pr_auc` | Hiệu số | Cận dưới | ROC-AUC | PR-AUC | Recall@1% | Nhận |
|---|---|---|---|---|---|---|---|---|
| `infra_asn` | 44 | 0,5534 | +0,0068 | +0,0020 | 0,9234 | 0,5534 | 21,0% | **có** |
| `novelty` | 41 | 0,5460 | -0,0006 | -0,0034 | 0,9246 | 0,5460 | 20,3% |  |
| `infra_ip` | 43 | 0,5451 | -0,0015 | -0,0169 | 0,9263 | 0,5451 | 20,0% |  |
| `history` | 47 | 0,5450 | -0,0015 | -0,0039 | 0,9250 | 0,5450 | 19,3% |  |
| `cur` | 48 | 0,5448 | -0,0018 | -0,0035 | 0,9251 | 0,5448 | 19,1% |  |
| `rhythm` | 42 | 0,5434 | -0,0031 | -0,0073 | 0,9240 | 0,5434 | 19,2% |  |
| `freeman` | 42 | 0,5433 | -0,0033 | -0,0071 | 0,9234 | 0,5433 | 19,7% |  |
| `rarity` | 43 | 0,4827 | -0,0639 | -0,0761 | 0,9084 | 0,4827 | 15,3% |  |

Vòng 2: cấu hình hiện tại 7 nhóm (44 đặc trưng) — `pr_auc` 0,5534, ROC-AUC 0,9234, PR-AUC 0,5534, recall@1% 21,0%

| Bỏ nhóm | Số đặc trưng còn | `pr_auc` | Hiệu số | Cận dưới | ROC-AUC | PR-AUC | Recall@1% | Nhận |
|---|---|---|---|---|---|---|---|---|
| `infra_ip` | 37 | 0,5483 | -0,0051 | -0,0218 | 0,9252 | 0,5483 | 21,6% |  |
| `freeman` | 36 | 0,5435 | -0,0099 | -0,0142 | 0,9230 | 0,5435 | 19,7% |  |
| `novelty` | 35 | 0,5432 | -0,0102 | -0,0144 | 0,9212 | 0,5432 | 19,9% |  |
| `history` | 41 | 0,5426 | -0,0108 | -0,0159 | 0,9229 | 0,5426 | 20,1% |  |
| `rhythm` | 36 | 0,5426 | -0,0108 | -0,0151 | 0,9206 | 0,5426 | 19,3% |  |
| `cur` | 42 | 0,5414 | -0,0120 | -0,0168 | 0,9193 | 0,5414 | 19,2% |  |
| `rarity` | 37 | 0,4028 | -0,1506 | -0,1687 | 0,8850 | 0,4028 | 12,4% |  |

Kết quả: giữ `cur`, `novelty`, `history`, `rhythm`, `freeman`, `rarity`, `infra_ip`; bỏ `infra_asn`

Cuộc chọn (chỉ dùng val) đề xuất **bỏ `infra_asn`**: PR-AUC 0,5466 → 0,5534, cận dưới hiệu số +0,0020. Sau đó kiểm tra giai đoạn trôi phân phối (**không dùng để chọn**):

| | `attack_ip/test` recall@FPR 1% | `attack_ip/late` recall@FPR 1% |
|---|---|---|
| `gbm_attack_ip` (MR6, 50 đặc trưng) | 15,0% [11–20] | **11,1%** [8–15] |
| ứng viên bỏ `infra_asn` (44 đặc trưng) | 14,6% [11–19] | **6,5%** [5–9] |

Cận trên một phía 95% của hiệu số (mới − cũ) ở `late` là −0,032 < 0 nên **phủ quyết**: giữ bản MR6. Cải thiện +0,007 PR-AUC trên **một tháng** val không đáng đổi lấy suy giảm gần một nửa khi phân phối trôi. Nói rõ để chủ dự án quyết: (1) mục đích của `gbm_attack_ip` là chạy được nhiều tháng sau khi huấn luyện; (2) quy tắc phủ quyết được thêm sau khi đã thấy kết quả — không phải quy tắc đăng ký trước; (3) ứng viên đã lưu (`gbm_attack_ip_cp2`), muốn dùng thì dựng lại hybrid với nó (`train_final` có sẵn logic, chỉ cần tắt `late_guard`).

## 5. Kết quả trước → sau

Recall ở FPR 1% trên chính âm tính của mỗi bài (khoảng tin cậy 95% theo cụm dương tính, bootstrap 300 lần), giai đoạn test:

| Mô hình | IP tấn công (test) | IP tấn công (late) | ATO tương lai (38) | ATO cả 130 | Naive (mô phỏng) | VPN (mô phỏng) | Targeted (mô phỏng) |
|---|---|---|---|---|---|---|---|
| `hybrid` (MR6) | 12,3% [9%–16%] | 7,3% [5%–10%] | 26,3% [13%–39%] | 23,8% [16%–32%] | 47,1% [45%–49%] | 37,2% [35%–39%] | 17,8% [16%–20%] |
| **`hybrid_cp2` (chốt)** | 12,4% [9%–17%] | 7,2% [5%–10%] | 36,8% [21%–51%] | 31,5% [24%–40%] | 36,4% [34%–38%] | 27,0% [25%–29%] | 8,4% [7%–10%] |

- **ATO thật:** cải thiện đến từ Isolation Forest bỏ `infra_ip`; ROC-AUC `ato/future` 0,923 → 0,934.
- **IP tấn công:** không đổi (cùng `gbm_attack_ip`).
- **Kẻ tấn công mô phỏng:** giảm cả ba kiểu; Targeted giảm nhiều nhất (17,8% → 8,4%) vì phần lớn tín hiệu Targeted trước đây đến từ hạ tầng IP.
- **Nguồn báo động** (ngưỡng chọn trên val, FPR 1%, `ato/future`): Isolation Forest 28,9%, `chiem_tai_khoan` 2,6%, `ip_tan_cong` 0%.

## 6. Ngưỡng vận hành của bản chốt

Ngưỡng chọn chỉ trên đăng nhập hợp lệ thành công của val, chuyển nguyên sang test và late (`python -m ml.rba.explain_eval operating`):

| FPR mục tiêu (val) | Ngưỡng | FPR thực tế val / test / late | Cảnh báo nhầm / 10 nghìn đăng nhập | Recall ATO thật tương lai (38) | Recall IP tấn công (test) | Recall mô phỏng naive | Recall mô phỏng vpn | Recall mô phỏng targeted |
|---|---|---|---|---|---|---|---|---|
| 1,0% | 2,391 | 1,00% / 0,93% / 0,95% | 93 | 31,6% | 12,1% | 37,0% | 27,4% | 8,7% |
| 0,1% | 3,345 | 0,10% / 0,11% / 0,12% | 11 | 7,9% | 3,9% | 18,8% | 12,1% | 1,8% |

Độ chính xác của cảnh báo (phần cảnh báo là tấn công thật) theo tỉ lệ tấn công giả định trong số đăng nhập thành công, dùng recall ATO thật tương lai:

| Tỉ lệ tấn công | FPR 1,0% | FPR 0,1% |
|---|---|---|
| 1 trên 10.000 | 0,34% | 0,74% |
| 1 trên 1.000 | 3,28% | 6,93% |
| 1 trên 100 | 25,50% | 42,92% |

- Ngưỡng chuyển tốt như MR6: FPR thực tế 0,93% / 0,95% (test / late) cho mục tiêu 1% và 0,11% / 0,12% cho 0,1%.
- Số cảnh báo nhầm/10 nghìn đăng nhập: 93 (trước 102) và 11 (trước 10).
- Độ chính xác của cảnh báo ở mức 0,1%: 0,74% nếu tấn công 1 trên 10.000 (trước 0,25%); ở mức 1%: 0,34% (trước 0,26%). Vẫn rất thấp khi tấn công hiếm: đây là giới hạn của mọi hệ thống chấm điểm rủi ro, không riêng mô hình này.
- Giải thích cảnh báo của hybrid chốt cho kết quả cùng dạng MR8 (xoá yếu tố nêu ra làm mất 100% cảnh báo, ngẫu nhiên 71–95%; ba yếu tố vẫn chỉ là phần chủ đạo với thành phần không giám sát): [`ml-explanations.md`](ml-explanations.md) mục 9.

## 7. Giới hạn

1. **38 ATO tương lai đã bị nhìn** (MR7) — số trên chúng xác nhận hướng cải thiện chứ không phải ước lượng "sạch"; chọn nhóm đặc trưng chỉ dùng 92 ca quá khứ.
2. **ATO của RBA có đặc điểm nhân tạo** (nhà mạng/quốc gia cực hiếm): Isolation Forest bỏ `infra_ip` mạnh lên vì `rarity` và `infra_asn` — nhóm phát hiện độ hiếm — được để lại; khả năng đó có thể không còn khi kẻ tấn công dùng nhà mạng phổ biến (Targeted, VPN cùng nước).
3. **Recall trên kẻ tấn công mô phỏng vẫn là cận trên** cho kẻ tấn công thật: D1 loại phần lớn đường tắt IP nhưng bộ mô phỏng chưa sửa (D1b, gộp vào MR18: sinh lại với IP mượn từ đăng nhập của người cũng đang dùng IP mới).
4. **Phủ quyết theo `late` thêm sau khi thấy kết quả** (mục 4).
5. **Một tháng val** để chọn `gbm_attack_ip`; không có cách nào biết cải thiện nhỏ trên val có bền hay không nếu không có thêm tháng — chính vì vậy cần phủ quyết.
6. **Số vòng tìm kiếm nhỏ** (2 vòng × 8 nhóm) để hạn chế chọn theo nhiễu; không thử tổ hợp nhiều nhóm cùng lúc.

## 8. Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.selection search          # hai cuộc chọn (Isolation Forest trên ATO quá khứ, gbm_attack_ip trên val) -> ml/artifacts/rba_cp2/selection.json
venv\Scripts\python.exe -m ml.rba.selection train           # huấn luyện mô hình cuối, phủ quyết theo late, dựng hybrid_cp2
venv\Scripts\python.exe -m ml.rba.report gbm_attack_ip_cp2 gbm_attacker_sim_cp2 isolation_forest_cp2 hybrid_cp2 --n-boot 300
venv\Scripts\python.exe -m ml.rba.analysis hybrid_cp2
venv\Scripts\python.exe -m ml.rba.explain_eval all          # mặc định chạy trên hybrid_cp2 (thêm --hybrid hybrid để chạy bản MR6)
venv\Scripts\python.exe -m pytest tests/test_rba_selection.py
```
