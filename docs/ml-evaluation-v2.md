# Đánh giá AI v2 trên bộ RBA

Tài liệu kết quả cho giai đoạn mở rộng (MR1–MR19). Khung đo và cách đọc số liệu: [`rba-evaluation.md`](rba-evaluation.md). Bản chất dữ liệu (**tổng hợp**, không phải log thật): [`rba-data-card.md`](rba-data-card.md). Mô hình, dữ liệu học và giới hạn: [`model-card-rba.md`](model-card-rba.md). Bảng đầy đủ mọi mô hình × mọi bài, kèm khoảng tin cậy: [`rba-baseline-comparison.md`](rba-baseline-comparison.md).

> ⚠️ **Cập nhật CP2 (26/09/2026):** các số ở tài liệu này là của **hybrid MR6** (`hybrid`). Sau khi chốt mô hình ở CP2 ([`ml-model-selection.md`](ml-model-selection.md)) hybrid vận hành là `hybrid_cp2` (Isolation Forest bỏ nhóm `infra_ip`, `gbm_attacker_sim` chỉ 28 đặc trưng quan hệ với lịch sử): ATO tương lai 26,3% → 36,8%, IP tấn công 12,3% → 12,4%, kẻ tấn công mô phỏng 47,1 / 37,2 / 17,8% → 36,4 / 27,0 / 8,4%. Kết luận định tính của tài liệu này giữ nguyên; tổng hợp lại toàn bộ số ở MR19.

## Đính chính (21/09/2026): hai sai sót của báo cáo CP1

Trong lúc làm MR6 tôi phát hiện hai sai sót ở báo cáo CP1 (MR4–MR5). Cả hai đã sửa, **mọi số liệu trong tài liệu này được sinh lại từ mã**, số cũ không còn hiệu lực.

**1. Trọng số dân số.** CP1 đo tỉ lệ báo nhầm trên mẫu user phân tầng (5% user chỉ đăng nhập 1 lần, 10% vài lần, 25% nhiều lần), tức nghiêng về user hoạt động nhiều. Nay mọi chỉ số dùng `pop_weight = weight ÷ tỉ lệ lấy mẫu của tầng` để quy về toàn bộ 4,3 triệu user. Kết luận CP1 về ATO thật không đổi (ROC-AUC thay đổi tối đa 0,095 ở mô hình `random` trên 38 ca, do nhiễu; luật đã tinh chỉnh −0,03…−0,04).

**2. Bộ mô phỏng kẻ tấn công của CP1 để lại "dấu vân tay".** Khi huấn luyện mô hình trên kẻ tấn công mô phỏng, nó đạt recall **100% kể cả với kẻ tấn công Targeted bắt chước hoàn hảo** — kết quả tốt quá mức là dấu hiệu của lối tắt, không phải của mô hình giỏi. Tôi viết công cụ kiểm định ([`audit.py`](../backend/ml/rba/audit.py): huấn luyện một mô hình nhỏ để tách đăng nhập giả khỏi đăng nhập thật theo từng nhóm đặc trưng) và phát hiện bộ mô phỏng CP1 tách được hoàn toàn (ROC-AUC 1,000; riêng nhóm nhịp 0,94, nhóm IP 0,92, nhóm lịch sử 0,74–0,76). Tôi mất **bảy lần sửa** (mỗi lần do kiểm định chỉ ra, liệt kê ở [`rba-evaluation.md`](rba-evaluation.md) mục 5.1) đến khi các nhóm nhịp/lịch sử/hạ tầng/độ hiếm đều ≈ 0,5. Hệ quả: **mọi số của bài `attacker/*` ở CP1 sai**, và định nghĩa Targeted đổi (nay: biết trọn hồ sơ phiên của nạn nhân, chỉ IP mới).

ROC-AUC của các baseline CP1 trước và sau khi sửa (bộ mô phỏng mới, trọng số dân số):

| Mô hình | Naive: CP1 → nay | VPN: CP1 → nay | Targeted: CP1 → nay | ATO thật tương lai: CP1 → nay |
|---|---|---|---|---|
| `random` | 0,50 → 0,49 | 0,50 → 0,50 | 0,50 → 0,51 | 0,57 → 0,47 |
| `tier2_current` | 0,56 → 0,55 | 0,49 → 0,50 | 0,50 → 0,50 | 0,53 → 0,53 |
| `rules_tuned` | 0,67 → 0,55 | 0,57 → 0,51 | 0,62 → 0,53 | 0,78 → 0,74 |
| `freeman_all` | 0,91 → 0,93 | 0,87 → 0,91 | 0,46 → 0,67 | 0,77 → 0,76 |
| `isolation_forest` | 0,86 → 0,76 | 0,81 → 0,74 | 0,54 → 0,54 | 0,95 → 0,95 |

Kết luận CP1 về **ATO thật** đứng vững (Isolation Forest > Freeman ≈ luật tinh chỉnh > Tier 2 ≈ ngẫu nhiên). Kết luận về **kẻ tấn công mô phỏng** đổi: Freeman không còn "dưới ngẫu nhiên" ở Targeted (0,67) và Isolation Forest kém Freeman xa hơn (0,76 so với 0,93 ở Naive).

## Tóm tắt MR6

Các con số dưới đây đều ở **FPR 1%** (chỉ báo nhầm 1% đăng nhập hợp lệ), giai đoạn test, trọng số dân số:

| Họ tấn công | Tier 2 hiện tại | Luật đã tinh chỉnh | Freeman (học thuật) | Isolation Forest | LightGBM chuyên dụng | **Hybrid** |
|---|---|---|---|---|---|---|
| **ATO thật, tương lai (38 ca)** | 0% | 0% | 15,8% | **42,1%** | 0% (IP tấn công) / 0% (mô phỏng) | 26,3% |
| IP tấn công (test) | 0,2% | 3,9% | 0,3% | 0,7% | **15,0%** | 12,3% |
| Kẻ tấn công **Naive** (mô phỏng) | 1,1% | 5,4% | 35,0% | 11,8% | **59,1%** | 47,1% |
| Kẻ tấn công **VPN** (mô phỏng) | 1,2% | 0,1% | 26,5% | 6,0% | **50,9%** | 37,2% |
| Kẻ tấn công **Targeted** (mô phỏng) | 1,6% | 0,5% | 1,5% | 0,5% | **28,5%** | 17,8% |

1. **Hybrid là mô hình duy nhất có khả năng phát hiện đáng kể ở cả ba họ.** Rule Tier 2 hiện tại của hệ thống gần như vô dụng trên bộ dữ liệu này (recall ≤ 1,6% ở mọi bài); luật tinh chỉnh chỉ khá ở IP tấn công.
2. **Mỗi bộ phát hiện giỏi một họ, và không bộ nào giỏi hết**: LightGBM học từ kẻ tấn công mô phỏng bắt 59/51/29% kẻ tấn công mô phỏng nhưng 0% ATO thật; LightGBM học từ nhãn IP tấn công bắt 15% IP tấn công (luật tinh chỉnh: 3,9%) nhưng 0% ATO thật; Isolation Forest không nhãn bắt 42% ATO thật nhưng ≤ 12% các họ khác. Hybrid ghép ba bộ phát hiện và giữ được phần lớn từng bộ.
3. **Kết quả âm tính quan trọng: mô hình có giám sát KHÔNG chuyển được sang ATO thật.** Hai nguồn nhãn có sẵn (IP tấn công, kẻ tấn công mô phỏng) đều không giống ATO thật của bộ dữ liệu, vốn đến từ nhà mạng/quốc gia cực hiếm; chỉ bộ phát hiện không giám sát bắt được. Đây là lý do hybrid giữ Isolation Forest. (ATO thật trong RBA có thể mang đặc điểm nhân tạo của bộ dữ liệu — xem mục 8.)
4. **Cá nhân hoá quyết định khả năng chống chiếm tài khoản**: bỏ đặc trưng theo user thì ROC-AUC trên kẻ tấn công mô phỏng rơi về mức ngẫu nhiên (0,94 → 0,51), còn IP tấn công không đổi (0,86 → 0,90).
5. **Hybrid không báo nhầm tài khoản mới nhiều hơn mức chung** (0,56% ở ngưỡng chung cho FPR 1%; Isolation Forest 0,29%) **nhưng cũng chưa có mô hình nào bắt được ATO ở tài khoản chưa có lịch sử** (35% số ATO; 0/46 ở hybrid và mọi mô hình có giám sát, 1/46 ở Isolation Forest và Autoencoder). Đây là giới hạn chưa giải quyết.
6. **Ngưỡng chọn trên val giữ đúng mức báo nhầm** ở test và ở giai đoạn trôi phân phối (hybrid, mục tiêu 1%: 0,92% ở test, 0,85% ở late).

7. **Kiểm chứng thêm ở MR7** ([`ml-holdout-ablation.md`](ml-holdout-ablation.md)): giấu một họ IP tấn công khỏi huấn luyện thì LightGBM gần như mất khả năng bắt họ đó (0,0–1,1% ở 5 trong 6 họ mà nó bắt được khi đã thấy); chỉ với kẻ tấn công mô phỏng mới tổng quát một phần (giữ 30–91%). Một luật một đặc trưng `rare_asn` (không học) bắt 65,8% ATO tương lai, hơn mọi mô hình ở đây.
8. **Giải thích và ngưỡng vận hành ở MR8** ([`ml-explanations.md`](ml-explanations.md)): mỗi cảnh báo có tối đa 3 yếu tố (SHAP cho LightGBM, z-score cho bộ không giám sát) kèm "thường … → nay …"; xoá các yếu tố nêu ra làm mất 99–100% cảnh báo (ngẫu nhiên 49–90%) nhưng ba yếu tố chỉ là phần chủ đạo của điểm (bộ không giám sát: ~68%). Ngưỡng hybrid 2,410 / 3,365 cho ~102 / ~10 cảnh báo nhầm trên 10 nghìn đăng nhập hợp lệ thành công; độ chính xác của cảnh báo chỉ 0,26% nếu tấn công chiếm 1 trên 10.000 đăng nhập, và siết ngưỡng xuống 0,1% không cải thiện nó. ⚠️ Kiểm định dấu vân tay **có điều kiện** (so với đăng nhập hợp lệ cũng dùng IP mới) cho thấy bộ mô phỏng còn tách được ở nhóm IP/độ hiếm (AUC 0,67–0,72): mọi recall trên kẻ tấn công mô phỏng ở tài liệu này là **cận trên** (tối đa khoảng 6–12 điểm), ATO thật không bị ảnh hưởng.

Mọi kết luận chịu các giới hạn ở mục 8: dữ liệu **tổng hợp**, chỉ **38** ATO tương lai (khoảng tin cậy rộng), và kẻ tấn công mô phỏng là chuẩn so sánh, không phải bảo đảm.

## 1. Các mô hình và cách chọn

Mười ba mô hình/luật đi qua đúng cùng 11 bài kiểm tra, khoảng tin cậy 95% (bootstrap 300 lần theo cụm dương tính). Mô tả đầy đủ và quy tắc chống rò rỉ: [`model-card-rba.md`](model-card-rba.md).

| Mô hình | Là gì | Học từ |
|---|---|---|
| `random` | điểm ngẫu nhiên (đường cơ sở tuyệt đối) | không |
| `tier2_current` | luật chấm điểm Tier 2 **hiện tại của hệ thống**, xấp xỉ bằng đặc trưng RBA (bỏ luật "lệch giờ" vì RBA không có giờ đáng tin) | không |
| `rules_tuned` | 18 luật ngưỡng, ngưỡng chọn trên train, trọng số hồi quy logistic | train (nhãn IP tấn công) |
| `freeman_all`, `freeman_no_ip` | baseline học thuật Freeman et al. 2016: tổng log-tỉ-số khả năng của 7 thuộc tính (có/không IP) | không |
| `isolation_forest`, `knn_distance`, `autoencoder` | bộ phát hiện bất thường không giám sát, học từ đăng nhập bình thường | train, không nhãn |
| `gbm_attack_ip` | LightGBM, nhãn `Is Attack IP` (chia theo nhóm IP) | train |
| `gbm_attacker_sim` | LightGBM, kẻ tấn công **mô phỏng** so với đăng nhập hợp lệ của tài khoản có lịch sử | train |
| `gbm_combined` | LightGBM, cả hai nguồn dương tính; tỉ trọng ρ chọn trên val | train |
| `gbm_combined_global` | như trên, chỉ đặc trưng toàn cục (đo giá trị của cá nhân hoá) | train |
| `hybrid` | báo động khi bất kỳ bộ phát hiện nào (`gbm_attack_ip`, `gbm_attacker_sim` có cổng, `isolation_forest` có cổng) thấy bằng chứng cực đoan; hiệu chỉnh trên val | train + val |

**Chọn mô hình chỉ trên val** (điểm chọn = 0,5 × PR-AUC bài IP tấn công + 0,5 × recall@FPR 1% trung bình 3 kẻ tấn công mô phỏng val; **không dùng ATO thật**, không dùng test):

| Mô hình | Điểm chọn (val) | AP IP tấn công (val) | Recall@FPR 1% Naive / VPN / Targeted (val) |
|---|---|---|---|
| `gbm_attack_ip` | 0.278 | 0.547 | 0.9% / 0.7% / 1.2% |
| `gbm_attacker_sim` | 0.330 | 0.218 | 56.5% / 46.7% / 29.5% |
| `gbm_combined` | 0.387 | 0.470 | 44.2% / 32.5% / 14.2% |
| `gbm_combined_global` | 0.274 | 0.540 | 0.6% / 0.6% / 1.0% |
| `knn_distance` | 0.081 | 0.086 | 13.7% / 7.4% / 1.3% |
| `autoencoder` | 0.075 | 0.089 | 13.2% / 4.6% / 0.9% |
| `isolation_forest` | 0.085 | 0.115 | 10.9% / 4.9% / 0.8% |
| `hybrid` | 0.363 | 0.402 | 45.9% / 33.9% / 17.3% |

Chọn ρ = 0,25 cho `gbm_combined` (thử ρ ∈ {0,25; 1}: điểm 0,387 và 0,364). Hybrid có điểm chọn thấp hơn `gbm_combined` (0,363 so với 0,387) vì phải chia ngân sách báo nhầm cho ba bộ phát hiện; tôi vẫn giữ hybrid làm mô hình chính vì (a) thiết kế đó được quyết định từ trước khi có kết quả, dựa trên việc mỗi họ tấn công cần một bộ phát hiện khác, và (b) `gbm_combined` không giữ được khả năng bắt ATO thật (mục 3). Tôi **không** đổi thành phần hybrid theo kết quả trên test hay ATO.

## 2. Kết quả trên test

Giai đoạn test 09–11/2020 (tương lai so với train/val), ngưỡng và tham số không được chọn trên test. `attack_ip/late` (12/2020–02/2021) đo khả năng chịu trôi phân phối.

**ROC-AUC**

| Mô hình | `attack_ip/test` | `attack_ip/late` | `ato/future` | `ato/all` | `attacker/naive` | `attacker/vpn` | `attacker/targeted` |
|---|---|---|---|---|---|---|---|
| `random` | 0.496 | 0.499 | 0.471 | 0.460 | 0.490 | 0.501 | 0.508 |
| `tier2_current` | 0.501 | 0.504 | 0.532 | 0.532 | 0.554 | 0.501 | 0.503 |
| `rules_tuned` | 0.861 | 0.843 | 0.735 | 0.717 | 0.550 | 0.506 | 0.525 |
| `freeman_all` | 0.480 | 0.496 | 0.759 | 0.775 | 0.933 | 0.906 | 0.665 |
| `freeman_no_ip` | 0.422 | 0.438 | 0.709 | 0.729 | 0.902 | 0.860 | 0.496 |
| `isolation_forest` | 0.685 | 0.695 | 0.953 | 0.944 | 0.764 | 0.739 | 0.541 |
| `knn_distance` | 0.522 | 0.506 | 0.892 | 0.856 | 0.784 | 0.756 | 0.637 |
| `autoencoder` | 0.557 | 0.540 | 0.863 | 0.806 | 0.739 | 0.695 | 0.564 |
| `gbm_attack_ip` | 0.905 | 0.885 | 0.844 | 0.823 | 0.426 | 0.415 | 0.406 |
| `gbm_attacker_sim` | 0.676 | 0.685 | 0.724 | 0.697 | 0.968 | 0.958 | 0.907 |
| `gbm_combined` | 0.862 | 0.816 | 0.850 | 0.798 | 0.944 | 0.932 | 0.859 |
| `gbm_combined_global` | 0.900 | 0.873 | 0.817 | 0.791 | 0.512 | 0.525 | 0.501 |
| `hybrid` | 0.822 | 0.794 | 0.923 | 0.892 | 0.934 | 0.919 | 0.835 |

**Recall khi báo nhầm 1% đăng nhập hợp lệ**

| Mô hình | `attack_ip/test` | `attack_ip/late` | `ato/future` | `ato/all` | `attacker/naive` | `attacker/vpn` | `attacker/targeted` |
|---|---|---|---|---|---|---|---|
| `random` | 0.8% | 0.9% | 0.0% | 1.5% | 1.1% | 0.9% | 0.9% |
| `tier2_current` | 0.2% | 0.5% | 0.0% | 0.0% | 1.1% | 1.2% | 1.6% |
| `rules_tuned` | 3.9% | 1.6% | 0.0% | 0.0% | 5.4% | 0.1% | 0.5% |
| `freeman_all` | 0.3% | 0.2% | 15.8% | 15.4% | 35.0% | 26.5% | 1.5% |
| `freeman_no_ip` | 0.3% | 0.2% | 15.8% | 13.8% | 32.4% | 22.0% | 0.8% |
| `isolation_forest` | 0.7% | 2.2% | 42.1% | 43.1% | 11.8% | 6.0% | 0.5% |
| `knn_distance` | 1.0% | 2.3% | 18.4% | 20.8% | 14.2% | 8.2% | 0.9% |
| `autoencoder` | 0.5% | 1.9% | 13.2% | 17.7% | 11.4% | 4.4% | 1.2% |
| `gbm_attack_ip` | 15.0% | 11.1% | 0.0% | 0.0% | 1.1% | 1.1% | 0.7% |
| `gbm_attacker_sim` | 4.0% | 3.3% | 0.0% | 0.0% | 59.1% | 50.9% | 28.5% |
| `gbm_combined` | 13.2% | 9.4% | 7.9% | 8.5% | 49.1% | 39.1% | 16.6% |
| `gbm_combined_global` | 14.5% | 9.8% | 0.0% | 0.0% | 0.8% | 0.6% | 0.7% |
| `hybrid` | 12.3% | 7.3% | 26.3% | 23.8% | 47.1% | 37.2% | 17.8% |

**Recall khi báo nhầm 0,1% đăng nhập hợp lệ**

| Mô hình | `attack_ip/test` | `attack_ip/late` | `ato/future` | `ato/all` | `attacker/naive` | `attacker/vpn` | `attacker/targeted` |
|---|---|---|---|---|---|---|---|
| `random` | 0.1% | 0.1% | 0.0% | 0.0% | 0.1% | 0.1% | 0.1% |
| `tier2_current` | 0.0% | 0.0% | 0.0% | 0.0% | 0.2% | 0.0% | 0.0% |
| `rules_tuned` | 0.6% | 0.6% | 0.0% | 0.0% | 5.4% | 0.1% | 0.0% |
| `freeman_all` | 0.0% | 0.1% | 0.0% | 0.8% | 13.4% | 8.5% | 0.1% |
| `freeman_no_ip` | 0.0% | 0.0% | 0.0% | 1.5% | 12.8% | 7.2% | 0.0% |
| `isolation_forest` | 0.1% | 1.4% | 5.3% | 6.2% | 1.8% | 0.7% | 0.0% |
| `knn_distance` | 0.1% | 1.4% | 0.0% | 0.8% | 1.6% | 0.6% | 0.0% |
| `autoencoder` | 0.1% | 1.5% | 0.0% | 0.8% | 2.1% | 0.5% | 0.0% |
| `gbm_attack_ip` | 9.7% | 3.1% | 0.0% | 0.0% | 0.0% | 0.1% | 0.1% |
| `gbm_attacker_sim` | 0.3% | 0.3% | 0.0% | 0.0% | 32.0% | 22.8% | 8.9% |
| `gbm_combined` | 7.2% | 1.8% | 0.0% | 0.0% | 25.4% | 17.0% | 3.1% |
| `gbm_combined_global` | 8.1% | 1.2% | 0.0% | 0.0% | 0.1% | 0.0% | 0.1% |
| `hybrid` | 4.2% | 2.1% | 2.6% | 3.1% | 25.1% | 15.7% | 5.0% |

**Tỉ lệ đăng nhập hợp lệ phải xác thực lại để bắt 90% tấn công**

| Mô hình | `attack_ip/test` | `attack_ip/late` | `ato/future` | `ato/all` | `attacker/naive` | `attacker/vpn` | `attacker/targeted` |
|---|---|---|---|---|---|---|---|
| `random` | 89.1% | 90.3% | 89.8% | 90.0% | 91.1% | 90.3% | 89.5% |
| `tier2_current` | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| `rules_tuned` | 25.4% | 26.3% | 47.1% | 45.7% | 87.6% | 92.8% | 76.6% |
| `freeman_all` | 91.6% | 89.9% | 74.1% | 62.2% | 20.1% | 26.6% | 62.5% |
| `freeman_no_ip` | 94.1% | 93.1% | 92.3% | 80.5% | 28.5% | 40.4% | 88.1% |
| `isolation_forest` | 60.6% | 57.4% | 17.5% | 12.6% | 62.8% | 61.7% | 83.5% |
| `knn_distance` | 85.5% | 86.7% | 45.1% | 46.9% | 59.4% | 65.7% | 79.2% |
| `autoencoder` | 80.6% | 80.3% | 50.9% | 56.1% | 67.1% | 72.8% | 84.5% |
| `gbm_attack_ip` | 17.7% | 23.3% | 24.5% | 21.1% | 97.8% | 97.8% | 97.8% |
| `gbm_attacker_sim` | 69.5% | 69.8% | 49.2% | 51.4% | 9.7% | 13.4% | 28.3% |
| `gbm_combined` | 24.2% | 36.1% | 39.8% | 37.3% | 19.4% | 21.7% | 37.7% |
| `gbm_combined_global` | 18.1% | 25.0% | 20.2% | 19.7% | 89.2% | 87.3% | 90.1% |
| `hybrid` | 31.1% | 39.0% | 25.0% | 26.8% | 21.4% | 27.1% | 46.8% |

**Đọc bảng.**

- **IP tấn công.** `gbm_attack_ip` đạt ROC-AUC 0,905 và PR-AUC 0,441 trên test (luật tinh chỉnh: 0,861 và 0,280; Tier 2: 0,501), recall@FPR 1% là 15,0% so với 3,9% và 9,7% so với 0,6% ở FPR 0,1%. Giai đoạn `late` (trôi phân phối: tỉ lệ tấn công 7,9% → 10,9%) giảm còn 0,885 / 11,1% nhưng vẫn hơn luật tinh chỉnh (0,843 / 1,6%). Nhưng 15% recall ở FPR 1% là thấp về giá trị tuyệt đối: nhiều dòng tấn công trông giống đăng nhập bình thường nếu chỉ nhìn từng dòng; chặn theo IP (blocklist) là phần bổ sung, không phải thứ mô hình thay thế. Freeman (0,480) không có tín hiệu vì so sánh với lịch sử user, còn lưu lượng tấn công phần lớn nhắm vào tài khoản chưa có lịch sử.
- **Kẻ tấn công mô phỏng.** `gbm_attacker_sim` bắt 59,1% / 50,9% / 28,5% (Naive/VPN/Targeted) ở FPR 1%, so với Freeman 35,0% / 26,5% / 1,5% và luật tinh chỉnh 5,4% / 0,1% / 0,5%. Lưu ý công bằng: mô hình này được huấn luyện trên cùng họ mô phỏng (kẻ tấn công **khác**, nạn nhân **khác**, giai đoạn **khác**) nên có lợi thế so với các baseline không học từ đó. Tín hiệu Targeted (mimic hoàn hảo trừ IP) đến từ tương tác "IP mới × khoảng cách ngắn từ lần thành công trước" — tín hiệu thật nhưng phụ thuộc giả định kẻ tấn công đăng nhập đúng nhịp của nạn nhân ([`rba-evaluation.md`](rba-evaluation.md) mục 5.3).
- **ATO thật:** mục 3.

## 3. ATO thật: bằng chứng ngoài duy nhất

141 ca ATO thật không bao giờ được dùng để học hay chọn. Con số công bố chính là **38 ca ở tương lai** (`ato/future`); `ato/all` (130 ca sau warm-up) chỉ là số phụ vì gồm cả ca xảy ra trước thời điểm mô hình học xong.

**ROC-AUC (khoảng tin cậy 95%)**

| Mô hình | `ato/future` | `ato/all` |
|---|---|---|
| `random` | 0.471 [0.38–0.57] | 0.460 [0.41–0.51] |
| `tier2_current` | 0.532 [0.51–0.57] | 0.532 [0.51–0.55] |
| `rules_tuned` | 0.735 [0.69–0.78] | 0.717 [0.69–0.74] |
| `freeman_all` | 0.759 [0.66–0.83] | 0.775 [0.73–0.81] |
| `freeman_no_ip` | 0.709 [0.58–0.81] | 0.729 [0.68–0.78] |
| `isolation_forest` | 0.953 [0.93–0.97] | 0.944 [0.92–0.96] |
| `knn_distance` | 0.892 [0.83–0.94] | 0.856 [0.82–0.89] |
| `autoencoder` | 0.863 [0.79–0.92] | 0.806 [0.77–0.84] |
| `gbm_attack_ip` | 0.844 [0.80–0.87] | 0.823 [0.80–0.84] |
| `gbm_attacker_sim` | 0.724 [0.68–0.76] | 0.697 [0.67–0.72] |
| `gbm_combined` | 0.850 [0.79–0.90] | 0.798 [0.77–0.82] |
| `gbm_combined_global` | 0.817 [0.79–0.83] | 0.791 [0.76–0.82] |
| `hybrid` | 0.923 [0.87–0.96] | 0.892 [0.86–0.92] |

**Recall @ FPR 1% (khoảng tin cậy 95%)**

| Mô hình | `ato/future` | `ato/all` |
|---|---|---|
| `random` | 0.0% [0%–0%] | 1.5% [0%–4%] |
| `tier2_current` | 0.0% [0%–0%] | 0.0% [0%–0%] |
| `rules_tuned` | 0.0% [0%–0%] | 0.0% [0%–0%] |
| `freeman_all` | 15.8% [7%–29%] | 15.4% [9%–21%] |
| `freeman_no_ip` | 15.8% [7%–29%] | 13.8% [8%–20%] |
| `isolation_forest` | 42.1% [26%–55%] | 43.1% [34%–51%] |
| `knn_distance` | 18.4% [8%–32%] | 20.8% [15%–27%] |
| `autoencoder` | 13.2% [3%–25%] | 17.7% [12%–23%] |
| `gbm_attack_ip` | 0.0% [0%–0%] | 0.0% [0%–0%] |
| `gbm_attacker_sim` | 0.0% [0%–0%] | 0.0% [0%–0%] |
| `gbm_combined` | 7.9% [0%–17%] | 8.5% [5%–13%] |
| `gbm_combined_global` | 0.0% [0%–0%] | 0.0% [0%–0%] |
| `hybrid` | 26.3% [13%–39%] | 23.8% [16%–32%] |

- **Isolation Forest không nhãn là mô hình tốt nhất trên ATO thật**: ROC-AUC 0,953 [0,93–0,97], bắt 42,1% [26–55%] ca ở FPR 1%. Hybrid 0,923 [0,87–0,96], 26,3% [13–39%]; khoảng tin cậy của hai mô hình chồng nhau nên không kết luận được chúng khác nhau. Cả hai hơn rõ Freeman (0,759 [0,66–0,83], 15,8%), luật tinh chỉnh (0,735, 0%) và Tier 2 (0,532, 0%).
- **Các mô hình có giám sát không chuyển sang ATO thật ở FPR thấp**: `gbm_attack_ip` và `gbm_attacker_sim` đạt ROC-AUC 0,84 và 0,72 nhưng recall@FPR 1% bằng **0%**; `gbm_combined` 7,9%. Nguyên nhân (MR7 xác nhận ở [`ml-holdout-ablation.md`](ml-holdout-ablation.md) mục 4.3 và 5.1: bỏ nhóm độ hiếm/mới lạ/ASN làm Isolation Forest mất khả năng bắt ATO): ATO thật của bộ dữ liệu dùng nhà mạng và quốc gia cực hiếm (trung vị nhà mạng của chúng có 0 lượt thử trong 24 giờ trước, so với 14.463 của đăng nhập hợp lệ), khác cả lưu lượng IP tấn công (đông, nhiều lượt) lẫn kẻ tấn công mô phỏng (mượn nhà mạng phổ biến của đăng nhập thật); Isolation Forest coi "hiếm" là bất thường nên bắt được. Kẻ tấn công ngoài đời hay dùng nhà mạng phổ biến hơn, nên **điểm cao của Isolation Forest trên ATO thật của bộ dữ liệu này có thể lạc quan** so với thực tế.
- **Thành phần nào làm nên kết quả hybrid** (ngưỡng hybrid chọn trên val cho FPR 1%): trong 26,3% ATO thật hybrid bắt được, 23,7 điểm phần trăm do `bat_thuong` (Isolation Forest) và 2,6 do `chiem_tai_khoan`; `ip_tan_cong` không bắt ca nào. Ngược lại 11,8/12,0 điểm phần trăm IP tấn công do `ip_tan_cong`, và gần như toàn bộ kẻ tấn công mô phỏng do `chiem_tai_khoan` (mục 6).

## 4. Cá nhân hoá và tài khoản mới (cold-start)

**Cá nhân hoá.** `gbm_combined_global` chỉ dùng đặc trưng toàn cục (không có lịch sử theo user); `gbm_combined` dùng cả 50:

| Bài | ROC-AUC `gbm_combined` | ROC-AUC chỉ toàn cục | Recall@FPR 1% `gbm_combined` | Recall@FPR 1% chỉ toàn cục |
|---|---|---|---|---|
| IP tấn công (test) | 0,862 | 0,900 | 13,2% | 14,5% |
| ATO thật tương lai | 0,850 | 0,817 | 7,9% | 0% |
| Naive (mô phỏng) | 0,944 | 0,512 | 49,1% | 0,8% |
| VPN (mô phỏng) | 0,932 | 0,525 | 39,1% | 0,6% |
| Targeted (mô phỏng) | 0,859 | 0,501 | 16,6% | 0,7% |

Chiếm tài khoản là bài toán **về quan hệ giữa đăng nhập và lịch sử của tài khoản**: không có đặc trưng theo user thì mô hình không phân biệt được (0,5). Ngược lại lưu lượng tấn công IP hàng loạt không cần cá nhân hoá (mô hình toàn cục còn nhỉnh hơn một chút: 0,900 so với 0,862).

**Tài khoản mới ở ngưỡng chung cho FPR 1%** (recall / tỉ lệ báo nhầm; 39,7% user RBA chỉ có 1 lần đăng nhập):

**Theo mức lịch sử của tài khoản — bài `ato/future`, ngưỡng chung cho FPR 1%** (recall / báo nhầm)

| Mô hình | Chưa có lịch sử | Mỏng (1–4) | Dày (≥5) |
|---|---|---|---|
| `tier2_current` | 0% / 0.09% | 0% / 0.00% | 0% / 0.00% |
| `rules_tuned` | 0% / 0.00% | 0% / 0.97% | 0% / 0.15% |
| `freeman_all` | 0% / 0.00% | 10% / 0.02% | 40% / 2.11% |
| `isolation_forest` | 0% / 0.29% | 50% / 1.07% | 60% / 1.22% |
| `gbm_combined` | 0% / 0.76% | 5% / 0.71% | 20% / 1.31% |
| `gbm_combined_global` | 0% / 2.29% | 0% / 1.05% | 0% / 0.46% |
| `hybrid` | 0% / 0.56% | 25% / 0.90% | 50% / 1.24% |

**Theo mức lịch sử của tài khoản — bài `ato/all`, ngưỡng chung cho FPR 1%** (recall / báo nhầm)

| Mô hình | Chưa có lịch sử | Mỏng (1–4) | Dày (≥5) |
|---|---|---|---|
| `tier2_current` | 0% / 0.05% | 0% / 0.00% | 0% / 0.00% |
| `rules_tuned` | 0% / 2.51% | 0% / 0.56% | 0% / 0.13% |
| `freeman_all` | 0% / 0.00% | 10% / 0.06% | 44% / 2.81% |
| `isolation_forest` | 2% / 0.36% | 64% / 1.08% | 68% / 1.38% |
| `gbm_combined` | 0% / 0.95% | 4% / 0.89% | 26% / 1.16% |
| `gbm_combined_global` | 0% / 1.92% | 0% / 0.99% | 0% / 0.34% |
| `hybrid` | 0% / 0.54% | 26% / 0.95% | 53% / 1.39% |

- Với hybrid và các bộ phát hiện dựa vào lịch sử (Isolation Forest, kNN, Freeman), tài khoản chưa có lịch sử **không bị báo nhầm nhiều hơn** mức chung (hybrid 0,56%, Isolation Forest 0,29%, thấp hơn 1%): không có lịch sử thì ít gì để coi là "lạ". Ngoại lệ: mô hình chỉ có đặc trưng toàn cục (`gbm_combined_global` 2,29%) và `gbm_attack_ip` (2,14%) báo nhầm nhóm này nhiều gấp đôi mức chung; trong hybrid, `gbm_attacker_sim` (5,5% ở nhóm này) bị chặn bằng cổng "đã có lịch sử" chính vì lý do đó.
- Nhưng **không mô hình nào bắt được ATO ở tài khoản chưa có lịch sử** (0/8 ở `ato/future`; tối đa 1/46 ở `ato/all`). Chẩn đoán thêm: Isolation Forest chỉ trên đặc trưng toàn cục (hạ tầng, độ hiếm) đạt ROC-AUC 0,947 nhưng recall@FPR 1% cũng chỉ 5,3% (6,5% ở nhóm chưa có lịch sử), nên tôi **không** đưa nó vào hybrid như một "fallback" — nó không giải quyết được vấn đề. Cold-start vẫn là khoảng trống lớn nhất, 35% số ATO nằm ở đây; hướng khả dĩ: luật hạ tầng (MR9) và ngân sách xác thực lại riêng cho tài khoản mới.
- Với tấn công mô phỏng (luôn nhắm tài khoản có lịch sử), mô hình bắt tốt hơn ở tài khoản dày (≥ 5 lần thành công) so với mỏng (1–4):

**Theo mức lịch sử của tài khoản — bài `attacker/naive`, ngưỡng chung cho FPR 1%** (recall / báo nhầm)

| Mô hình | Chưa có lịch sử | Mỏng (1–4) | Dày (≥5) |
|---|---|---|---|
| `tier2_current` | — | 2% / 1.42% | 1% / 0.57% |
| `rules_tuned` | — | 5% / 0.97% | 6% / 0.15% |
| `freeman_all` | — | 2% / 0.02% | 47% / 1.73% |
| `isolation_forest` | — | 5% / 0.91% | 14% / 1.07% |
| `gbm_combined` | — | 33% / 0.67% | 55% / 1.25% |
| `gbm_combined_global` | — | 1% / 1.53% | 1% / 0.60% |
| `hybrid` | — | 36% / 0.82% | 51% / 1.13% |

## 5. Chuyển ngưỡng và hiệu chỉnh xác suất

**Chuyển ngưỡng.** Chọn ngưỡng chỉ trên đăng nhập hợp lệ của `val` cho FPR mục tiêu, rồi áp nguyên ngưỡng ấy lên test và late (không chọn lại). Tỉ lệ báo nhầm **thực tế** và recall của hybrid:

| Họ bài | Áp lên | FPR mục tiêu 1% → thực tế | Recall | FPR mục tiêu 0,1% → thực tế | Recall |
|---|---|---|---|---|---|
| IP tấn công | test | 0,92% | 12,1% | 0,08% | 3,9% |
| IP tấn công | late (trôi phân phối) | 0,85% | 7,1% | 0,09% | 2,1% |
| ATO thật | tương lai (38 ca) | 1,02% | 26,3% | 0,10% | 2,6% |
| ATO thật | tất cả (130 ca) | 0,85% | 20,8% | 0,08% | 2,3% |
| Naive (mô phỏng) | test | 1,04% | 47,8% | 0,12% | 26,2% |
| VPN (mô phỏng) | test | 1,04% | 37,6% | 0,12% | 17,2% |
| Targeted (mô phỏng) | test | 1,04% | 18,5% | 0,12% | 5,6% |

Ngưỡng của hybrid **giữ đúng mức báo nhầm mục tiêu** (0,85–1,04% khi đích 1%; 0,08–0,12% khi đích 0,1%) kể cả ở giai đoạn trôi phân phối `late`; recall thì giảm (IP tấn công 12,1% → 7,1%). Điều này nhờ hiệu chỉnh từng thành phần bằng phân phối điểm của đăng nhập hợp lệ trên val. Với LightGBM đơn lẻ, ngưỡng chọn trên val cũng bảo thủ: `gbm_attack_ip` (mục tiêu 1%) cho FPR 0,35% ở test và 0,33% ở late; `gbm_attacker_sim` cho 1,01% trên kẻ tấn công mô phỏng (đúng mục tiêu).

**Hiệu chỉnh xác suất.** Hồi quy isotonic học trên val biến điểm `gbm_attack_ip` thành xác suất một dòng thuộc IP tấn công. Trên test, Brier score 0,0532 (isotonic), 0,0604 (xác suất thô), 0,0726 (đoán theo tỉ lệ trung bình); bảng độ tin cậy theo phân vị (nhóm cao nhất: dự đoán 33,2%, thực tế 34,4%; nhóm 9: 9,3% và 8,6%) cho thấy xác suất đáng tin ở vùng cảnh báo. Ở `late`, xác suất **dưới ước lượng** (nhóm 9: dự đoán 14,6%, thực tế 21,0%; nhóm 10: 34,7% và 38,4%) vì tỉ lệ tấn công thật tăng từ 8,4% (val) lên 10,9%: xác suất cần hiệu chỉnh lại định kỳ khi phân phối trôi.

## 6. Ai bắt được gì: đóng góp của từng thành phần hybrid

Ngưỡng hybrid chọn trên đăng nhập hợp lệ thành công của val cho FPR 1%. Mỗi ô là phần ca dương tính được thành phần đó báo (thành phần có xác suất đuôi nhỏ nhất); dòng đầu là phần đăng nhập hợp lệ bị báo nhầm do từng thành phần.

| Bài | Ca dương | Recall | `ip_tan_cong` | `chiem_tai_khoan` | `bat_thuong` |
|---|---|---|---|---|---|
| đăng nhập hợp lệ thành công (val) | — | báo nhầm 1,00% | 0,3% | 0,3% | 0,4% |
| `attack_ip/test` | 5.709 | 12,0% | 11,8% | 0,1% | 0,1% |
| `ato/future` | 38 | 26,3% | 0,0% | 2,6% | 23,7% |
| `ato/all` | 130 | 20,8% | 0,0% | 1,5% | 19,2% |
| `attacker/naive` | 2.000 | 48,9% | 0,0% | 47,2% | 1,7% |
| `attacker/vpn` | 1.995 | 39,7% | 0,1% | 38,0% | 1,6% |
| `attacker/targeted` | 1.916 | 19,4% | 0,2% | 19,1% | 0,1% |

Phân công rõ ràng: mỗi họ tấn công do đúng một bộ phát hiện gánh, các bộ còn lại gần như chỉ tốn ngân sách báo nhầm (mỗi bộ chiếm 0,3–0,4% trong 1%). Đó là cái giá của việc ghép bằng "bất kỳ bộ nào báo động": recall của hybrid trên từng họ thấp hơn bộ phát hiện chuyên dụng ở cùng tổng FPR (IP tấn công 12,3% so với 15,0%; Naive 47,1% so với 59,1%; ATO thật 26,3% so với 42,1%). Ghép bằng mô hình học (stacking) trên val có thể lấy lại một phần, chưa làm.

## 7. Kết luận

1. **AI hơn rule-based rõ rệt trên dữ liệu này, ở cả ba họ tấn công** — nhưng bằng ba bộ phát hiện khác nhau, không phải một mô hình "thông minh hơn hết". Rule Tier 2 hiện tại của hệ thống gần như ngẫu nhiên (đây là kết quả trên bản xấp xỉ bằng đặc trưng RBA; các luật địa lý/giờ của dự án không thử được trên RBA).
2. **Phát hiện bất thường không giám sát bắt được ATO thật, mô hình có giám sát thì không** — kết quả ngược với kỳ vọng ban đầu ("huấn luyện trên kẻ tấn công mô phỏng sẽ tổng quát sang tấn công thật") và là lý do hybrid có cả hai.
3. **Cá nhân hoá là điều kiện cần cho chống chiếm tài khoản**, không cần cho IP tấn công hàng loạt.
4. **Ngưỡng chọn trên tập tiền-test đứng vững qua trôi phân phối** ở mức báo nhầm; recall thì suy giảm (IP tấn công 12,1% → 7,1%), cần theo dõi và huấn luyện lại định kỳ.
5. **Khoảng trống chưa giải quyết:** ATO ở tài khoản chưa có lịch sử (35% số ATO, 0% recall), và kẻ tấn công bắt chước hoàn hảo IP.

## 8. Giới hạn (đọc trước khi trích số liệu)

- **Dữ liệu tổng hợp** ([`rba-data-card.md`](rba-data-card.md)): mọi con số là "trên bộ RBA tổng hợp", không phải "trên đăng nhập thật". Đặc biệt ATO thật của bộ dữ liệu có nhà mạng hiếm bất thường (nghi ngờ đặc điểm nhân tạo), có thể làm Isolation Forest **lạc quan**.
- **Chỉ 38 ATO tương lai**: khoảng tin cậy rộng (Isolation Forest 26–55%; hybrid 13–39% ở FPR 1%). Kết luận định tính (không giám sát > có giám sát trên ATO thật; mọi mô hình học > Tier 2) vững vì khoảng tin cậy không chồng; thứ hạng giữa Isolation Forest và hybrid thì không.
- **Kẻ tấn công mô phỏng là chuẩn so sánh, không phải bảo đảm**: hoà lẫn về hạ tầng, đăng nhập đúng nhịp của nạn nhân, Targeted biết trọn hồ sơ phiên. Mô hình học từ chính họ mô phỏng này nên có lợi thế; số tuyệt đối không suy ra được cho kẻ tấn công thật. Bộ mô phỏng đã qua kiểm định dấu vân tay (mục 5.2 của [`rba-evaluation.md`](rba-evaluation.md)) nhưng kiểm định chỉ bắt được lối tắt theo nhóm đặc trưng, không chứng minh không còn lối tắt nào.
- **Kẻ tấn công bắt chước cả IP** (proxy trên máy nạn nhân, đánh cắp phiên) nằm ngoài phạm vi và là giới hạn đã biết của chấm điểm theo thuộc tính đăng nhập.
- **Kiểu tấn công mới** đã đo ở MR7 ([`ml-holdout-ablation.md`](ml-holdout-ablation.md)): mô hình có giám sát không bắt được họ IP tấn công chưa thấy (0,0–1,1% ở 5/6 họ bắt được khi đã thấy; bộ phát hiện không nhãn cao nhất 10,1%). **Không tuyên bố "phát hiện được tấn công mới"**; chỉ nói hệ thống cần huấn luyện lại khi có họ mới.
- **Tài khoản mới**: xem mục 4.

## Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.attackers                    # bộ mô phỏng test, ~10 phút, nên chạy nền
venv\Scripts\python.exe -m ml.rba.attackers --period trainval  # bộ huấn luyện/chọn mô hình, ~8 phút
venv\Scripts\python.exe -m ml.rba.audit                        # kiểm định dấu vân tay (test)
venv\Scripts\python.exe -m ml.rba.audit trainval               # ... và train, val
venv\Scripts\python.exe -m ml.rba.train                        # huấn luyện mọi mô hình, ~8 phút; ml/artifacts/rba/
venv\Scripts\python.exe -m ml.rba.report all --n-boot 300      # 13 mô hình × 11 bài, ~15 phút; ml/artifacts/rba_reports/
venv\Scripts\python.exe -m ml.rba.analysis gbm_attack_ip gbm_attacker_sim hybrid   # chuyển ngưỡng, hiệu chỉnh, gán công
venv\Scripts\python.exe -m ml.rba.summary                      # bảng ma trận mô hình × bài từ báo cáo đã lưu
```
