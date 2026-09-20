# Đánh giá AI v2 trên bộ RBA

Tài liệu kết quả cho giai đoạn mở rộng (MR1–MR19). Khung đo và cách đọc số liệu: [`rba-evaluation.md`](rba-evaluation.md). Bản chất dữ liệu (**tổng hợp**, không phải log thật): [`rba-data-card.md`](rba-data-card.md).

## Điểm kiểm soát CP1 — baseline (MR5)

Sáu mô hình/luật đi qua đúng cùng 8 bài kiểm tra, khoảng tin cậy 95% (bootstrap 300 lần theo cụm dương tính):

| Mô hình | Là gì | Học từ |
|---|---|---|
| `random` | điểm ngẫu nhiên (đường cơ sở tuyệt đối) | không |
| `tier2_current` | luật chấm điểm Tier 2 **hiện tại của hệ thống** (+30 vị trí lạ, +40 dò mật khẩu, +50 thành công sau chuỗi thất bại), xấp xỉ bằng đặc trưng RBA; bỏ luật "lệch giờ" vì RBA không có giờ đáng tin | không |
| `freeman_all` | baseline học thuật Freeman et al. 2016: tổng log-tỉ-số khả năng của 7 thuộc tính (IP, quốc gia, ASN, UA, trình duyệt, OS, thiết bị) | không |
| `freeman_no_ip` | như trên nhưng bỏ IP | không |
| `rules_tuned` | 18 luật ngưỡng do người viết, ngưỡng chọn trên train, trọng số học bằng hồi quy logistic, mục tiêu `Is Attack IP` | train |
| `isolation_forest` | Isolation Forest học trên đăng nhập bình thường của train, **không dùng nhãn** | train |

### Kết quả chính

ROC-AUC [khoảng tin cậy 95%]. Bảng đầy đủ (PR-AUC, recall tại FPR, tỉ lệ xác thực lại, khoảng tin cậy của từng ô): [`rba-baseline-comparison.md`](rba-baseline-comparison.md).

| Bài | `random` | `tier2_current` | `freeman_all` | `rules_tuned` | `isolation_forest` |
|---|---|---|---|---|---|
| **ATO thật, tương lai (38 ca)** | 0,57 [0,46–0,66] | **0,53** [0,51–0,57] | 0,77 [0,67–0,84] | 0,78 [0,73–0,82] | **0,95** [0,92–0,97] |
| ATO thật, nhìn lại (130 ca) | 0,48 | 0,53 | 0,79 | 0,76 | **0,94** |
| Kẻ tấn công **naive** (mô phỏng) | 0,50 | 0,56 | **0,91** | 0,67 | 0,86 |
| Kẻ tấn công **VPN** (mô phỏng) | 0,50 | 0,49 | **0,87** | 0,57 | 0,81 |
| Kẻ tấn công **targeted** (mô phỏng) | 0,50 | 0,50 | **0,46** | 0,62 | 0,54 |
| IP tấn công (test, IP chưa thấy) | 0,50 | 0,51 | **0,47** | **0,86** | 0,71 |

Recall tại FPR 1% (tức bắt được bao nhiêu % tấn công khi chỉ báo nhầm 1% đăng nhập hợp lệ):

| Bài | `tier2_current` | `freeman_all` | `isolation_forest` |
|---|---|---|---|
| ATO thật, tương lai (38 ca) | 0% | 10,5% [2,6–21] | **42,1%** [26–55] |
| Naive | 0% | 22,1% | 11,6% |
| VPN | 0% | 10,1% | 3,4% |
| Targeted | 0,1% | 0% | 0,1% |

### Kết luận

1. **Luật Tier 2 hiện tại của hệ thống gần như không có giá trị** trên dữ liệu này: ROC-AUC 0,49–0,56 ở mọi bài (sát ngẫu nhiên), recall tại FPR 1% bằng 0%. Nguyên nhân: 3 luật gần như luôn bằng 0 (điểm chỉ có vài giá trị rời rạc, phần lớn là 0) và không có luật nào nhìn vào **độ hiếm** của quốc gia/nhà mạng hay hành vi của IP. Đây là bằng chứng số cho việc cần nâng cấp, không phải giả định.
2. **Freeman** (baseline học thuật) tốt với kẻ tấn công không biết gì về nạn nhân (naive 0,91, VPN 0,87) và vừa phải với ATO thật (0,77), nhưng **vô hiệu với kẻ tấn công Targeted (0,46, dưới cả ngẫu nhiên)** và với user chưa có lịch sử. Lý do Targeted "dưới ngẫu nhiên": kẻ tấn công sao chép đúng ASN/UA/thiết bị quen thuộc của nạn nhân nên trông *bình thường hơn* đăng nhập hợp lệ trung bình (vốn hay có giá trị mới).
3. **Isolation Forest không dùng nhãn nào đạt ROC-AUC 0,95 trên ATO thật** và bắt được 42% ATO tương lai khi chỉ báo nhầm 1% — hơn hẳn Freeman (0,77) và khoảng tin cậy không chồng lên nhau. Nhưng nó **kém Freeman trên kẻ tấn công mô phỏng** (naive 0,86 so với 0,91): hai phương pháp bắt hai loại tín hiệu khác nhau, nên kết hợp có lý do rõ ràng (MR6).
4. **Bài IP tấn công là một bài khác hẳn ATO.** Freeman (0,47) và Tier 2 (0,51) không có tín hiệu vì chúng so sánh với lịch sử user, còn lưu lượng từ IP tấn công phần lớn nhắm vào tài khoản chưa có lịch sử hoặc không tồn tại. Luật hạ tầng đã tinh chỉnh đạt 0,86: các luật mạnh nhất là `ip_prior_attempts_all ≥ 42`, `asn_fail_ratio_24h ≥ 0,49`, `rare_country`, `new_country`.
5. **Kẻ tấn công Targeted đánh bại mọi mô hình hiện có** (ROC-AUC ≤ 0,62). Đây là giới hạn cơ bản của chấm điểm theo thuộc tính đăng nhập, không phải lỗi cài đặt; sẽ được báo cáo thẳng trong báo cáo cuối.
6. **Hiệu quả phụ thuộc mạnh vào độ dày lịch sử.** Ở ngưỡng chung cho FPR 1%, với kẻ tấn công naive Freeman bắt 45% nạn nhân có lịch sử dày (≥5 lần thành công) nhưng 0% nạn nhân có lịch sử mỏng (1–4 lần); với VPN là 20% so với 0%. Khoảng một nửa user RBA chỉ có 1–2 lần đăng nhập.
7. **35% ATO thật (46/130) nhắm vào tài khoản chưa có lần đăng nhập thành công nào — không baseline nào bắt được (0/46 ở FPR 1%), nhưng dữ liệu KHÔNG mù với nhóm này.** Riêng trong nhóm đó, `rare_asn` có AUC 0,97 và `rare_country` 0,95 (87% ATO đến từ quốc gia hiếm hơn phân vị 95 của đăng nhập hợp lệ; ASN của chúng có trung vị 0 lượt trong 24h trước so với 14.463 của đăng nhập hợp lệ). Freeman không dùng độ hiếm nên không thấy; Isolation Forest coi 50 đặc trưng ngang nhau nên tín hiệu này bị loãng. Đây là dư địa rõ nhất cho mô hình có giám sát.

### Cảnh báo về cách đọc các số này

- **Chỉ 38 ATO tương lai.** Khoảng tin cậy rộng (ví dụ recall tại FPR 1% của Isolation Forest: 26–55%). Kết luận định tính (Isolation Forest > Freeman > Tier 2 trên ATO thật) vững vì khoảng tin cậy không chồng lên nhau; số cụ thể thì không.
- **Dữ liệu tổng hợp.** ATO thật trong RBA dùng ASN gần như không có lưu lượng nào khác (trung vị 0 lượt/24h). Kẻ tấn công ngoài đời hay dùng nhà mạng phổ biến hơn nhiều, nên điểm cao trên ATO thật của bộ dữ liệu này **có thể lạc quan** so với thực tế. Bài naive/VPN/Targeted dùng đăng nhập thật làm "người cho" nên không có thiên lệch này, và cho kết quả thấp hơn ở Isolation Forest (0,81–0,86) — phản ánh tốt hơn phần khó.
- **Kẻ tấn công mô phỏng là cận lạc quan** về khả năng chống chịu: kẻ tấn công thật có thể bắt chước hoàn hảo hơn "targeted".
- Recall tại FPR nhỏ của `rules_tuned` thấp (3,8–5,3%) dù ROC-AUC 0,86–0,88 vì điểm chỉ có vài giá trị rời rạc (tổng của ~18 cờ nhị phân): khó cắt ngưỡng sát ở FPR 1%.
- Nhóm "chưa có lịch sử" không có mặt ở bài `attacker/*` (nạn nhân luôn có ≥ 1 lần thành công), chỉ có ở bài ATO thật.

### Hệ quả cho MR6 (điều chỉnh kế hoạch)

Kết quả CP1 cho thấy dữ liệu **có** tín hiệu vượt xa Freeman và Tier 2, nên kế hoạch tiếp tục. Bổ sung một hướng mới từ kết quả này:

- **Huấn luyện có giám sát trên kẻ tấn công mô phỏng** (sinh cho nạn nhân ở giai đoạn train bằng cùng bộ mô phỏng của MR4), đánh giá ngoài trên ATO thật chưa từng dùng khi học. Cách này tận dụng được nhãn "tấn công vào tài khoản có lịch sử" mà nhãn `Is Attack IP` (chủ yếu là lưu lượng dò mật khẩu hàng loạt) không cung cấp, và tránh dùng 141 nhãn ATO hiếm. Rủi ro cần đo: kẻ tấn công mô phỏng lấy thuộc tính từ đăng nhập thật nên không có "chữ ký ASN hiếm" của ATO thật; mô hình học từ chúng có thể không bắt được chữ ký đó.
- Kết hợp có giám sát (IP tấn công + kẻ tấn công mô phỏng) với Isolation Forest (không nhãn) và đặc trưng Freeman, hiệu chỉnh xác suất, rồi so lại trên cùng 8 bài.

## Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.attackers          # ~11 phút, nên chạy nền
venv\Scripts\python.exe -m ml.rba.report all --n-boot 300   # ~4 phút; ghi ml/artifacts/rba_reports/*.md, comparison.md
```
