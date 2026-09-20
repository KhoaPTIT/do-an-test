# Khung đánh giá trên bộ RBA (MR4)

Một lệnh sinh bảng kết quả chuẩn cho **mọi** mô hình hoặc luật chấm điểm, để so sánh công bằng ở MR5–MR7:

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.report freeman_all            # tên đăng ký trong ml/rba/scorers.py
venv\Scripts\python.exe -m ml.rba.report all --n-boot 300      # so sánh mọi mô hình cạnh nhau
venv\Scripts\python.exe -m ml.rba.report random --n-boot 200
```

Kết quả in ra màn hình và lưu ở `backend/ml/artifacts/rba_reports/<tên>.md` và `.json`. Mã: [`metrics.py`](../backend/ml/rba/metrics.py) (chỉ số + bootstrap), [`eval_tasks.py`](../backend/ml/rba/eval_tasks.py) (các bài kiểm tra + bảng), [`attackers.py`](../backend/ml/rba/attackers.py) (mô phỏng kẻ tấn công), [`scorers.py`](../backend/ml/rba/scorers.py) (sổ đăng ký mô hình).

## 1. Nguyên tắc

- **Cùng một bộ bài cho mọi mô hình.** Mô hình chỉ là hàm `bảng đặc trưng → điểm rủi ro` (càng cao càng đáng ngờ).
- **Có trọng số.** Dòng tấn công chỉ được giữ theo nhóm IP nên cần trọng số để phục hồi tỉ lệ tấn công tự nhiên (~5,9%); nếu không, precision và PR-AUC sai ([`rba-data-card.md`](rba-data-card.md) mục 8).
- **Khoảng tin cậy 95%** cho mọi chỉ số (bootstrap 500 lần).
- **Tách riêng user mới và user có lịch sử**, vì 39,7% user RBA chỉ có 1 lần đăng nhập.
- **Không chọn ngưỡng trên tập test.** Mô hình có tham số học từ train, ngưỡng chọn trên val (MR6); test chỉ để báo cáo.

## 2. Các bài kiểm tra

| Bài | Dương tính | Âm tính |
|---|---|---|
| `attack_ip/val`, `/test`, `/late` | dòng thuộc IP tấn công (**IP chưa từng thấy ở train**) | dòng bình thường cùng giai đoạn |
| `ato/future` | 38 ca ATO từ 09–11/2020 (tương lai so với train/val) | đăng nhập hợp lệ thành công giai đoạn test |
| `ato/all` | 130 ca ATO ngoài warm-up (nhìn lại, lạc quan hơn) | đăng nhập hợp lệ thành công train+val+test |
| `attacker/naive`, `/vpn`, `/targeted` | ~2.000 đăng nhập kẻ tấn công mô phỏng mỗi loại | như `ato/future` |

"Đăng nhập hợp lệ thành công" = thành công, không thuộc IP tấn công, không phải ATO. Đăng nhập thành công **từ IP tấn công không được tính là âm tính**: chúng có thể là tấn công chưa gắn nhãn, đưa vào sẽ phạt oan mô hình. Con số công bố chính cho ATO là `ato/future` (38 ca); `ato/all` chỉ là số phụ vì dùng cả các ca xảy ra trước thời điểm mô hình học xong.

## 3. Chỉ số

Cảnh báo khi điểm ≥ ngưỡng.

| Chỉ số | Ý nghĩa |
|---|---|
| ROC-AUC, PR-AUC | có trọng số, khớp `scikit-learn` (test kiểm chứng, kể cả khi có điểm bằng nhau) |
| Recall @ FPR 1% và 0,1% | bắt được bao nhiêu tấn công nếu chỉ chịu báo nhầm 1% (0,1%) đăng nhập hợp lệ |
| **Xác thực lại @ TPR 90% và 99%** | phải yêu cầu xác thực thêm bao nhiêu % đăng nhập hợp lệ để bắt được 90% (99%) tấn công — chỉ số chính của nghiên cứu RBA |
| Cảnh báo / 1.000 đăng nhập và / ngày | ở ngưỡng bắt được 90% / 99% dòng tấn công, quy về toàn bộ dân số user được chấm điểm (nhân lại tỉ lệ lấy mẫu theo tầng) |
| Theo mức lịch sử | với **một ngưỡng chung** cho FPR 1%: recall và tỉ lệ báo nhầm của user chưa có lịch sử / mỏng (1–4) / dày (≥5) — user mới có bị thử thách oan nhiều hơn không |

## 4. Khoảng tin cậy

Bootstrap **theo cụm dương tính**: lấy mẫu lại các ca tấn công có hoàn lại (theo IP cho bài `attack_ip`, theo user cho ATO), giữ **cố định** tập âm tính. Lý do và giới hạn:

- ATO chỉ có 38–141 ca nên bất định của số liệu đến từ số ca dương tính hữu hạn; tập âm tính hàng trăm nghìn dòng đóng góp không đáng kể.
- Giữ tập âm tính cố định cho phép tính mỗi lần lấy mẫu trong O(P log P), nên 500 lần bootstrap chỉ mất vài giây.
- Các dòng cùng cụm (cùng IP tấn công, cùng user) không độc lập nên luôn được lấy cùng nhau.
- Khoảng tin cậy **không** phản ánh bất định do chọn mẫu user (mẫu 401 nghìn trên 4,3 triệu) và do một tập huấn luyện cụ thể.

## 5. Mô phỏng kẻ tấn công (theo Wiefling et al. 2022)

Chỉ có 38 ATO tương lai nên không đủ để kết luận chắc. Giao thức chuẩn của nghiên cứu RBA là **chèn đăng nhập của kẻ tấn công giả định vào lịch sử của user hợp lệ**:

| Loại | Biết gì về nạn nhân | Thuộc tính đăng nhập giả |
|---|---|---|
| **Naive** | không gì cả | IP/ASN/quốc gia/UA lấy nguyên từ một đăng nhập thật của người khác trong 1 giờ trước |
| **VPN** | quốc gia hay gặp nhất | như trên, nhưng đăng nhập thật được chọn phải cùng quốc gia đó |
| **Targeted** | quốc gia, nhà mạng (ASN), thiết bị và trình duyệt | ASN và UA/trình duyệt/OS/thiết bị đúng của nạn nhân, chỉ **IP mới** (lấy từ đăng nhập thật cùng ASN) |

- Nạn nhân: 6.000 user khác nhau ở giai đoạn `test`, chia đều 3 loại; **luôn có ít nhất 1 lần đăng nhập thành công trước đó** (đăng nhập thật làm mốc), nên nhóm "chưa có lịch sử" không có mặt ở bài `attacker/*`. Mỗi người có đúng một đăng nhập giả **thành công** (đã có mật khẩu), 2–72 giờ sau đăng nhập thật đó.
- Đặc trưng tính bằng **đúng pipeline MR3** (bằng SQL đã được chứng minh bằng test là bằng đặc tả), nên đặc trưng hạ tầng (hoạt động của IP/ASN quanh thời điểm) cũng thực tế.
- Tất định: cùng seed cho cùng kết quả; hồ sơ "hay gặp nhất" của nạn nhân hoà thì lấy giá trị nhỏ nhất theo thứ tự (tránh phụ thuộc số luồng).
- **Nạn nhân không có "người cho" phù hợp bị loại** (chủ yếu ở loại Targeted, cần cùng ASN).

Kết quả sinh: `backend/ml/data/rba/rba_attackers.parquet` (**5.966 đăng nhập giả**: 2.000 naive, 2.000 vpn, 1.966 targeted; 34 nạn nhân Targeted bị loại vì không có "người cho" cùng ASN). Sinh và tính đặc trưng mất ~11 phút.

Thuộc tính đăng nhập giả so với hồ sơ nạn nhân (kiểm chứng trên dữ liệu thật):

| Loại | Cùng quốc gia | Cùng ASN | Cùng UA | Cùng loại thiết bị |
|---|---|---|---|---|
| naive | 53,1% | 20,8% | 1,4% | 51,0% |
| vpn | 100% | 41,9% | 1,7% | 56,0% |
| targeted | 97,4% | 100% | 100% | 100% |

Lưu ý: kẻ tấn công **naive trùng ASN với nạn nhân tới 20,8%** vì một nhà mạng Na Uy chiếm phần lớn lưu lượng trong bộ dữ liệu — đặc điểm thật của phân phối, làm bài naive khó hơn "hoàn toàn ngẫu nhiên".

**Giới hạn thẳng thắn:** kẻ tấn công bắt chước hoàn hảo (cùng IP, cùng thiết bị, cùng giờ với nạn nhân) không nằm trong giao thức này và cũng là giới hạn đã biết của mọi hệ thống chấm điểm rủi ro theo thuộc tính đăng nhập. Kết quả trên kẻ tấn công mô phỏng là **cận dưới lạc quan** về khả năng chống chịu, không phải bảo đảm.

## 6. Tự kiểm chứng khung đánh giá

- **Chỉ số khớp thư viện chuẩn:** ROC-AUC và average precision có trọng số bằng `scikit-learn` đến 1e-12 (có điểm bằng nhau); recall@FPR và FPR@TPR khớp tính vét cạn trên đường cong ROC (`tests/test_rba_metrics.py`, 18 test).
- **Mô hình ngẫu nhiên trên dữ liệu thật** cho đúng kết quả lý thuyết — bằng chứng khung không tự tạo ra hiệu năng:

| Bài (điểm ngẫu nhiên) | ROC-AUC | PR-AUC | Tỉ lệ tấn công có trọng số |
|---|---|---|---|
| `attack_ip/val` | 0,497 | 0,062 | 6,3% |
| `attack_ip/test` | 0,501 | 0,059 | 5,9% |
| `attack_ip/late` | 0,500 | 0,081 | 8,1% |
| `ato/future` | 0,566 [0,470–0,655] | 0,000 | (rất hiếm) |

PR-AUC của mô hình ngẫu nhiên trùng đúng tỉ lệ tấn công có trọng số ở từng giai đoạn, xác nhận cột `weight` phục hồi đúng tỉ lệ tự nhiên. Recall tại FPR 1% ≈ 1%, xác thực lại tại TPR 90% ≈ 90% và tại TPR 99% ≈ 99%, đúng như lý thuyết cho điểm không mang thông tin.
