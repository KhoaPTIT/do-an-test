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
- **Có trọng số.** Dòng tấn công chỉ được giữ theo nhóm IP nên cần trọng số `weight` để phục hồi tỉ lệ tấn công tự nhiên (~5,9%); nếu không, precision và PR-AUC sai ([`rba-data-card.md`](rba-data-card.md) mục 8).
- **Trọng số dân số (`pop_weight`, thêm ở MR6).** Mẫu user lấy theo tầng (5% user chỉ đăng nhập 1 lần, 10% vài lần, 25% nhiều lần) nên user hoạt động nhiều bị đại diện thừa; tỉ lệ báo nhầm đo trên mẫu thô nghiêng về họ. `pop_weight = weight ÷ tỉ lệ lấy mẫu của tầng` quy mọi chỉ số (ROC/PR-AUC, FPR, số cảnh báo/ngày, chọn ngưỡng) về toàn bộ 4,3 triệu user. Bản CP1 dùng `weight`; kết luận CP1 không đổi nhưng số thay đổi nhẹ — xem "Đính chính" trong [`ml-evaluation-v2.md`](ml-evaluation-v2.md).
- **Khoảng tin cậy 95%** cho mọi chỉ số (bootstrap 500 lần).
- **Tách riêng user mới và user có lịch sử**, vì 39,7% user RBA chỉ có 1 lần đăng nhập.
- **Không chọn ngưỡng trên tập test.** Mô hình có tham số học từ train; dừng sớm, chọn siêu tham số và ngưỡng chỉ dùng `val` (bài `attack_ip/val`, `attacker_val/*`); `test` và `late` chỉ để báo cáo. 141 ca ATO thật không bao giờ được dùng để học hay chọn.

## 2. Các bài kiểm tra

| Bài | Dương tính | Âm tính |
|---|---|---|
| `attack_ip/val`, `/test`, `/late` | dòng thuộc IP tấn công (**IP chưa từng thấy ở train**) | dòng bình thường cùng giai đoạn |
| `ato/future` | 38 ca ATO từ 09–11/2020 (tương lai so với train/val) | đăng nhập hợp lệ thành công giai đoạn test |
| `ato/all` | 130 ca ATO ngoài warm-up (nhìn lại, lạc quan hơn) | đăng nhập hợp lệ thành công train+val+test |
| `attacker/naive`, `/vpn`, `/targeted` | 2.000 / 1.995 / 1.916 đăng nhập kẻ tấn công mô phỏng, nạn nhân giai đoạn test | đăng nhập hợp lệ thành công của giai đoạn test **của tài khoản đã có lịch sử** (`u_n_success ≥ 1`, đúng như nạn nhân) |
| `attacker_val/*` | như trên, nạn nhân giai đoạn val, user khác | như trên, giai đoạn val — **chỉ để chọn mô hình, không báo cáo là kết quả** |

"Đăng nhập hợp lệ thành công" = thành công, không thuộc IP tấn công, không phải ATO. Đăng nhập thành công **từ IP tấn công không được tính là âm tính**: chúng có thể là tấn công chưa gắn nhãn, đưa vào sẽ phạt oan mô hình. Con số công bố chính cho ATO là `ato/future` (38 ca); `ato/all` chỉ là số phụ vì dùng cả các ca xảy ra trước thời điểm mô hình học xong. Bài `attacker/*` chỉ so với âm tính có lịch sử vì đăng nhập giả luôn thay thế một đăng nhập của tài khoản đã có lịch sử; so với cả tài khoản mới sẽ cho mô hình một lối tắt ("tài khoản mới = hợp lệ") không có ở tấn công thật.

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

Chỉ có 38 ATO tương lai nên không đủ để kết luận chắc. Giao thức chuẩn của nghiên cứu RBA là **chèn đăng nhập của kẻ tấn công giả định vào lịch sử của user hợp lệ**. Mã: [`attackers.py`](../backend/ml/rba/attackers.py); kiểm định: [`audit.py`](../backend/ml/rba/audit.py).

**Nạn nhân** là một *đăng nhập gốc*: một đăng nhập hợp lệ, thành công của tài khoản đã có lịch sử (`u_n_success ≥ 1`), chọn ngẫu nhiên **đều theo dòng** trong giai đoạn (một user có thể bị chọn nhiều lần, đúng theo tỉ lệ đăng nhập của họ; chỉ user có ATO thật bị loại). Đăng nhập giả **thay thế** đăng nhập gốc đúng thời điểm đó — thành công (đã có mật khẩu), và khi tính đặc trưng đăng nhập gốc bị **bỏ khỏi luồng sự kiện** nên tổng số đếm toàn cục được bảo toàn. IP lấy từ một "người cho": đăng nhập thật đầu tiên của **người khác** thoả điều kiện, xảy ra **sau** thời điểm đó.

| Loại | Kẻ tấn công biết gì | Người cho phải | Thuộc tính đăng nhập giả |
|---|---|---|---|
| **Naive** | không gì cả | user khác | IP, ASN, quốc gia, UA, trình duyệt, OS, thiết bị của người cho |
| **VPN** | quốc gia của nạn nhân | user khác, cùng quốc gia với đăng nhập gốc | như naive |
| **Targeted** | toàn bộ hồ sơ phiên của nạn nhân, **trừ IP** | user khác, cùng ASN với đăng nhập gốc | quốc gia, ASN, UA, trình duyệt, OS, thiết bị **đúng bằng** đăng nhập gốc; chỉ IP là của người cho |

- **Targeted là kẻ tấn công mạnh nhất có thể theo thuộc tính đăng nhập** (cận trên sức mạnh, tức cận dưới của khả năng phát hiện): mọi đặc trưng liên quan hồ sơ nạn nhân (mới lạ, Freeman, độ hiếm) giống hệt đăng nhập gốc, chỉ còn IP khác.
- Đặc trưng tính bằng **đúng pipeline MR3** (SQL đã chứng minh bằng test là bằng đặc tả), nên đặc trưng hạ tầng (hoạt động của IP/ASN quanh thời điểm) cũng thực tế.
- Tất định: cùng seed cho cùng kết quả. Nạn nhân không có người cho phù hợp trong 24 giờ sau (chủ yếu Targeted ở ASN hiếm) bị loại.
- **Đăng nhập giả HOÀ LẪN về hạ tầng**: IP/ASN là của một đăng nhập thật bất kỳ. Tấn công có dấu hiệu hạ tầng rõ (IP tấn công dò mật khẩu hàng loạt) do nhãn `Is Attack IP` và mô hình `gbm_attack_ip` phụ trách; bộ mô phỏng chỉ đo phần tấn công theo quan hệ với **lịch sử của nạn nhân**.

### 5.1 Bài học: bảy lỗi "dấu vân tay" trong bộ mô phỏng (đã sửa)

Mô hình học từ kẻ tấn công mô phỏng dễ học **cách mô phỏng** thay vì cách tấn công. Phiên bản đầu của tôi cho mô hình có giám sát đạt recall 100% kể cả với Targeted — dấu hiệu chắc chắn của lối tắt, không phải của mô hình giỏi. Từ đó tôi viết `python -m ml.rba.audit` (mục 5.2) và lặp lại đến khi sạch. Mỗi lỗi bên dưới đều do audit chỉ ra:

| # | Thiết kế sai | Dấu hiệu audit | Sửa |
|---|---|---|---|
| 1 | Chèn 2–72 giờ sau một đăng nhập thật của nạn nhân | nhóm nhịp AUC 0,94 (khoảng cách giữa các lần đăng nhập ngắn hơn người thật) | thay thế đúng một đăng nhập thật, mốc chọn theo dòng |
| 2 | Mượn IP của đăng nhập người khác ngay **trước** mốc | 100% có "IP vừa được người khác dùng" (đăng nhập hợp lệ 43%); nhóm IP AUC 0,92 | người cho lấy **sau** mốc (đặc trưng chỉ nhìn sự kiện trước nên đăng nhập của người cho không nằm trong ngữ cảnh của đăng nhập giả) |
| 3 | IP hoàn toàn mới (chưa ai từng dùng) | nhóm IP AUC 0,96; độ hiếm 0,97–0,98 | IP thật của người cho |
| 4 | Hồ sơ Targeted = giá trị **hay gặp nhất** của nạn nhân | Freeman tách 38,8%, độ hiếm 32,9% ở FPR 1% (quen thuộc tối đa) | — |
| 5 | Hồ sơ Targeted = lần đăng nhập **gần nhất** | Freeman tách 31,6%: trong RBA tổng hợp **52% đăng nhập hợp lệ có UA mới** nên lần gần nhất là "quen mong manh" (llr_ua trung vị −5,1 so với +0,7 của đăng nhập hợp lệ) | hồ sơ = đúng đăng nhập gốc (không có lựa chọn nào của tôi để lệch phân phối) |
| 6 | Mỗi user một nạn nhân; bộ val loại các user đã là nạn nhân ở bộ khác | user hoạt động nhiều vắng ở dương tính nhưng có ở âm tính (theo dòng) | chọn đăng nhập gốc đều theo dòng, cho phép cùng user nhiều lần |
| 7 | Chỉ **chèn** đăng nhập giả vào luồng sự kiện | nhóm độ hiếm tách 59–64% ở val (test ~6–9%, train ~15–18%): mỗi đăng nhập giả cộng thêm số đếm toàn cục mà đăng nhập thật không có; độ lệch vài phần vạn tích luỹ theo số đăng nhập giả và LightGBM (chia thùng theo phân vị, rất mịn ở vùng dày) học được | **bỏ đăng nhập gốc** khỏi luồng sự kiện (thay thế), tổng số đếm được bảo toàn |

### 5.2 Kiểm định dấu vân tay (bắt buộc sau mỗi lần sinh)

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.audit            # bộ test
venv\Scripts\python.exe -m ml.rba.audit trainval   # bộ huấn luyện và chọn mô hình, tách riêng train và val
```

Với mỗi kiểu kẻ tấn công và mỗi **nhóm đặc trưng**, huấn luyện một LightGBM nhỏ để tách đăng nhập giả khỏi đăng nhập hợp lệ thành công (của tài khoản đã có lịch sử, **cùng giai đoạn**), chấm trên các user chưa dùng khi học. Hai chỉ số: ROC-AUC và **recall khi báo nhầm 1% đăng nhập hợp lệ** (chỉ số quan trọng hơn: AUC bị chi phối bởi phần lớn phân phối, còn cảnh báo thật chỉ hoạt động ở FPR nhỏ). Đọc kết quả:

- Sáu nhóm **`cur`, `history`, `rhythm`, `rarity`, `infra_ip`, `infra_asn`** phải ≈ 0,5 (recall ≈ 1%): đăng nhập giả có cùng nhịp, lịch sử, hạ tầng, độ hiếm thuộc tính như một đăng nhập thật. Cao hơn hẳn (AUC ≥ 0,6 hoặc recall ≥ 10%) = còn dấu vân tay, phải sửa bộ mô phỏng trước khi huấn luyện.
- Hai nhóm **`novelty`, `freeman`** là tín hiệu tấn công **thật** (thuộc tính lạ so với lịch sử nạn nhân): cao với Naive/VPN.

Kết quả bộ **test** (5.911 đăng nhập giả từ 6.000 nạn nhân: 2.000 Naive / 1.995 VPN / 1.916 Targeted):

| ROC-AUC | n | tất cả | cur | history | rhythm | rarity | infra_ip | infra_asn | novelty | freeman |
|---|---|---|---|---|---|---|---|---|---|---|
| Naive | 2.000 | 0,968 | 0,517 | 0,502 | 0,506 | 0,483 | 0,515 | 0,521 | 0,926 | 0,945 |
| VPN | 1.995 | 0,963 | 0,492 | 0,501 | 0,513 | 0,492 | 0,528 | 0,505 | 0,910 | 0,932 |
| Targeted | 1.916 | 0,914 | 0,487 | 0,496 | 0,492 | 0,537 | 0,561 | 0,512 | 0,848 | 0,868 |

| Recall @ FPR 1% | tất cả | cur | history | rhythm | rarity | infra_ip | infra_asn | novelty | freeman |
|---|---|---|---|---|---|---|---|---|---|
| Naive | 56,0% | 0,2% | 1,6% | 0,8% | 0,5% | 1,0% | 0,6% | 26,7% | 41,9% |
| VPN | 48,3% | 0,0% | 1,3% | 1,0% | 1,2% | 0,8% | 1,2% | 7,2% | 27,3% |
| Targeted | 33,4% | 0,0% | 0,5% | 0,2% | 1,3% | 1,1% | 1,1% | 0,0% | 15,4% |

Sáu nhóm "không được phép tách" đều có AUC 0,48–0,56 và recall ≤ 1,6%. Bộ huấn luyện (11.739 đăng nhập giả ở train, 4.423 ở val) đạt cùng tiêu chí: các nhóm đó AUC 0,47–0,59, recall ≤ 1,7% (riêng `infra_asn` ở val 5,4–6,2%, còn chấp nhận được). Trước khi sửa lỗi 7 (chèn thay vì thay thế), nhóm `rarity` ở val có AUC 0,91–0,94 và recall 59–64% — đó là lý do kiểm định phải chạy **tách theo giai đoạn** và không thể bỏ qua.

Tín hiệu còn lại của Targeted (recall 33% ở mô hình `tất cả`, đến chủ yếu từ nhóm Freeman 15,4%) là tương tác thật giữa IP mới và khoảng cách thời gian, không phải dấu vân tay — xem mục 5.3.


### 5.3 Giả định và giới hạn thẳng thắn

- **Giả định thời điểm.** Kẻ tấn công đăng nhập *đúng nhịp của nạn nhân* (đúng thời điểm một đăng nhập thật của họ). Giả định này loại nhịp khỏi tín hiệu (bảo thủ với các luật/mô hình dựa nhịp) nhưng tạo ra tương tác "**IP mới × khoảng cách ngắn từ lần thành công trước**": đăng nhập hợp lệ hiếm khi đổi IP trong vài phút (P(IP mới) = 2,3% khi cách < 1 phút, 10,6% khi 10 phút–1 giờ, 74% khi > 30 ngày) còn kẻ tấn công mô phỏng có IP mới gần như 100% ở mọi khoảng cách. Đây là tín hiệu thật, nhưng độ lớn của nó phụ thuộc giả định. Kẻ tấn công đăng nhập ở thời điểm độc lập với nạn nhân sẽ tạo phân phối nhịp khác (dài hơn), không được đo ở đây.
- **Hoà lẫn về hạ tầng** (xem trên): kết quả **không** nói gì về khả năng bắt kẻ tấn công dùng IP/ASN có dấu hiệu bất thường (Tor, datacenter, proxy dùng chung nhiều tài khoản) — phần đó thuộc luật hạ tầng MR9 và mô hình IP tấn công.
- **Targeted là cận trên sức mạnh**: kẻ tấn công biết trọn hồ sơ phiên nhưng không biết IP. Kẻ tấn công bắt chước cả IP (proxy trên máy nạn nhân, đánh cắp phiên) là giới hạn đã biết của mọi hệ thống chấm điểm rủi ro theo thuộc tính đăng nhập.
- Kết quả trên kẻ tấn công mô phỏng dùng để **so sánh các mô hình với nhau**, không phải bảo đảm ngoài đời. Bằng chứng ngoài duy nhất là 38 ca ATO thật của bộ dữ liệu (`ato/future`).
- Hai đăng nhập giả có thể chung ASN/IP nên ảnh hưởng nhẹ lên đặc trưng của nhau (vài nghìn dòng chèn trên 22 triệu sự kiện).

## 6. Tự kiểm chứng khung đánh giá

- **Chỉ số khớp thư viện chuẩn:** ROC-AUC và average precision có trọng số bằng `scikit-learn` đến 1e-12 (có điểm bằng nhau); recall@FPR và FPR@TPR khớp tính vét cạn trên đường cong ROC (`tests/test_rba_metrics.py`, 18 test).
- **Mô hình ngẫu nhiên trên dữ liệu thật** cho đúng kết quả lý thuyết — bằng chứng khung không tự tạo ra hiệu năng:

| Bài (điểm ngẫu nhiên) | ROC-AUC | PR-AUC | Tỉ lệ tấn công (trọng số dân số) |
|---|---|---|---|
| `attack_ip/val` | 0,493 [0,478–0,507] | 0,081 | 8,4% |
| `attack_ip/test` | 0,496 [0,490–0,503] | 0,077 | 7,9% |
| `attack_ip/late` | 0,499 [0,492–0,506] | 0,109 | 10,9% |
| `ato/future` | 0,471 [0,384–0,566] | 0,000 | (rất hiếm) |
| `attacker/naive`, `/vpn`, `/targeted` | 0,490 / 0,501 / 0,508 | 0,001 | (rất hiếm) |

PR-AUC của mô hình ngẫu nhiên trùng tỉ lệ tấn công có trọng số ở từng giai đoạn (`late` cao hơn: trôi phân phối thật), xác nhận cột `pop_weight` phục hồi đúng tỉ lệ. Recall tại FPR 1% = 0,8–1,5%, xác thực lại tại TPR 90% ≈ 89–91% và tại TPR 99% ≈ 96–99%, đúng như lý thuyết cho điểm không mang thông tin (số liệu sinh lại bằng `pop_weight`, MR6).
