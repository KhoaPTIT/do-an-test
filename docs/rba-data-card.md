# Data card — bộ dữ liệu RBA

> ⚠️ **Lỗi thời từ Phase 4.1 (tài liệu lịch sử, giữ để tra cứu).** Bộ RBA chỉ còn dùng cho nghiên cứu offline (`ml/rba/`); từ Phase 4.1 không model nào train trên RBA chạy trong `/login`. Model AI đang chạy: Isolation Forest trên dataset tổng hợp tái lập được — [`ml-anomaly-model.md`](ml-anomaly-model.md).

**Login Data Set for Risk-Based Authentication** — dùng cho giai đoạn mở rộng AI (MR1–MR19, xem [`checklist.md`](checklist.md)).

## 1. Nguồn, giấy phép, trích dẫn

- Kaggle: `dasgroup/rba-dataset`.
- Giấy phép **CC BY 4.0** — bắt buộc trích dẫn bài báo gốc trong mọi báo cáo/slide dùng bộ dữ liệu này:

  > Stephan Wiefling, Paul René Jørgensen, Sigurd Thunem, Luigi Lo Iacono.
  > *Pump Up Password Security! Evaluating and Enhancing Risk-Based Authentication on a Real-World Large-Scale Online Service.*
  > ACM Transactions on Privacy and Security (2022). doi:10.1145/3546069

- Mô hình baseline mà bộ dữ liệu được thiết kế để tái lập: Freeman et al., *Who Are You? A Statistical Approach to Measuring User Authenticity*, NDSS 2016 (doi:10.14722/ndss.2016.23240).

## 2. Bản chất: dữ liệu TỔNG HỢP, không phải log thật

Theo README của bộ dữ liệu:

- Được **tổng hợp** từ hành vi đăng nhập thật của hơn 3,3 triệu người dùng một dịch vụ SSO lớn ở Na Uy (02/2020 – 02/2021).
- Giá trị các trường "hợp lý nhưng **hoàn toàn nhân tạo**"; README khuyến cáo **không dùng cho hệ thống phát hiện xâm nhập thực tế**.
- Phân phối thống kê của các đặc trưng dạng phân loại được giữ giống dữ liệu gốc (toàn cục và theo từng user). Các giá trị còn lại sinh ngẫu nhiên nhưng giữ quan hệ logic và thứ tự thời gian.
- Cụ thể: quốc gia được gán ngẫu nhiên theo từng giá trị duy nhất; ASN và IP sinh theo quốc gia; thành phố/vùng suy ra từ IP sinh ra nên **không phản ánh quan hệ thật**; chuỗi User-Agent sinh từ dữ liệu công khai; RTT gán ngẫu nhiên theo địa lý; timestamp có thành phần ngẫu nhiên; loại thiết bị giữ nguyên như dữ liệu gốc.
- README xác nhận bộ này tái lập được kết quả nghiên cứu cho mô hình RBA dùng: IP, country, ASN, User-Agent, OS, browser, device type.

> **Cách nói đúng khi báo cáo/bảo vệ:** "benchmark học thuật công khai (CC BY 4.0), tổng hợp từ thống kê của một dịch vụ SSO thật". **Không** được nói "huấn luyện trên dữ liệu thật" hay "log tấn công thật".

## 3. Thống kê đã xác minh

Quét toàn bộ file `rba-dataset.csv` (8,43 GiB giải nén, đọc theo chunk từ zip) ngày 20/09/2026:

| Chỉ số | Giá trị |
|---|---|
| Số dòng | **31.269.264** (README ghi ">33 triệu"; `index` liên tục nên không mất dòng khi đọc — xem phát hiện MR2 bên dưới) |
| Số user (User ID khác nhau) | 4.304.857 |
| Khoảng thời gian | 2020-02-03 12:43 → 2021-02-28 23:59 |
| Đăng nhập thành công | 12.541.442 (40,1%) — phần lớn thất bại là lưu lượng tấn công |
| `Is Attack IP` = true | 3.096.977 dòng (9,9%) nhưng chỉ **82.975 IP khác nhau** |
| `Is Account Takeover` = true | **141 dòng / 138 user** (0,00045%) |
| ATO: đăng nhập thành công | 140 / 141 |
| ATO: đến từ IP thuộc danh sách tấn công | 77 / 141 → **64 ca (45%) không bị blocklist bắt** |
| Số lần đăng nhập / user | trung vị 2; p90 = 9; p99 = 28 |
| User chỉ có đúng 1 lần đăng nhập | 1.707.596 (39,7%) |
| User có ≥ 10 lần đăng nhập | 367.923 (8,5%) |
| Loại thiết bị | mobile 19,64M · desktop 7,93M · bot 2,03M · unknown 0,87M · tablet 0,80M · rỗng 1.526 |
| Quốc gia | 229 giá trị; NO 42,3%, US 27,8%, RU 5,4%, BR 3,8%, DE 2,9% |

Các ca ATO xuất hiện theo cụm (ví dụ 6 ca từ Romania trong ~30 phút ngày 10/02/2020, cùng vài ASN) — cơ sở dữ liệu cho tính năng gom chiến dịch (MR14).

### Phát hiện khi khảo sát toàn bộ Parquet (MR2)

- **File nhất quán:** đúng 31.269.264 dòng, `index` liên tục 0…31.269.263, không lần nào thời gian đi lùi (file đã sắp theo thời gian). README ghi ">33 triệu" — chênh lệch không do mất dòng khi đọc; nguyên nhân chưa rõ.
- **45% dữ liệu là một "user" không có thật:** `-4324475583306591935` có 14.025.899 sự kiện, **0% thành công**, 2,05 triệu IP và 11.694 ASN khác nhau, 227 quốc gia → là "thùng chứa" các lần thử vào **tài khoản không tồn tại** (trong hệ thống của dự án tương ứng `user_id = NULL`). Chỉ 11,8% dòng của nó bị gắn `Is Attack IP`.
- **Một client tự động thử lại liên tục:** `6998943612473066845` có 70.028 sự kiện, 0% thành công, chỉ 4 IP, 1 quốc gia, 1 thiết bị.
- **Nhãn `Is Attack IP` nhất quán tuyệt đối theo IP:** 82.975 IP tấn công, không IP nào có nhãn lẫn → chia theo nhóm IP là hợp lệ.
- **ATO chỉ có ở 02/2020–11/2020** (22, 11, 11, 15, 17, 10, 17, 16, 14, 8 ca theo tháng), không có ca nào từ 12/2020.
- **Trôi phân phối từ 11/2020:** lưu lượng tăng ~40% (2,3 → 3,1 triệu/tháng) và tỉ lệ thành công toàn cục tụt từ ~0,44 xuống ~0,30. Tách riêng giai đoạn này làm tập kiểm tra chịu trôi phân phối.
- **Bỏ thùng chứa ra, lưu lượng của user thật thành công ~78%** (so với 40% toàn bộ).
- **Loại thiết bị và tấn công:** `bot` có tỉ lệ thành công 0% nhưng chỉ 1,3% thuộc IP tấn công (không phải dấu hiệu của danh sách tấn công); `mobile` có 14,1% thuộc IP tấn công (cao nhất), `desktop` 2,9%, `tablet` 2,8%.
- Phân tầng user (không kể 2 user trên): 1 lần = 1.707.596 user; 2–9 lần = 2.229.338 user (8,36 triệu sự kiện); ≥10 lần = 367.922 user (7,18 triệu sự kiện).

## 4. Cột nào dùng được làm đặc trưng

| Cột | Dùng? | Ghi chú |
|---|---|---|
| `User ID` | Khoá nhóm | Bút danh, không phải định danh thật |
| `Login Timestamp` | **Thứ tự và cửa sổ thời gian thô** | README: có thành phần ngẫu nhiên → **không dùng** giờ-trong-ngày, chu kỳ ngày/tuần |
| `IP Address` | Có (mới lạ/tần suất) | IP dạng `10.x.x.x` là giá trị nhân tạo, không tra GeoIP |
| `Country` | Có, dạng phân loại | **Không dùng khoảng cách địa lý giữa các nước** (quốc gia bị gán ngẫu nhiên) |
| `Region`, `City` | **Không** | Suy từ IP sinh ra, không phản ánh quan hệ thật |
| `ASN` | Có | ASN ≥ 500000 là giá trị nhân tạo |
| `User Agent String`, `Browser…`, `OS…`, `Device Type` | Có | 1.526 UA lỗi không parse được |
| `Round-Trip Time` | **Không** | Gán ngẫu nhiên giữa các user theo địa lý, không phải RTT thật của user |
| `Login Successful` | Có | Lịch sử thành công/thất bại |
| `Is Attack IP` | **Nhãn**, không phải đặc trưng | Suy ra từ việc IP nằm trong danh sách tấn công → đưa vào làm đặc trưng là rò rỉ nhãn |
| `Is Account Takeover` | **Nhãn đánh giá** | Chỉ 141 mẫu |

## 5. Artifact đã biết

- 7.291.335 dòng (23,3%) có IP dạng `10.0.0.0/8` — giá trị nhân tạo do xung đột lúc sinh dữ liệu (README).
- 1.457.824 dòng (4,66%) có ASN ≥ 500000 — nhân tạo (README).
- Hai User ID khổng lồ (14 triệu và 70 nghìn sự kiện, đều 0% thành công) không phải người dùng thật — loại khỏi mẫu user nhưng vẫn ở trong Parquet đầy đủ để tính đặc trưng cấp IP/ASN (xem mục 3).
- Lệch số dòng giữa README (>33M) và số đếm được (31,27M): đã đối chiếu, `index` liên tục, không mất dòng khi đọc.

## 6. Quy tắc sử dụng trong dự án

1. Không tuyên bố "dữ liệu thật"; luôn dùng cách nói ở mục 2.
2. Không dùng địa lý, giờ trong ngày, RTT, region/city từ RBA. Phần địa lý-thời gian (impossible travel, giờ, khoảng cách) huấn luyện và đánh giá trên **simulator của dự án** (`backend/ml/generate_dataset.py`).
3. Nhãn `Is Attack IP` chia train/val/test **theo nhóm IP** (không cho cùng một IP tấn công xuất hiện ở cả tập huấn luyện và tập đánh giá) để mô hình không học thuộc blocklist — chi tiết ở mục 8.
4. ATO chỉ có 141 mẫu: dùng để **đánh giá**, kèm khoảng tin cậy bootstrap; không bao giờ vào tập huấn luyện. Chỉ 38 ca nằm ở giai đoạn "tương lai" (09–11/2020) so với train/val; con số công bố chính phải dùng 38 ca này, số trên cả 141 ca là "nhìn lại" và lạc quan hơn.
5. `Is Attack IP` không được làm đặc trưng đầu vào của ML; danh sách IP tấn công chỉ xuất hiện ở lớp rule (blocklist), mô phỏng theo thời gian.
6. Kết quả trên RBA không suy ra được cho hệ thống khác — ghi rõ trong báo cáo.

## 7. Cách đọc dữ liệu

- Đặt file `rba-dataset.zip` ở một trong: biến môi trường `RBA_ZIP_PATH`, `backend/ml/data/rba/`, hoặc thư mục Downloads.
- **Không giải nén** (9GB): mã đọc thẳng từ zip theo chunk.
- Kiểm tra môi trường: `cd backend && venv\Scripts\python.exe -m ml.check_env`.
- Dữ liệu mẫu/Parquet sinh ra nằm trong `backend/ml/data/rba/` (đã ignore, không commit).

## 8. Pipeline dữ liệu (MR2)

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.etl      # zip -> ml/data/rba/rba_full.parquet (~5 phút, 0,78 GiB)
venv\Scripts\python.exe -m ml.rba.sample   # -> rba_sample.parquet (~30 giây) + sample_report.json
```

**Mẫu:** lấy theo user, giữ nguyên toàn bộ lịch sử của user được chọn (đặc trưng theo user cần lịch sử đầy đủ). Tỉ lệ theo tầng: 1 lần = 5%, 2–9 lần = 10%, ≥10 lần = 25%, cộng **100% user có ATO** (138 user). Loại 2 user khổng lồ. Kết quả: **2.707.021 dòng, 401.092 user**. Cột `ua` thay bằng `ua_hash` (chỉ cần biết cùng/khác chuỗi UA).

**Chia dữ liệu (hai trục độc lập):**

1. Theo thời gian: `train` 03/02–31/07/2020 · `val` 08/2020 · `test` 09–11/2020 · `late` 12/2020–02/2021.
2. Theo nhóm IP tấn công: mỗi IP tấn công thuộc đúng một nhóm 70% / 15% / 15% (băm MD5 ổn định). Dòng tấn công chỉ được giữ khi nhóm IP khớp giai đoạn (`late` dùng nhóm của `test`); dòng còn lại vào `excluded`. Dòng ATO có phân vùng riêng `ato`.

| Phân vùng | Dòng | User | Dòng tấn công | IP tấn công | Tỉ lệ tấn công (có trọng số) | Thành công |
|---|---|---|---|---|---|---|
| train | 1.241.440 | 257.223 | 52.288 | 5.057 | 5,9% | 78,1% |
| val | 199.114 | 84.812 | 1.996 | 393 | 6,3% | 78,7% |
| test | 610.050 | 172.253 | 5.709 | 644 | 5,9% | 78,8% |
| late | 544.002 | 166.425 | 7.137 | 585 | **8,1%** | 76,6% |
| excluded | 112.274 | 46.500 | 112.274 | 7.957 | — | 59,6% |
| ato | 141 | 138 | 77 | 57 | — | 99,3% |

- **Cột `weight`:** vì val/test chỉ giữ 15% IP tấn công, tỉ lệ tấn công thô ở đó (≈1%) thấp hơn tự nhiên chỉ do cách chia. Trọng số `1/(tỉ lệ nhóm IP)` cho dòng tấn công phục hồi tỉ lệ tự nhiên (≈5,9% ở cả train/val/test, khớp nhau). Mọi chỉ số phụ thuộc tỉ lệ (precision, PR-AUC, số cảnh báo/ngày) phải tính **có trọng số**; recall tại FPR cố định không phụ thuộc.
- **ATO theo giai đoạn:** train 86 · val 17 · **test 38** · late 0.
- **Trôi phân phối thật:** tỉ lệ tấn công (có trọng số) của `late` là 8,1% so với ~5,9% trước đó.
- Bất biến được kiểm tra tự động mỗi lần lấy mẫu (`verify_and_summarize`) và bằng test trên file thật (`tests/test_rba_real_data.py`): mẫu = toàn bộ lịch sử của user được chọn; không IP tấn công nào trùng giữa train và val/test/late; thứ tự thời gian train < val < test < late; ATO không vào tập thường; user khổng lồ bị loại.
