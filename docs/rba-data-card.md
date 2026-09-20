# Data card — bộ dữ liệu RBA

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
| Số dòng | **31.269.264** (README ghi ">33 triệu" — sẽ đối chiếu với cột `index` ở MR2 để chắc không mất dòng khi đọc) |
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
- Một User ID có ~14 triệu sự kiện — không phải một người dùng thật; loại/tách riêng ở MR2.
- Lệch số dòng giữa README (>33M) và số đếm được (31,27M) — đối chiếu ở MR2.

## 6. Quy tắc sử dụng trong dự án

1. Không tuyên bố "dữ liệu thật"; luôn dùng cách nói ở mục 2.
2. Không dùng địa lý, giờ trong ngày, RTT, region/city từ RBA. Phần địa lý-thời gian (impossible travel, giờ, khoảng cách) huấn luyện và đánh giá trên **simulator của dự án** (`backend/ml/generate_dataset.py`).
3. Nhãn `Is Attack IP` chia train/test **theo IP** (không cho cùng một IP tấn công xuất hiện ở cả hai phía) để mô hình không học thuộc blocklist.
4. ATO chỉ có 141 mẫu: dùng để **đánh giá**, kèm khoảng tin cậy bootstrap; không huấn luyện mô hình ATO riêng.
5. `Is Attack IP` không được làm đặc trưng đầu vào của ML; danh sách IP tấn công chỉ xuất hiện ở lớp rule (blocklist), mô phỏng theo thời gian.
6. Kết quả trên RBA không suy ra được cho hệ thống khác — ghi rõ trong báo cáo.

## 7. Cách đọc dữ liệu

- Đặt file `rba-dataset.zip` ở một trong: biến môi trường `RBA_ZIP_PATH`, `backend/ml/data/rba/`, hoặc thư mục Downloads.
- **Không giải nén** (9GB): mã đọc thẳng từ zip theo chunk.
- Kiểm tra môi trường: `cd backend && venv\Scripts\python.exe -m ml.check_env`.
- Dữ liệu mẫu/Parquet sinh ra nằm trong `backend/ml/data/rba/` (đã ignore, không commit).
