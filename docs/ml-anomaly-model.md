# Mô hình bất thường chạy thật (Phase 4.1)

> Tài liệu được hoàn thiện dần theo các milestone ML0–ML7. Mục 1 ghi quyết định kiến trúc (ML0), ghi TRƯỚC khi sửa mã.

## 1. Quyết định kiến trúc (ML0)

**Một model runtime duy nhất: Isolation Forest (không giám sát)** trên 7 đặc trưng hành vi của chính tài khoản.

| Tiêu chí | Isolation Forest trên dataset tự sinh (chọn) | `hybrid_cp2` / RBA (bỏ khỏi runtime) |
|---|---|---|
| Chạy được trên repo hiện tại | có — dataset sinh tất định từ mã trong repo | không — cần `rba-dataset.zip` 9GB (Kaggle), không có trong repo |
| Train lại | vài giây | ~1 giờ cho cả chuỗi ETL → mô phỏng → train → chọn |
| Artifact | nhỏ (một file joblib + metadata) | nhiều model LightGBM/IF + hồ sơ hiệu chỉnh |
| Inference | một vector 7 số | 50 đặc trưng, thống kê toàn cục quét cả bảng |
| Lệch train/serve | sửa được triệt để (đặc tả đặc trưng dùng chung) | lệch chuẩn hoá browser/os và quần thể thống kê toàn cục (audit Phase 4.0) |
| So sánh với 20 luật | chạy thẳng trong harness Phase 3 | RBA ngẫu nhiên hoá địa lý/giờ: phần lớn luật không đánh giá được |
| Giải thích khi bảo vệ | "mức lạ so với lịch sử đăng nhập của chính tài khoản" | hợp nhiều thành phần, khó trình bày |

Hệ quả:
- Nhánh ML tầng 3 cũ (`app/detection/ml_model.py`, alert `ml_anomaly` tạo riêng ngoài risk engine) và thành phần ML
  `hybrid_cp2` trong `hybrid_runtime` bị **gỡ khỏi luồng /login**; mã nghiên cứu RBA (`ml/rba/`) giữ nguyên làm tài liệu
  offline. Risk engine (noisy-OR + ngưỡng hành động + quy kết) giữ nguyên; tín hiệu ML mới đi vào CHÍNH risk engine đó.
- **Dataset (đã hỏi và được người dùng chọn):** bộ sinh dữ liệu tầng 3 cũ mô tả "bình thường" quá thưa so với lưu lượng
  bình thường v3 mà 20 luật được đo (trung vị 1.512 so với 91 phút giữa hai lần đăng nhập; 0,55 so với 17,6 lần/24 giờ) —
  model học trên đó sẽ coi gần hết đăng nhập bình thường là bất thường. Dataset mới: hành vi bình thường sinh bằng chính
  bộ sinh lưu lượng bình thường v3 (`verification/normal_traffic.py`) với **seed khác hẳn seed của harness**, cộng bất
  thường được chèn theo danh mục kiểu bất thường của tầng 3. Dataset là **tổng hợp**.
- **Phạm vi chấm:** chỉ lần đăng nhập THÀNH CÔNG của tài khoản có hồ sơ trưởng thành (≥ 10 lần thành công, ≥ 7 ngày — cùng
  định nghĩa với các luật hồ sơ hành vi). Lần thất bại và tài khoản mới để 20 detector luật xử lý.
- **An toàn:** ML chỉ là tín hiệu bổ sung cho risk engine; ML không bao giờ tự khoá tài khoản.

## 2. Đặc trưng (ML1)

Đặc tả duy nhất: [`backend/ml/features.py`](../backend/ml/features.py) — `compute_features(prior, current)` là hàm thuần dùng
chung cho offline (`extract_offline`) và runtime (`app/detection/ml_runtime.py::runtime_features`).

| Đặc trưng | Ý nghĩa | Thiếu dữ liệu |
|---|---|---|
| `hour_deviation` | khoảng cách vòng tròn (giờ, 0–12) tới giờ trung bình vòng tròn của các lần thành công trước | — |
| `is_new_location` | (quốc gia, thành phố) chưa từng đăng nhập thành công | thiếu GeoIP → 0 |
| `is_new_device` | họ thiết bị chuẩn hoá (loại \| HĐH \| trình duyệt, bỏ phiên bản) chưa từng thấy — cùng hàm với luật `unusual_device` | không có UA → 0 |
| `log_minutes_since_last_success` | log(1 + phút) kể từ lần thành công gần nhất | — |
| `logins_last_24h` | số lần thành công trong 24 giờ trước đó | — |
| `log_distance_km_from_home` | log(1 + km) tới vị trí lần thành công đầu tiên có toạ độ | thiếu toạ độ → 0 |
| `log_travel_speed_kmh` | log(1 + km/h) từ vị trí lần thành công gần nhất có toạ độ | thiếu toạ độ → 0 |

Không đặc trưng nào là nhãn, loại tấn công hay kết quả của luật.

Lỗi lệch train/serve đã sửa (audit Phase 4.0) và test chứng minh:

| Lỗi | Sửa | Test |
|---|---|---|
| sự kiện hiện tại đã flush bị lấy làm "lần thành công trước" → `minutes_since_last_login` luôn 0 | lịch sử chỉ gồm lần thành công TRƯỚC HẲN, loại trừ id sự kiện hiện tại | `test_regression_previous_login_is_not_the_current_event` |
| train chỉ lần thành công nhưng runtime chấm cả lần thất bại | runtime chỉ chấm lần thành công của hồ sơ trưởng thành | `test_failed_logins_and_unknown_accounts_are_out_of_scope` |
| thiết bị = băm toàn bộ User-Agent (Chrome 120 ≠ Chrome 121) | họ thiết bị chuẩn hoá dùng chung với luật hành vi | `test_browser_version_update_is_the_same_device_but_another_browser_is_new` |
| giờ trung bình cộng (sai quanh nửa đêm) | trung bình vòng tròn | `test_hour_deviation_is_circular` |
| hai bản cài đặt đặc trưng offline/runtime khác nhau | một hàm duy nhất + test parity bắt buộc | `tests/test_ml_feature_parity.py` |
