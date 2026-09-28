# Mô hình B (địa lý-thời gian) — dữ liệu từ thư viện tấn công mô phỏng v2 (MR18)

`docs/checklist.md` MR6 ghi: "Mô hình B (địa lý-thời gian) chuyển sang MR18: cần thư viện kịch bản tấn công của MR18
và simulator hiện tại (`ml/generate_dataset.py`) dựa trên DB". "Mô hình B" **không phải một mô hình xây MỚI** — chính
là tầng 3 đã có từ Tuần 7 (Isolation Forest/LOF/Autoencoder, [`docs/ml-evaluation.md`](ml-evaluation.md)), đặc trưng
[`ml/features.py`](../backend/ml/features.py) (giờ trong ngày, khoảng cách tới "nhà", thiết bị/vị trí mới) — ĐÚNG phần
"địa lý-thời gian" mà RBA không có (`docs/rba-features.md` mục 5: "Đặc trưng địa lý và giờ trong ngày không có ở đây
vì RBA không hỗ trợ... chúng thuộc mô hình B trên simulator"). MR18 bổ sung DỮ LIỆU (2 kiểu bất thường mới, tinh vi
hơn 5 kiểu gốc) và huấn luyện/đánh giá LẠI, không đổi kiến trúc mô hình.

## Chỉ 2/9 kịch bản MR18 dịch được sang khuôn dữ liệu tầng 3 — vì sao

`ml/features.py` có 9 đặc trưng: `hour_sin/cos`, `day_of_week`, `hour_deviation_from_avg`, `is_new_location`,
`is_new_device`, `minutes_since_last_login`, `logins_last_24h`, `distance_km_from_home` — **không có đặc trưng nào về
IP/ASN cụ thể, số lượng IP/tài khoản khác nhau, hay tốc độ thử sai**. 7/9 kịch bản của
[`ml/attack_scenarios.py`](../backend/ml/attack_scenarios.py) (rải mật khẩu chậm, botnet phân tán, proxy cùng quốc
gia, xoay User-Agent, mô phỏng tinh vi, dò danh sách tài khoản, nhồi thông tin quy mô lớn) đo ĐÚNG những tín hiệu tầng
3 KHÔNG THẤY ĐƯỢC — dịch chúng thành nhãn tầng 3 sẽ chỉ tạo ra các dòng "trông giống bình thường" về mặt đặc trưng dù
nhãn là "bất thường", không dạy được gì cho mô hình (và có thể làm HỎNG việc huấn luyện bằng nhiễu nhãn). Đây là một
GIỚI HẠN PHẠM VI thật của tầng 3, không phải sơ suất — đã ghi từ Tuần 7 (`model-card-rba.md` mục 3: "phát hiện tấn
công dựa trên địa lý/giờ trong ngày... phần đó thuộc mô hình B").

Chỉ 2 kịch bản có tín hiệu ĐÚNG phạm vi geo/time của tầng 3:
- **`dormant_reactivation`** — khoảng cách thời gian CỰC LỚN kể từ lần đăng nhập trước (`minutes_since_last_login`)
  cộng vị trí mới — kiểu bất thường HOÀN TOÀN MỚI so với 5 kiểu gốc (không kiểu nào của Tuần 7 dựng riêng tín hiệu
  "im lặng lâu ngày").
- **`impossible_travel_geo`** — TỔ HỢP thời gian cực ngắn VÀ khoảng cách cực xa CÙNG LÚC kể từ lần trước — khác
  `unusual_location` gốc (không ràng buộc thời gian, có thể xảy ra sau nhiều ngày).

Đã thêm vào [`ml/generate_dataset.py`](../backend/ml/generate_dataset.py) (`_make_dormant_reactivation_anomaly`,
`_make_impossible_travel_geo_anomaly`), chạy lại toàn bộ pipeline (`generate_dataset --reset` → `extract_features` →
`train` → `evaluate`).

## Kết quả — recall theo kiểu bất thường (Isolation Forest, tốt nhất trong 3 mô hình, tập test)

| Kiểu bất thường | Số ca (test) | Recall |
|---|---|---|
| `dormant_reactivation` (MỚI) | 13 | **100%** |
| `impossible_travel_geo` (MỚI) | 19 | **63,2%** |
| `unusual_hour+unusual_location` | 8 | 100% |
| `unusual_device+unusual_hour` | 5 | 100% |
| `unusual_device+unusual_location` | 11 | 90,9% |
| `unusual_location` | 18 | 88,9% |
| `unusual_hour` | 17 | 58,8% |
| `unusual_device` | 23 | 39,1% |
| `rapid_fire` | 20 | 0% |

**2 kiểu MỚI hoạt động tốt** — `dormant_reactivation` bắt được TOÀN BỘ, `impossible_travel_geo` ngang `unusual_hour`.
Hợp lý: cả hai đều có tín hiệu THỜI GIAN cực đoan (khoảng cách giờ/phút rất lớn hoặc rất nhỏ so với phân phối thường
thấy), loại tín hiệu Isolation Forest vốn đã mạnh nhất (`docs/ml-evaluation.md`: yếu nhất ở `rapid_fire`/`unusual_device`
đơn lẻ, mạnh nhất ở tín hiệu đơn giản/cực đoan).

## ⚠️ Giới hạn quan trọng: không so sánh "trước/sau" được chính xác

`ml/generate_dataset.py` **không cố định random seed** — mỗi lần chạy `--reset` sinh lại dữ liệu NGẪU NHIÊN khác
(hồ sơ user, giờ/vị trí cụ thể của từng lần bất thường...). Số liệu MỚI đo được cho 5 kiểu GỐC trong lần chạy CÙNG với
2 kiểu MR18 (**56,9% recall gộp**, tính riêng — xem bên dưới) THẤP HƠN số đã công bố ở Tuần 7 (`ml-evaluation.md`:
78,3% recall tổng, `unusual_hour`/`unusual_location` 100%) — nhưng đây RẤT CÓ THỂ là dao động ngẫu nhiên giữa hai lần
chạy độc lập (mẫu mỗi kiểu chỉ 13-62 ca), KHÔNG PHẢI bằng chứng "thêm 2 kiểu mới làm hỏng mô hình". Tách riêng để kiểm
tra trực tiếp trên CHÍNH lần chạy này:

- Recall trên 5 kiểu GỐC (không tính 2 kiểu MR18): **56,9%** (58/102 ca)
- Recall trên 2 kiểu MR18: **78,1%** (25/32 ca)

2 kiểu MỚI không hề kéo tụt kết quả — NGƯỢC LẠI, cao hơn 5 kiểu gốc TRONG CHÍNH lần chạy này. Kết luận công bằng nhất:
**không đủ căn cứ để so sánh chính xác trước/sau** khi thiếu seed cố định; muốn so sánh đúng cần cố định seed (chưa
làm — ngoài phạm vi MR18, để lại cho lần sau) rồi chạy lại CẢ hai cấu hình (có/không 2 kiểu mới) trên CÙNG một seed.

## Giới hạn khác

- Mẫu nhỏ (13-19 ca/kiểu mới) — đủ để thấy xu hướng, không đủ cho khoảng tin cậy chặt.
- `dormant_reactivation` dùng khoảng cách 35 ngày (không phải 90 ngày như `dormant_account_login` của rule engine,
  MR9) — tầng 3 không có ngưỡng cứng, chỉ cần lệch rõ so với phân phối khoảng cách thường thấy (~2-3 ngày/lần trên
  90 ngày, 30-55 lần/user) để mô hình học được; không nhằm khớp số của một luật ở tầng khác.
- 7/9 kịch bản KHÔNG dịch được sang tầng 3 (xem trên) — muốn tầng 3 "thấy" được kiểu tấn công đó cần THÊM đặc trưng
  mới (IP/ASN, tốc độ) vào `ml/features.py`, về bản chất là làm lại một phần việc RBA (`ml/rba/features.py`) đã làm
  cho tầng khác — không phải việc của MR18.
- Chưa vẽ lại ma trận nhầm lẫn/ROC cho RIÊNG 2 kiểu mới (biểu đồ `ml.evaluate` hiện vẫn gộp toàn bộ tập test).
