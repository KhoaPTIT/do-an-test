# Đánh giá ML tầng 3 (nhiệm vụ 7.1) — điểm nhấn chính của đồ án

> ⚠️ **Lỗi thời từ Phase 4.1 (tài liệu lịch sử, giữ để tra cứu).** Bộ dữ liệu và mã tầng 3 cũ (`ml/generate_dataset.py`, `ml/extract_features.py`, `app/detection/ml_model.py`, cảnh báo `ml_anomaly` riêng) đã GỠ ở Phase 4.1; số liệu dưới đây KHÔNG tái lập được trên mã hiện tại. Model AI đang chạy: Isolation Forest trên dataset tổng hợp tái lập được — [`ml-anomaly-model.md`](ml-anomaly-model.md).

> ⚠️ **MR18** đã thêm 2 kiểu bất thường mới (`dormant_reactivation`, `impossible_travel_geo` — "mô hình B" địa lý-thời
> gian, xem [`docs/model-b-geo-time.md`](model-b-geo-time.md)) vào `ml/generate_dataset.py` rồi huấn luyện/đánh giá
> LẠI — các con số CỤ THỂ dưới đây (78,3% recall, bảng theo kiểu bất thường mục dưới...) là ảnh chụp của Tuần 7, KHÔNG
> còn khớp với `backend/ml/artifacts/` hiện tại (dữ liệu sinh lại KHÔNG cố định seed nên cũng không tái lập chính xác
> được — xem giới hạn ở tài liệu MR18). Giữ nguyên ở đây làm tài liệu lịch sử; hợp nhất đầy đủ dự kiến ở MR19.
>
> Không đổi: phương pháp luận (train/test tách theo thời gian, 3 mô hình, so với tầng 2 thật) và các đặc trưng gốc.

## Vì sao làm sâu phần này

Ban đầu checklist coi ML là "tuỳ chọn, không bắt buộc thành công". Nhóm quyết
định đầu tư sâu hơn để ML thực sự là điểm khác biệt của đồ án — nhưng **trung
thực với giới hạn của dữ liệu tự sinh** là nguyên tắc xuyên suốt: mọi con số
dưới đây đo trên dữ liệu do chính nhóm tạo ra (`backend/ml/generate_dataset.py`),
không phải dữ liệu tấn công thật. Đây là **proof-of-concept có phương pháp
luận chuẩn** (train/test tách theo thời gian, không rò rỉ dữ liệu tương lai,
so sánh trên hàm sản xuất thật), không phải bằng chứng "AI phát hiện được
tấn công thật ngoài đời" — nếu hội đồng hỏi, đây là câu trả lời đúng mực.

## 1. Dữ liệu

- **40 user** (`user101`-`user140`), tách biệt hoàn toàn khỏi 30 user dùng
  cho demo dashboard (Tuần 2-3) để không xáo trộn số liệu đã ghi ở các tuần
  trước.
- **1846 lần đăng nhập thành công**, trải trong 90 ngày.
- **5 kiểu bất thường** (nhiều hơn hẳn bản Tuần 3 chỉ có 2 kiểu):

  | Kiểu | Mô tả | Số lượng (toàn tập) |
  |---|---|---|
  | `unusual_hour` | Giờ đăng nhập đối lập hoàn toàn thói quen | ~80 |
  | `unusual_location` | Vị trí cách xa nơi ở quen thuộc | ~77 |
  | `unusual_device` | Thiết bị (User-Agent) chưa từng thấy | ~80 |
  | `rapid_fire` | Nhiều lần đăng nhập dồn dập bất thường (vài chục giây/lần) | ~41 |
  | kết hợp (VD `unusual_device+unusual_hour`) | 2 tín hiệu cùng lúc — ca khó nhất | ~61 |

- Tỷ lệ **84.8% bình thường / 15.2% bất thường** — trong khoảng 80-90% khuyến
  nghị (mục 11 checklist gốc).
- Mỗi user có 1-2 "thiết bị quen thuộc" (User-Agent thật của trình duyệt/di
  động phổ biến) thay vì 1 chuỗi cố định như bản Tuần 2-3 — cần thiết để đặc
  trưng "thiết bị lạ" có ý nghĩa.

## 2. Đặc trưng (feature engineering)

9 đặc trưng, tính từ [`backend/ml/features.py`](../backend/ml/features.py) —
**chống rò rỉ dữ liệu tương lai** bằng cách xử lý tuần tự theo thời gian,
chỉ dùng lịch sử TRƯỚC thời điểm đăng nhập hiện tại (kiểm tra bằng unit test
`test_ml_features.py`):

| Đặc trưng | Ý nghĩa |
|---|---|
| `hour_sin`, `hour_cos` | Giờ đăng nhập (mã hoá vòng tròn — 23h và 1h gần nhau) |
| `day_of_week` | Thứ trong tuần |
| `hour_deviation_from_avg` | Lệch bao nhiêu giờ so với giờ trung bình của user (khoảng cách vòng tròn) |
| `is_new_location` | Vị trí chưa từng thấy |
| `is_new_device` | Thiết bị chưa từng thấy |
| `minutes_since_last_login` | Bao lâu kể từ lần đăng nhập trước |
| `logins_last_24h` | Số lần đăng nhập trong 24h qua (bắt `rapid_fire`) |
| `distance_km_from_home` | Khoảng cách tới vị trí quen thuộc nhất |

Phần lớn đặc trưng **tái sử dụng tín hiệu đã có ở tầng 2**
([`app/detection/baseline.py`](../backend/app/detection/baseline.py),
[`app/detection/rules.py`](../backend/app/detection/rules.py)) — khác biệt
cốt lõi không phải là "ML thấy nhiều thứ hơn" mà là **tầng 2 gán trọng số
THỦ CÔNG cố định** (mục 4.2: lệch giờ +20, vị trí lạ +30...), còn **tầng 3
để mô hình TỰ HỌC cách kết hợp** (kể cả quan hệ phi tuyến) từ dữ liệu.

## 3. Phương pháp đánh giá

- **Train/test split theo THỜI GIAN, riêng từng user** (70% đầu → train, 30%
  cuối → test) — **không** xáo trộn ngẫu nhiên như `train_test_split()` mặc
  định, vì sẽ làm lẫn thông tin tương lai vào tập train.
- **3 mô hình ML** (scikit-learn, không cần TensorFlow/PyTorch):
  - **Isolation Forest** — học trên toàn bộ tập train (kể cả lẫn ít bất
    thường, đúng bản chất unsupervised).
  - **Local Outlier Factor** (novelty detection) — chỉ học trên phần được
    xác nhận bình thường của tập train.
  - **Autoencoder** (mạng MLP thắt cổ chai 9→6→3→6→9) — chỉ học tái tạo dữ
    liệu bình thường, đo lỗi tái tạo (MSE) làm điểm bất thường.
- **So sánh với tầng 2 THẬT** — không viết lại song song, gọi thẳng
  `compute_risk_score()` từ `app/detection/scoring.py`, dựng `UserBaseline`
  giả từ đúng ngữ cảnh lịch sử tại thời điểm đó. Đảm bảo so sánh công bằng
  trên cùng 1 hàm đang chạy thật trong hệ thống.

## 4. Kết quả

| Phương pháp | Precision | Recall | F1 | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Tầng 2 (behavioral, ngưỡng 40) | **1.000** | 0.036 | 0.070 | 0.777 | 3 | 0 | 80 | 491 |
| Isolation Forest | 0.722 | 0.783 | **0.751** | **0.882** | 65 | 25 | 18 | 466 |
| Local Outlier Factor | 0.689 | 0.747 | 0.717 | 0.884 | 62 | 28 | 21 | 463 |
| Autoencoder | 0.508 | 0.771 | 0.612 | 0.873 | 64 | 62 | 19 | 429 |

Biểu đồ: [`ml-confusion-matrices.png`](figures/ml-confusion-matrices.png),
[`ml-roc-curves.png`](figures/ml-roc-curves.png),
[`ml-feature-importance.png`](figures/ml-feature-importance.png).

### Phát hiện quan trọng nhất: tầng 2 gần như "im lặng"

Tầng 2 chỉ bắt được **3/83 ca bất thường** trong tập test (recall 3.6%),
dù không báo động giả nào (precision 100%). Soi theo từng kiểu bất thường:

| Kiểu bất thường | Số ca (test) | Recall tầng 2 | Recall Isolation Forest |
|---|---|---|---|
| `unusual_hour` | 20 | **0%** | 100% |
| `unusual_location` | 15 | **0%** | 100% |
| `unusual_device` | 18 | **0%** (không có trọng số cho loại này) | 44% |
| `rapid_fire` | 14 | **0%** (không có trọng số cho loại này) | 43% |
| `unusual_hour+unusual_location` | 4 | 75% | 100% |
| kết hợp có `unusual_device` | 12 | **0%** | 100% |

**Nguyên nhân gốc rễ, không phải lỗi đánh giá:**

1. **Tầng 2 KHÔNG có trọng số cho `unusual_device` và `rapid_fire`** —
   `compute_risk_score()` (mục 4.2 checklist gốc) chỉ tính 4 yếu tố: lệch
   giờ, vị trí lạ, fail liên tiếp, thành công sau chuỗi fail. Hai kiểu bất
   thường mới (thiết bị lạ, tốc độ bất thường) **về mặt thiết kế không thể
   bị tầng 2 bắt được** — đây là lý do chính đáng để có tầng 3.
2. **Baseline giờ bị "pha loãng" theo thời gian** — `avg_login_hour`/
   `stddev_login_hour` được tính lại từ **MỌI** lần đăng nhập thành công
   (xem `update_baseline_after_successful_login()`), **kể cả những lần đã
   là bất thường trước đó**. Khi có nhiều ca `unusual_hour` liên tiếp,
   `stddev_login_hour` bị kéo giãn ra, khiến ngưỡng `2.5 × stddev` ngày
   càng khó vượt qua — hạn chế THẬT của tầng 2 trong production, không chỉ
   trong đánh giá này. **Đây là điểm cần cải thiện nếu có thời gian** (VD
   dùng median/IQR thay vì mean/stddev, hoặc loại các lần đã gắn cờ rủi ro
   cao khỏi việc cập nhật baseline).
3. **Ngưỡng cố định (40 điểm) không thích ứng** — đường ROC của tầng 2 vẫn
   đạt AUC 0.777 (cao hơn ngẫu nhiên đáng kể), nghĩa là điểm số **về hướng
   là đúng** (anomaly có xu hướng điểm cao hơn normal), nhưng ngưỡng 40 đặt
   quá cao so với phân bố điểm thực tế nên hầu hết không vượt qua. ML không
   dùng ngưỡng cố định — chọn ngưỡng theo **percentile của chính phân bố dữ
   liệu** (tham số `contamination`), thích ứng tốt hơn.

### Feature importance (Isolation Forest, permutation importance)

Xếp hạng theo mức giảm ROC-AUC khi xáo trộn từng đặc trưng:
`hour_deviation_from_avg` > `is_new_device` > `distance_km_from_home` >
`logins_last_24h` > `is_new_location` > (4 đặc trưng còn lại gần như không
đóng góp, `day_of_week` gần như nhiễu).

**`is_new_device` đứng thứ 2** — ngay sau lệch giờ — dù đây là đặc trưng
**hoàn toàn không tồn tại ở tầng 2**. Đây là bằng chứng định lượng cho việc
mở rộng đặc trưng (không chỉ đổi thuật toán) mới là yếu tố quyết định khiến
tầng 3 "thông minh hơn", không phải bản thân Isolation Forest có phép màu gì.

## 5. Giới hạn thật, nói thẳng khi bị hỏi

- **Dữ liệu tự sinh, không phải tấn công thật.** Ranh giới "bất thường" do
  chính script sinh dữ liệu định nghĩa — mô hình về bản chất học lại đúng
  logic đó. Số liệu đẹp không chứng minh hệ thống phát hiện được tấn công
  thật ngoài đời, chỉ chứng minh **pipeline đúng phương pháp luận** (không
  rò rỉ dữ liệu, so sánh công bằng, tái lập được).
- **Isolation Forest yếu nhất ở `rapid_fire` và `unusual_device` đơn lẻ**
  (43-44% recall) — 2 kiểu bất thường mới thêm, ít mẫu train hơn (mỗi user
  1-2 ca) so với `unusual_hour`/`unusual_location` (3-5 ca/user) — hợp lý,
  cần thêm dữ liệu loại này nếu muốn cải thiện.
- **Precision của Autoencoder thấp (50.8%)** — báo động giả nhiều nhất
  trong 3 mô hình. Kiến trúc mạng nhỏ (phù hợp dữ liệu ít), có thể cải
  thiện bằng nhiều dữ liệu train "sạch" hơn.
- Baseline tầng 2 (mục 3, phát hiện #2) là hạn chế **có thật trong hệ thống
  đang chạy**, không riêng gì bài đánh giá này — nên ghi vào phần "hướng
  phát triển" của báo cáo cuối.

## 6. Tái tạo kết quả

```bash
cd backend
venv\Scripts\python.exe -m ml.generate_dataset --reset   # sinh dữ liệu (40 user, 5 kiểu bất thường)
venv\Scripts\python.exe -m ml.extract_features            # trích đặc trưng, chống rò rỉ dữ liệu
venv\Scripts\python.exe -m ml.train                        # huấn luyện 3 mô hình
venv\Scripts\python.exe -m ml.evaluate                     # so sánh + xuất biểu đồ
```

Có tính ngẫu nhiên nhẹ ở bước sinh dữ liệu (không cố định seed cho toàn bộ
random) — số liệu mỗi lần chạy lại xê dịch vài % nhưng xu hướng (tầng 2 gần
như im lặng, ML vượt trội rõ rệt) giữ nguyên.
