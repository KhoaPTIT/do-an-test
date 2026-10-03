# Mô hình bất thường chạy thật (Phase 4.1)

> Tài liệu chính của phần AI/ML đang chạy. Mục 1 ghi quyết định kiến trúc (ML0) TRƯỚC khi sửa mã; mọi con số ở mục 3–7 đọc từ
> bằng chứng do máy sinh trong [`artifacts/ml/`](../artifacts/ml/) — không gõ tay. **Dataset là TỔNG HỢP**, không phải log người dùng
> hay tấn công thật.

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

## 3. Dataset (ML2)

Mã: [`backend/ml/dataset.py`](../backend/ml/dataset.py) · [`backend/ml/build_features.py`](../backend/ml/build_features.py) · bằng chứng:
[`artifacts/ml/dataset_summary.json`](../artifacts/ml/dataset_summary.json).

- **Bình thường:** bộ sinh lưu lượng bình thường v3 (`verification/normal_traffic.py`), seed **41001**, 320 người dùng × 30 ngày
  — seed harness Phase 3 (20260302) bị loại trừ tường minh nên dữ liệu train không trùng lưu lượng dùng để đo 20 luật.
- **Bất thường chèn vào** (nhãn chỉ ghi ở `labels.csv`, KHÔNG BAO GIỜ là đầu vào model): `unusual_hour` 120, `unusual_location`
  120, `unusual_device` 120, `new_device_and_location` 100, `impossible_travel` 100, `login_burst` 30 đợt (292 lần thử).
- **Quy mô:** 27.573 lần thử (24.165 thành công) → **19.877 dòng đặc trưng** (chỉ lần thành công của hồ sơ trưởng thành).
- **Chia theo thời gian** (không xáo trộn, không rò rỉ tương lai): train < ngày 18 ≤ validation < ngày 24 ≤ test.

| Tập | Dòng | Bất thường | Dùng để |
|---|---:|---:|---|
| train | 13.236 | 507 | fit model (không dùng nhãn) |
| validation | 3.349 | 187 | CHỌN NGƯỠNG (chỉ dòng bình thường) |
| test | 3.292 | 143 | đánh giá CUỐI, chạy đúng một lần sau khi đã chốt ngưỡng |

Tất định: cùng seed ⇒ cùng file từng byte (sha256 ghi trong `dataset_summary.json`; test `tests/test_ml_dataset.py`).

## 4. Huấn luyện và chọn ngưỡng (ML3)

Mã: [`backend/ml/train.py`](../backend/ml/train.py) · bằng chứng: [`artifacts/ml/training_summary.json`](../artifacts/ml/training_summary.json).

- `sklearn.ensemble.IsolationForest(n_estimators=300, max_samples=256, contamination="auto", random_state=42)`, fit trên
  toàn bộ dòng train **không dùng nhãn** (học không giám sát).
- `anomaly_score = −score_samples(x)` (càng cao càng lạ).
- **Ngưỡng = phân vị 0,99 điểm của dòng BÌNH THƯỜNG trong validation** (FPR mục tiêu 1%) → **0,5905**. Chốt trước khi chạy test;
  không chỉnh sau khi xem kết quả test.
- Artifact: `backend/ml/artifacts/anomaly_iforest/{model.joblib, metadata.json}` (không commit; ~2,4 MB). `metadata.json` ghi
  tên/phiên bản (`v3-870bee225d73-03b95613-s42` = phiên bản đặc trưng + chữ ký đặc trưng + băm tập train + seed), tham số, danh
  sách và chữ ký đặc trưng, seed, kích thước các tập, ngưỡng, thống kê validation, trung bình/độ lệch chuẩn đặc trưng train
  (dùng để giải thích), sha256 dữ liệu.

## 5. Kết quả trên tập test (ML3)

Bằng chứng: [`evaluation.json`](../artifacts/ml/evaluation.json) · [`per_anomaly_metrics.json`](../artifacts/ml/per_anomaly_metrics.json) ·
[`confusion_matrix.json`](../artifacts/ml/confusion_matrix.json) / [`.png`](../artifacts/ml/confusion_matrix.png). Tỉ lệ bất thường trong test 4,34%
— vì vậy KHÔNG dùng accuracy (đoán "bình thường" cho mọi dòng đã đạt 95,7%).

| TP | FP | TN | FN | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC (AP) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 87 | 33 | 3.116 | 56 | 0,725 | 0,608 | 0,662 | 1,05% | 0,971 | 0,780 (ngẫu nhiên: 0,043) |

| Kiểu bất thường (test) | Mẫu | Phát hiện | Recall |
|---|---:|---:|---:|
| impossible_travel | 24 | 24 | 1,00 |
| new_device_and_location | 24 | 24 | 1,00 |
| unusual_location | 24 | 24 | 1,00 |
| unusual_device | 20 | 8 | 0,40 |
| unusual_hour | 27 | 7 | 0,26 |
| login_burst | 24 | 0 | 0,00 |

Đọc kết quả: model mạnh với bất thường VỊ TRÍ/di chuyển; yếu với giờ lạ và thiết bị lạ đơn lẻ; **không bắt được đợt đăng nhập
dồn dập** — trong lưu lượng bình thường v3 người dùng đã đăng nhập dày (trung vị 17,6 lần/24 giờ), nên `logins_last_24h` của một
đợt dồn dập không nổi bật. Đây là số trên dữ liệu tổng hợp; FPR 1,05% trên test ≈ mục tiêu 1% đặt ở validation.

## 6. Luật vs ML trên harness Phase 3 (ML4)

Mã: [`backend/verification/rule_ml_experiment.py`](../backend/verification/rule_ml_experiment.py) · bằng chứng (máy sinh, commit sạch
`a4d62ef`): [`artifacts/ml/rule_ml_overlap.json`](../artifacts/ml/rule_ml_overlap.json), bảng từng kịch bản
[`rule_ml_overlap.md`](../artifacts/ml/rule_ml_overlap.md). Chạy lại TOÀN BỘ 21 hành vi × 20 kịch bản dương tính (+ 20 âm tính) và lưu
lượng bình thường của Phase 3 (seed harness 20260302 — khác seed dataset train) qua pipeline `/login` thật, VỚI model đã nạp.

Định nghĩa chốt TRƯỚC lần chạy đầu: *luật phát hiện* = ít nhất một luật VERIFIED đủ tư cách tự cảnh báo khớp (đọc từ verdict thật;
`unusual_hour` là experimental nên không tính); *ML phát hiện* = ít nhất một lần thử bị model gắn cờ.

| Nhóm | Kịch bản tấn công (420) |
|---|---:|
| A — cả luật và ML | 86 |
| B — chỉ luật | 314 |
| **C — chỉ ML** | **10** |
| D — không bên nào | 10 |

- ML chỉ chấm được 120/420 kịch bản: 14/21 hành vi nằm HOÀN TOÀN ngoài phạm vi model theo thiết kế (chuỗi lần sai mật khẩu, tài
  khoản/hồ sơ chưa trưởng thành, tín hiệu hạ tầng/UA trên tài khoản mới) — toàn bộ là nhóm B.
- **Cả 10 ca chỉ-ML đều là `unusual_hour`**: lệch giờ ~10–12 giờ so với nhịp quen; không luật VERIFIED nào khớp; điểm ML (0,59–0,60,
  sát ngưỡng 0,5905) đưa risk lên 48 ⇒ cảnh báo `score_threshold`, quy kết cho `unusual_hour` (luật experimental cũng khớp). 10 ca
  `unusual_hour` còn lại cả hai bỏ sót (nhóm D, điểm ML 0,545–0,586). Đây là giá trị bổ sung THẬT nhưng HẸP và mong manh (sát ngưỡng).
- Ở các hành vi ML cũng thấy (`unusual_location`, `unusual_device`, `rare_network_login`, `login_velocity_spike`,
  `multi_context_simultaneous`, `dormant_account_login`), ML trùng với luật (nhóm A) — không thêm phát hiện mới.
- **Chi phí:** trên lưu lượng bình thường (5.647 lần thử, 4.551 được chấm) ML gắn cờ **59 lần (1,30%)** và tạo **49 cảnh báo
  chỉ-ML** (`hybrid_ml`), trong khi 20 luật tạo **0** cảnh báo. Trên kịch bản âm tính sát ngưỡng, ML gắn cờ 11/20 của
  `unusual_location`, 9/20 `rare_network_login`, 7/20 `multi_context_simultaneous`, 2/20 `login_velocity_spike` — những ca luật
  đúng là im lặng. ML không làm luật nào báo nhầm thêm (cảnh báo chỉ-ML mang detector `hybrid_ml`, không mang `rule_id`).
- **Hồi quy:** cả **20 hành vi VERIFIED vẫn đạt tiêu chí khi bật ML** (`all_verified_still_verified: true`). `unusual_hour` vẫn là
  PARTIAL (trạng thái chính thức đo ở Phase 3, ML tắt; registry không đổi) — khi bật ML, công thức chấm của runner cho nó
  `FAILED_CRITERIA` (recall 0,50, quy kết 0,00) vì cảnh báo có được là nhờ ML chứ không phải luật tự đủ tư cách.

Kết luận: với dataset và ngưỡng đã chốt, ML chứng minh được giá trị bổ sung ở MỘT hành vi (giờ đăng nhập lạ, 10/20 kịch bản) với
cái giá là 49 cảnh báo nhầm trên lưu lượng bình thường 63 người dùng × 30 ngày. Không đổi dataset/ngưỡng sau khi xem kết quả này.

## 7. Tích hợp runtime (ML5)

```
POST /login ─► pipeline (app/detection/pipeline.py)
                ├─ tầng 1-2 cũ (giữ nguyên)
                ├─ rule engine v2: 20 detector VERIFIED (+ unusual_hour experimental, datacenter/vpn shadow)
                ├─ ml_runtime.predict(db, event)  ── Isolation Forest, chỉ lần THÀNH CÔNG của hồ sơ trưởng thành
                ├─ hybrid_runtime.evaluate(ml_prediction, hits) ── noisy-OR: ML bất thường = xác suất 0,45
                │     └─ chốt chặn: ML không bao giờ đưa hành động tới "lock" (hạ về step_up, ml_lock_suppressed)
                ├─ attribution.build_verdict ── luật = detector chính; ML = tín hiệu phụ "ml_anomaly"
                │     hoặc detector "hybrid_ml" nếu không luật nào khớp mà điểm vẫn vượt ngưỡng cảnh báo
                └─ lưu login_events.ml_* + alert.explanation["ml"] ─► GET /login-events, GET /alerts, WebSocket ─► dashboard
```

| Câu hỏi | Ở đâu |
|---|---|
| Backend nạp model | `app/main.py::_startup_mr12` → `app/detection/ml_runtime.py::load_at_startup` → `ml/anomaly_model.py::AnomalyModel.load` (từ `ML_MODEL_DIR` hoặc `backend/ml/artifacts/anomaly_iforest`; từ chối artifact lệch chữ ký đặc trưng); ghi `model_registry` (`app/detection/model_registry.py`) |
| Login gọi inference | `app/detection/pipeline.py` (sau rule engine, trước risk engine) → `ml_runtime.get_runtime().predict(db, event)` → `runtime_features` → `ml/features.py::compute_features` (cùng hàm với offline) |
| Gộp điểm | `app/detection/hybrid_runtime.py::HybridEngine.evaluate` + `ml_lock_suppressed` |
| API | `GET /login-events`: `ml_anomaly_score`, `ml_is_anomaly`, `ml_threshold`, `ml_model_version`, `ml_details` · `GET /alerts` và WebSocket: `explanation.ml` = `{model, version, available, in_scope, anomaly_score, threshold, is_anomaly, top_features, reason}`, `explanation.ml_lock_suppressed` · `GET /ml/status` (admin): `ml_available`, `model_name`, `model_version`, `threshold`, `trained_at`, `feature_signature`, `code_feature_signature`, `artifact_dir`, `artifact_files`, `loaded_at`, `last_load_error`, `risk_weight_when_anomalous`, `scope`, `can_lock=false` |
| Dashboard | Danh sách cảnh báo → nút "Chi tiết (detector, bằng chứng, AI/ML)" (`frontend/src/components/AlertDetails.jsx`): Primary detector, Secondary signals, Risk score, Rule evidence, Model / Anomaly score / Threshold / Result; bảng log cột "AI/ML" (`LogTablePanel.jsx`); trang "Sức khoẻ mô hình" khối "Model AI đang chạy" (`ModelHealthPage.jsx`, đọc `GET /ml/status`). Không có model: "AI model: Not loaded". Ảnh: [`artifacts/ml/screenshots/`](../artifacts/ml/screenshots/) |

An toàn (Phase 4.1H): ML một mình chỉ đạt 45 điểm = "alert" (không OTP, không khoá); thiếu/lỗi artifact → `ml_available=false`, 20
detector luật chạy như trước; lỗi lúc chấm → bỏ qua tín hiệu ML (`reason="error"`), không chặn đăng nhập. Test:
`tests/test_ml_runtime_integration.py`, `tests/test_hybrid_runtime.py`.

## 8. Demo bảo vệ (ML7)

```bash
cd backend
python -m ml.pipeline                  # 1. train (nếu chưa có artifact)
python -m scripts.ml_demo --evidence   # 2-5. app thật nạp model -> POST /login -> inference -> API; ghi runtime_integration.json
python -m scripts.ml_demo --serve 8000 # + giữ backend chạy; terminal khác: cd frontend && npm run dev
                                       #   đăng nhập dashboard: demo_admin / DemoAdmin123!
```

_(Kết quả demo điền từ `artifacts/ml/runtime_integration.json`.)_

## 9. Train lại từ đầu

```bash
docker compose up -d                   # Postgres + Redis (cho web app; train/demo/test không cần)
cd backend
python -m ml.pipeline                  # dataset -> đặc trưng -> train -> đánh giá -> artifacts/ml/*.json
uvicorn app.main:app --port 8000       # khởi động (lại) backend: tự nạp artifact vừa train
python -m verification.rule_ml_experiment   # (tuỳ chọn) chạy lại thí nghiệm luật vs ML
```

## 10. Hạn chế (phải nói khi bảo vệ)

1. **Dataset tổng hợp.** Mọi số liệu đo trên dữ liệu sinh bằng mã (bình thường từ bộ sinh v3, bất thường chèn theo luật sinh) — không
   phải người dùng hay tấn công thật. Model và luật được kiểm trên dữ liệu có cùng "họ" bộ sinh: con số có thể lạc quan.
2. **Kiểu bất thường do chính nhóm định nghĩa.** Recall 100% ở vị trí/di chuyển phản ánh bất thường chèn rất rõ; recall thấp ở giờ lạ
   (0,26), thiết bị lạ (0,40) và **0 ở đăng nhập dồn dập**.
3. **Giá trị bổ sung hẹp:** 10/420 kịch bản chỉ-ML, đều là giờ lạ, điểm sát ngưỡng. Phần lớn tấn công (300/420) nằm ngoài phạm vi
   model (lần sai mật khẩu, tài khoản mới, hạ tầng) — đó là việc của 20 luật.
4. **Chi phí báo nhầm:** 49 cảnh báo chỉ-ML trên lưu lượng bình thường (luật: 0); FPR test 1,05%. ML chỉ ở mức "alert" (không OTP,
   không khoá) để giới hạn tác hại.
5. **Không giám sát, ngưỡng một điểm:** ngưỡng chọn cho FPR 1% trên validation; chưa hiệu chỉnh theo từng người dùng; chưa có
   cơ chế train lại định kỳ/giám sát trôi cho model mới (trang PSI hiện có thuộc đặc trưng RBA cũ).
6. **Giải thích là xấp xỉ:** `top_features` = z-score so với trung bình train, không phải đóng góp thật của Isolation Forest.
7. **Hiệu năng runtime:** mỗi lần chấm đọc toàn bộ lịch sử thành công của tài khoản — ổn ở quy mô đồ án, chưa tối ưu cho tài khoản
   có lịch sử rất dài.
8. **`hybrid_cp2` và số liệu RBA (MR1–8)** là nghiên cứu offline, không còn chạy; số liệu tầng 3 cũ (Tuần 7) không tái lập được.
