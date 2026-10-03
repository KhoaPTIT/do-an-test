# Hướng dẫn tái lập toàn bộ (MR19)

Gom **theo đúng thứ tự phụ thuộc** mọi lệnh tái lập đã nằm rải rác ở cuối từng tài liệu riêng (mỗi tài liệu vẫn là
nguồn giải thích số liệu — tài liệu này chỉ lo thứ tự chạy). Nếu chỉ cần chạy hệ thống lên (không cần huấn luyện lại
mô hình/tái lập số liệu nghiên cứu), dừng ở Giai đoạn 0 và xem [`getting-started.md`](getting-started.md).

Tất cả lệnh chạy từ `backend/`, môi trường ảo đã activate (`venv\Scripts\activate`), Windows:
`set PYTHONIOENCODING=utf-8` trước khi chạy bất kỳ lệnh nào in tiếng Việt.

## Giai đoạn 0 — Hạ tầng và dữ liệu demo (bắt buộc để chạy web app)

Đã có sẵn trên máy dev hiện tại; chỉ cần trên máy mới hoàn toàn. Chi tiết đầy đủ: [`getting-started.md`](getting-started.md).

```bash
docker compose up -d                                       # Postgres + Redis
alembic upgrade head                                        # toàn bộ schema, 15 bảng — docs/db-schema.md
python -m scripts.create_admin --username admin --password "MatKhauManh123!"
python -m scripts.generate_labeled_anomalies --reset        # 25 user demo dashboard (Tuần 3)
# (bộ dữ liệu tầng 3 cũ `ml.generate_dataset` đã gỡ ở Phase 4.1 — model AI đang chạy train theo Giai đoạn 5)
```

## Giai đoạn 1 — Bộ dữ liệu RBA (bắt buộc cho mọi thứ ở Giai đoạn 2-4)

> **Giai đoạn 1-4 là nghiên cứu OFFLINE trên bộ RBA.** Từ Phase 4.1, `hybrid_cp2` KHÔNG còn chạy trong `/login` (lý do:
> [`ml-anomaly-model.md`](ml-anomaly-model.md) mục 1). Không cần chạy Giai đoạn 1-4 để có hệ thống chạy đầy đủ.

Cần file `rba-dataset.zip` (Kaggle `dasgroup/rba-dataset`, 9GB, **không giải nén**) đặt ở `RBA_ZIP_PATH` hoặc
`backend/ml/data/rba/` hoặc Downloads. Chi tiết, giấy phép, cảnh báo "dữ liệu tổng hợp": [`rba-data-card.md`](rba-data-card.md).

```bash
python -m ml.check_env      # xác nhận tìm thấy file zip trước khi chạy gì tốn thời gian
python -m ml.rba.etl        # zip -> ml/data/rba/rba_full.parquet, ~5 phút
python -m ml.rba.sample     # -> rba_sample.parquet, ~30 giây — 2.707.021 dòng/401.092 user dùng cho mọi bước sau
python -m pytest tests/test_rba_features*.py tests/test_rba_model_table.py   # 29 test: đặc trưng v2 không rò rỉ — rba-features.md
```

## Giai đoạn 2 — Bộ mô phỏng kẻ tấn công + kiểm định dấu vân tay

**Chạy trước khi tin bất kỳ số nào ở bài `attacker/*`** — nếu kiểm định không đạt, bộ mô phỏng còn "dấu vân tay" và
mô hình học từ nó sẽ cho recall giả tạo (từng xảy ra ở CP1, xem [`rba-evaluation.md`](rba-evaluation.md) mục 5).

```bash
python -m ml.rba.attackers                     # bộ test, ~10 phút — nên chạy nền
python -m ml.rba.attackers --period trainval    # bộ train/val để huấn luyện/chọn mô hình, ~8 phút
python -m ml.rba.audit                          # kiểm định tổng thể (test) — nhóm cur/history/rhythm/rarity/infra phải ≈ 0,5
python -m ml.rba.audit trainval                 # ... và train, val
python -m ml.rba.audit conditional              # kiểm định CÓ ĐIỀU KIỆN (MR8) — phát hiện dấu vân tay còn sót ở infra_ip/rarity
```

## Giai đoạn 3 — Huấn luyện và đánh giá bản MR6 (13 mô hình baseline, dùng để so sánh công bằng)

```bash
python -m ml.rba.train                          # huấn luyện toàn bộ 13 mô hình, ~8 phút -> ml/artifacts/rba/ (không commit)
python -m ml.rba.report all --n-boot 300        # 13 mô hình × 11 bài, khoảng tin cậy bootstrap, ~15 phút -> ml/artifacts/rba_reports/
python -m ml.rba.analysis gbm_attack_ip gbm_attacker_sim hybrid   # chuyển ngưỡng, hiệu chỉnh xác suất, gán công (bản MR6)
python -m ml.rba.summary                        # bảng ma trận mô hình × bài, đọc nhanh từ báo cáo đã lưu
```

Kiểm chứng bổ sung (không bắt buộc để có số chính, nhưng là nguồn của các kết luận "tổng quát hoá kém với họ mới"):

```bash
python -m ml.rba.holdout    # giấu 1 họ IP tấn công khỏi train — ml-holdout-ablation.md
python -m ml.rba.ablation   # bỏ từng nhóm đặc trưng — ml-holdout-ablation.md
python -m ml.rba.errors     # phân tích lỗi theo trường hợp — ml-holdout-ablation.md
python -m ml.rba.explain_eval all --hybrid hybrid   # giải thích + ngưỡng vận hành bản MR6 — ml-explanations.md
```

## Giai đoạn 4 — Chốt mô hình CP2 (`hybrid_cp2`) — nghiên cứu offline

Trước Phase 4.1 đây là mô hình `/login` dùng; từ Phase 4.1 chỉ còn là kết quả nghiên cứu (không nạp ở runtime). Chi tiết cơ chế chọn: [`ml-model-selection.md`](ml-model-selection.md).

```bash
python -m ml.rba.selection all     # chọn nhóm đặc trưng (bootstrap ghép cặp) + huấn luyện hybrid_cp2, ~15-20 phút -> ml/artifacts/rba_cp2/
python -m ml.rba.report gbm_attack_ip_cp2 gbm_attacker_sim_cp2 isolation_forest_cp2 hybrid_cp2 --n-boot 300
python -m ml.rba.analysis hybrid_cp2                # chuyển ngưỡng + gán công cho hybrid_cp2 — số ở ml-evaluation-v2.md mục "Tóm tắt vận hành"
python -m ml.rba.explain_eval all                   # giải thích + ngưỡng vận hành bản cp2 (mặc định) -> ml/artifacts/rba_cp2/explain/
python -m pytest tests/test_rba_selection.py         # 12 test
```

## Giai đoạn 5 — Model AI đang chạy: Isolation Forest (Phase 4.1)

Dataset TỔNG HỢP sinh tất định từ mã trong repo (không tải gì từ ngoài), train + đánh giá + bằng chứng trong một lệnh
(~1 phút). Chi tiết dataset, đặc trưng, ngưỡng, số liệu: [`ml-anomaly-model.md`](ml-anomaly-model.md).

```bash
python -m ml.pipeline      # dataset (seed 41001) -> đặc trưng -> chia theo thời gian -> train -> đánh giá trên test
                           # -> backend/ml/data/v3/ + backend/ml/artifacts/anomaly_iforest/ (không commit)
                           # -> artifacts/ml/{dataset_summary,training_summary,evaluation,per_anomaly_metrics,confusion_matrix}.*
# hoặc từng bước:
python -m ml.dataset && python -m ml.build_features && python -m ml.train && python -m ml.evaluate
python -m pytest tests/test_ml_*.py tests/test_rule_ml_experiment.py
```

Cùng seed ⇒ cùng dataset từng byte (sha256 trong `artifacts/ml/dataset_summary.json`).

## Giai đoạn 6 — Chạy hệ thống (tự nạp model AI)

```bash
uvicorn app.main:app --reload --port 8000
```

Lúc khởi động, backend nạp `backend/ml/artifacts/anomaly_iforest/` (hoặc thư mục trong biến môi trường `ML_MODEL_DIR`), từ
chối artifact có chữ ký đặc trưng lệch với mã, ghi phiên bản vào bảng `model_registry`. Kiểm tra: `GET /ml/status` (JWT
admin) hoặc trang "Sức khoẻ mô hình" của dashboard. Thiếu artifact thì hệ thống KHÔNG lỗi: `ml_available=false`, 20 detector
luật vẫn chạy, dashboard ghi "AI model: Not loaded". Train lại thì khởi động lại backend để nạp artifact mới.

## Giai đoạn 7 — Kiểm chứng bằng kịch bản mô phỏng qua HTTP thật (không phải test đơn vị)

Mỗi script tự dựng CSDL/Redis riêng trong bộ nhớ hoặc chạy qua `TestClient` — **không** chạy qua `pytest` (xem
docstring từng script), kết quả ghi lại thành tài liệu `docs/*.md` tương ứng:

```bash
python -m scripts.attack_scenario_runner       # 9 kịch bản thật qua HTTP -> docs/attack-scenarios-v2.md (MR18)
python -m scripts.alert_intelligence_sim       # ưu tiên hoá + dedup cảnh báo -> alert-intelligence-v2.md (MR13)
python -m scripts.feedback_loop_sim            # vòng phản hồi + ngưỡng thích nghi -> feedback-loop.md (MR15)
python -m scripts.automated_response_sim       # OTP + khoá tài khoản/IP -> automated-response.md (MR16)
```

⚠️ Một số script (kẻ tấn công mô phỏng, thứ tự chọn IP...) không có hạt giống ngẫu nhiên cố định — số liệu có thể
lệch nhẹ giữa các lần chạy; xem caveat cụ thể ở từng tài liệu đích trước khi so sánh với số đã công bố.

## Giai đoạn 8 — Kiểm thử, hiệu năng, soak test

```bash
pytest -q                                          # toàn bộ, không cần Docker (SQLite in-memory + fakeredis)
python -m scripts.benchmark_login --n 50           # độ trễ tuần tự — docs/performance.md
python -m scripts.benchmark_login --n 50 --concurrency 5   # độ trễ có tải
python -m scripts.soak_test --minutes 15           # tải nhẹ liên tục, tìm suy giảm theo thời gian — docs/soak-test.md (MR19)
```

## Giai đoạn 9 — Kiểm chứng hành vi phát hiện (Phase 3)

Không cần bộ RBA hay dịch vụ ngoài: mỗi kịch bản chạy trong SQLite in-memory + fakeredis với GeoIP/threat intel TEST
FIXTURE (`backend/verification/fixtures/`), thành phần ML của hybrid tắt.

```bash
cd backend
python -m pytest tests/behavior_detection/        # test hành vi: dương tính, âm tính, biên, quy kết, chống đầu độc hồ sơ
python -m scripts.behavior_verification            # ~45 phút: 21 hành vi × (20 dương tính + 20 âm tính) + lưu lượng bình thường
                                                   # + cross-behavior + nghiên cứu unusual_hour -> artifacts/behavior_verification/
```

Kết quả mong đợi (commit `a465dfb`): 20/21 VERIFIED (`unusual_hour` PARTIAL), cross-behavior 19/19, 0 cảnh báo của
detector trên lưu lượng bình thường. Đọc kết quả: [`behavior-coverage-matrix.md`](behavior-coverage-matrix.md).

## Giai đoạn 10 — Luật vs ML và demo bảo vệ (Phase 4.1)

Cần artifact của Giai đoạn 5.

```bash
python -m verification.rule_ml_experiment   # chạy lại 21 hành vi + lưu lượng bình thường của Phase 3 VỚI model đã nạp
                                            # -> artifacts/ml/rule_ml_overlap.{json,md}: A/B/C/D + 20 hành vi còn VERIFIED không
python -m scripts.ml_demo --evidence        # 5 kịch bản demo qua POST /login thật -> artifacts/ml/runtime_integration.json
python -m scripts.ml_demo --serve 8000      # như trên rồi giữ backend chạy; `cd frontend && npm run dev` để xem dashboard
```

## Tổng thời gian ước tính

Giai đoạn 1-4 (toàn bộ pipeline RBA từ đầu) mất khoảng **60-90 phút** trên máy dev hiện tại, phần lớn ở Giai đoạn 2-4
(mô phỏng kẻ tấn công + huấn luyện + báo cáo bootstrap). Giai đoạn 0/5/7/8 mỗi giai đoạn dưới 5 phút. Không có bước
nào cần GPU.
