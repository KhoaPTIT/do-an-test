# Checklist tổng hợp toàn dự án

Chép từ phụ lục checklist gốc (`Ke_hoach_trien_khai_chi_tiet_va_checklist.docx`, mục 11).
Tick `[x]` khi nhiệm vụ đã qua đủ các mục kiểm tra — không tick khi chỉ mới viết code xong.

## Tuần 1 — Kiến trúc & khung project

- [x] 1.1 Thống nhất kiến trúc & API contract — Cả hai — xem [`docs/api-contract.md`](api-contract.md)
- [x] 1.2 Thiết kế schema cơ sở dữ liệu — A — xem [`docs/db-schema.md`](db-schema.md)
- [x] 1.3 Khởi tạo khung backend (FastAPI) — A
- [x] 1.4 Khởi tạo khung frontend (React) — B

## Tuần 2 — Đăng nhập & log cơ bản

- [x] 2.1 API đăng nhập cơ bản + ghi log — A — `POST /login`, xem [`backend/app/routers/auth.py`](../backend/app/routers/auth.py)
- [x] 2.2 Giao diện đăng nhập web app mẫu — B — [`frontend/src/pages/LoginPage.jsx`](../frontend/src/pages/LoginPage.jsx)
- [x] 2.3 Sinh dữ liệu đăng nhập lịch sử giả lập ban đầu — Cả hai — [`backend/scripts/generate_historical_data.py`](../backend/scripts/generate_historical_data.py)

## Tuần 3 — Rule-based tầng 1

- [x] 3.1 Tích hợp MaxMind GeoLite2 — A — [`backend/app/detection/geoip.py`](../backend/app/detection/geoip.py), dùng dữ liệu GeoLite2-City thật (xem [`docs/geoip-setup.md`](geoip-setup.md))
- [x] 3.2 Đếm login fail bằng Redis (sliding window) — A — [`backend/app/detection/rate_counter.py`](../backend/app/detection/rate_counter.py)
- [x] 3.3 Viết rule-based detection tầng 1 — A — [`backend/app/detection/rules.py`](../backend/app/detection/rules.py)
- [x] 3.4 Dựng khung dashboard 4 khu vực — B — [`frontend/src/pages/DashboardPage.jsx`](../frontend/src/pages/DashboardPage.jsx)
- [x] 3.5 Mở rộng dữ liệu lịch sử giả lập cho baseline — B — [`backend/scripts/generate_labeled_anomalies.py`](../backend/scripts/generate_labeled_anomalies.py)

## Tuần 4 — Behavioral scoring tầng 2

- [x] 4.1 Xây baseline hành vi user — A — [`backend/app/detection/baseline.py`](../backend/app/detection/baseline.py)
- [x] 4.2 Cài đặt chấm điểm risk score tầng 2 — A — [`backend/app/detection/scoring.py`](../backend/app/detection/scoring.py)
- [x] 4.3 Bảng log & biểu đồ tĩnh trên dashboard — B — `GET /login-events`, `GET /alerts` + [`frontend/src/components/LogTablePanel.jsx`](../frontend/src/components/LogTablePanel.jsx), [`RiskChartPanel.jsx`](../frontend/src/components/RiskChartPanel.jsx)

## Tuần 5 — Bảo mật & real-time

- [x] 5.1 Xác thực JWT cho admin & WebSocket — A — [`backend/app/dependencies.py`](../backend/app/dependencies.py), [`backend/app/routers/admin.py`](../backend/app/routers/admin.py)
- [x] 5.2 Tối ưu tốc độ detection engine — A — [`backend/app/detection/pipeline.py`](../backend/app/detection/pipeline.py) (BackgroundTasks), xem [`docs/performance.md`](performance.md)
- [x] 5.3 Kết nối WebSocket thật & bản đồ real-time — B — [`frontend/src/services/useAlertsSocket.js`](../frontend/src/services/useAlertsSocket.js)

## Tuần 6 — Kịch bản tấn công & kiểm thử end-to-end

- [x] 6.1 Viết 4 script giả lập tấn công — B — [`attack-sim/`](../attack-sim/)
- [x] 6.2 Kiểm thử end-to-end toàn luồng — Cả hai — [`docs/e2e-test-report.md`](e2e-test-report.md)

## Tuần 7 — ML mở rộng & đánh giá hệ thống

- [x] 7.1 Thử nghiệm mô hình ML tầng 3 — A — **đầu tư sâu, không chỉ "tuỳ chọn"**: 3 thuật toán (Isolation Forest, LOF, Autoencoder), 5 kiểu bất thường, so sánh với tầng 2 thật — xem [`docs/ml-evaluation.md`](ml-evaluation.md)
- [x] 7.2 Hoàn thiện giao diện & đo precision/recall — B — hệ thống thiết kế (CSS variables), nav/form/dashboard viết lại, responsive mobile/tablet đã test; precision/recall đo xong ở 7.1

## Tuần 8 — Báo cáo, slide & diễn tập demo

- [ ] 8.1 Viết báo cáo, chuẩn bị slide, diễn tập demo — Cả hai

---

# Giai đoạn mở rộng — nâng cấp AI, rule engine, cảnh báo (sau Tuần 7)

Kế hoạch **MR1–MR19** đã được duyệt ngày 20/09/2026, làm tuần tự theo thứ tự dưới đây. Nhãn: **[Lõi]** bắt buộc, **[Nên]** nên có, **[Thêm]** bổ sung. Cỡ: S ≈ 1 phiên làm việc, M ≈ 2–3, L ≥ 4. Mỗi MR có test, commit riêng và cập nhật docs; chỉ tick khi đạt điều kiện "Xong khi".

⚠️ **Đính chính quan trọng về dữ liệu:** bộ RBA là dữ liệu **tổng hợp** (README ghi "hoàn toàn nhân tạo"), không phải log thật — xem [`rba-data-card.md`](rba-data-card.md). Không được nói "huấn luyện trên dữ liệu thật" khi báo cáo.

Ba nguồn bằng chứng: (1) **RBA** — mô hình tần suất/mới lạ, so baseline Freeman, kiểm tra tổng quát hoá; (2) **simulator của dự án** — địa lý, giờ, impossible travel, kịch bản tấn công có nhãn tự kiểm soát; (3) **tấn công sống** vào hệ thống đang chạy — kiểm thử end-to-end, thời gian phát hiện.

**Điểm kiểm soát:** CP1 sau MR5 (đo tín hiệu thật, báo trước khi làm tiếp) · CP2 sau MR8 (chốt mô hình) · CP3 sau MR12 (hồi quy toàn hệ thống).

## Giai đoạn A — Nền móng dữ liệu

- [x] **MR1 [Lõi, S] Chốt chiến lược dữ liệu và môi trường** — Xong khi: một lệnh kiểm tra môi trường báo đủ (`python -m ml.check_env`)
  - [x] Data card: nguồn, CC BY 4.0, trích dẫn, ghi rõ "tổng hợp" — [`rba-data-card.md`](rba-data-card.md)
  - [x] Dữ liệu RBA ngoài git (`backend/ml/data/rba/` trong `.gitignore`), đọc thẳng từ zip, không giải nén — [`backend/ml/rba/paths.py`](../backend/ml/rba/paths.py)
  - [x] Cài lightgbm, shap, pyarrow, duckdb, user-agents; cập nhật [`requirements.txt`](../backend/requirements.txt)
  - [x] `lookup_asn()` ([`geoip.py`](../backend/app/detection/geoip.py)) và `parse_user_agent()` ([`device.py`](../backend/app/utils/device.py)) cho luồng realtime; file `GeoLite2-ASN.mmdb` chưa tải (chỉ cần từ MR12), xem [`geoip-setup.md`](geoip-setup.md)
  - [x] Danh sách Tor / datacenter / VPN công khai — [`backend/scripts/update_threat_feeds.py`](../backend/scripts/update_threat_feeds.py)
- [x] **MR2 [Lõi, M] Pipeline dữ liệu RBA** — Xong khi: test chứng minh không IP tấn công nào trùng giữa train và test (`tests/test_rba_real_data.py` trên mẫu thật + `tests/test_rba_splits.py`, `test_rba_sample.py`). Chi tiết: [`rba-data-card.md`](rba-data-card.md) mục 8
  - [x] ETL theo chunk từ zip sang Parquet ([`etl.py`](../backend/ml/rba/etl.py)); đối chiếu cột `index`: 31.269.264 dòng, liên tục, không mất dòng (README ghi >33M, nguyên nhân chênh chưa rõ)
  - [x] Đánh dấu artifact (IP 10.x, ASN ≥ 500000, 1.526 UA lỗi); loại 2 "user" khổng lồ (thùng chứa tài khoản không tồn tại 14 triệu sự kiện; client tự thử lại 70 nghìn sự kiện)
  - [x] Lấy mẫu theo user giữ nguyên lịch sử ([`sample.py`](../backend/ml/rba/sample.py)): đủ 138 user ATO + mẫu phân tầng 5%/10%/25% → 2.707.021 dòng, 401.092 user
  - [x] Chia theo thời gian + nhóm IP ([`splits.py`](../backend/ml/rba/splits.py)): train 02–07/2020, val 08/2020, test 09–11/2020, **late 12/2020–02/2021 (kiểm tra trôi phân phối)**; nhãn Attack IP chia theo **IP**; ATO (141) chỉ để đánh giá, 38 ca ở giai đoạn tương lai
  - ⚠️ Điều chỉnh so với kế hoạch: cả 141 ATO nằm trong 02–11/2020 (không có ca nào từ 12/2020) nên test phải phủ hết 11/2020; thêm cột `weight` để phục hồi tỉ lệ tấn công tự nhiên (val/test chỉ giữ 15% IP tấn công); bỏ "CV theo user cho ATO" vì ATO không bao giờ vào huấn luyện

## Giai đoạn B — AI lõi

- [ ] **MR3 [Lõi, L] Đặc trưng v2, dùng chung train và realtime** — Xong khi: test rò rỉ và test tương đương offline/online đều pass
  - [ ] Mới lạ theo user: country/ASN/IP/browser/OS/device type mới (so với lịch sử đăng nhập thành công)
  - [ ] Kiểu Freeman: log-ratio p_user/p_global từng thuộc tính (có làm mịn), đưa từng thành phần vào model
  - [ ] Độ hiếm toàn cục (−log p_global): country, ASN, UA family, OS
  - [ ] Nhịp/tần suất: số lần thử theo user/IP/ASN trong 1h/24h, chuỗi fail, thời gian từ lần thành công gần nhất, số IP/quốc gia khác nhau 24h/7d
  - [ ] Cấp hạ tầng: số user bị thử từ cùng IP/ASN, tỉ lệ thành công của IP/ASN, đa dạng UA
  - [ ] Đặc trưng cold-start cho user ít lịch sử
  - [ ] Đặc trưng cấp IP/ASN tính bằng DuckDB trên toàn bộ dữ liệu, kèm test tương đương với đường online Python
  - [ ] Test không rò rỉ: thêm sự kiện tương lai thì đặc trưng không đổi
- [ ] **MR4 [Lõi, M] Khung đánh giá nghiêm ngặt** — Xong khi: một lệnh sinh bảng kết quả chuẩn cho mọi model
  - [ ] Chỉ số: PR-AUC, recall tại FPR 1% và 0,1%, số cảnh báo/ngày ở recall cố định, tỉ lệ yêu cầu xác thực lại tại TPR 99%/99,9%
  - [ ] Mô phỏng kẻ tấn công Naive / VPN / Targeted chèn vào lịch sử user hợp lệ
  - [ ] Khoảng tin cậy bootstrap (bắt buộc cho ATO chỉ có 141 mẫu)
  - [ ] Báo cáo tách riêng user cold-start và user nhiều lịch sử
- [ ] **MR5 [Lõi, M] Baseline (CP1)** — Xong khi: có bảng baseline và kết luận dữ liệu thật sự chứa tín hiệu gì
  - [ ] Cài lại mô hình Freeman et al. 2016 làm baseline học thuật
  - [ ] Rule Tier 2 hiện tại và rule đã tinh chỉnh ngưỡng trên train
  - [ ] Isolation Forest hiện tại chạy trên đặc trưng mới
- [ ] **MR6 [Lõi, L] Mô hình và hybrid** — Xong khi: model card và bảng so với baseline MR5
  - [ ] Unsupervised chỉ học từ đăng nhập hợp lệ: Isolation Forest, LOF/kNN-distance, Autoencoder
  - [ ] Supervised gradient boosting (LightGBM) trên nhãn Attack IP, chia theo IP, class weight
  - [ ] Đánh giá trên 141 ATO: recall ở ngân sách cảnh báo cố định
  - [ ] Stacking/ensemble, hiệu chỉnh xác suất (isotonic/Platt), chọn ngưỡng theo mục tiêu
  - [ ] Cá nhân hoá, toàn cục và fallback cold-start
  - [ ] Mô hình B (địa lý-thời gian) trên simulator mở rộng, vì RBA không hỗ trợ
- [ ] **MR7 [Lõi, M] Kiểm chứng "kiểu tấn công mới" và ablation** — Xong khi: bảng ablation và kết luận trung thực
  - [ ] Giấu từng họ tấn công khỏi tập train (bot/device, Attack IP theo ASN, ATO), đo phần bắt được
  - [ ] Ablation theo nhóm đặc trưng để chứng minh không học đường tắt
  - [ ] Phân tích lỗi: các ca ATO bị bỏ sót và báo nhầm tiêu biểu
  - [ ] Ghi thẳng giới hạn với Targeted attacker
- [ ] **MR8 [Lõi, M] Giải thích và model card (CP2)**
  - [ ] SHAP cho LightGBM; z-score fallback cho unsupervised
  - [ ] Câu tiếng Việt ngắn từ top-3 yếu tố, kèm so sánh "thường … hôm nay …" (giữ định dạng rút gọn hiện tại)
  - [ ] Model card: dữ liệu, chỉ số, giới hạn, phiên bản đặc trưng, ngưỡng

## Giai đoạn C — Rule engine v2

- [ ] **MR9 [Lõi, L] Rule engine v2** — Xong khi: ≥ 12 rule có test, danh mục rule tự sinh vào docs
  - [ ] Registry: id, mô tả, mức nghiêm trọng, ánh xạ MITRE ATT&CK (T1110.001/.003/.004, T1078, T1090), ngưỡng cấu hình được, bật/tắt, chế độ shadow
  - [ ] Rule mới: password spray chậm; brute force phân tán vào 1 tài khoản; enumeration; bot/automation (UA bot, UA rotation, nhịp đều, client kịch bản như curl/python-requests); Tor/datacenter/VPN; TK ngủ đông; đa ngữ cảnh đồng thời; blocklist; country-hop
  - [ ] Nâng rule cũ: credential stuffing dùng thêm ASN, UA rotation, tỉ lệ thành công
  - [ ] Test dương/âm cho từng rule và bộ replay chạy rule trên log lịch sử
- [ ] **MR10 [Nên, M] Tinh chỉnh theo dữ liệu và bù trừ rule/ML** — Xong khi: bảng chồng lấn làm bằng chứng cho hybrid
  - [ ] Tối ưu ngưỡng các rule áp dụng được trên train RBA, báo cáo trên test
  - [ ] Phân tích chồng lấn: chỉ rule bắt / chỉ ML bắt / cả hai / cả hai bỏ sót

## Giai đoạn D — Hợp nhất và tích hợp

- [ ] **MR11 [Lõi, M] Hybrid risk engine**
  - [ ] Gộp điểm ML đã hiệu chỉnh, kết quả rule và reputation thành điểm 0–100 (noisy-OR có trọng số + luật ghi đè cho rule chắc chắn)
  - [ ] Chính sách hành động: cho qua / cảnh báo / yêu cầu xác thực thêm / khoá tạm
  - [ ] Lưu điểm từng thành phần để giải thích
  - [ ] Kiểm tra chuyển miền (RBA sang simulator/live) và hiệu chỉnh lại ngưỡng
- [ ] **MR12 [Lõi, L] Tích hợp realtime (CP3)**
  - [ ] Migration Alembic: cột mới cho `login_events` (asn, os_name, browser_name, device_type), `alerts` (rule_id, attack_family, explanation JSON, campaign_id, trạng thái, phản hồi); bảng mới (campaigns, blocklist, response_actions, audit_log, model_registry)
  - [ ] Parse UA và tra ASN trong pipeline nền, không chặn `/login`
  - [ ] Nạp model theo phiên bản, fallback an toàn
  - [ ] Đo độ trễ p50/p95/p99 và tải; giữ toàn bộ test cũ và thêm test mới
  - [ ] Theo dõi drift đặc trưng (PSI)

## Giai đoạn E — Cảnh báo thông minh và vận hành

- [ ] **MR13 [Lõi, M] Cảnh báo thông minh v2** — Xong khi: đo được mức giảm số cảnh báo và độ chính xác gán họ trên simulator
  - [ ] Novelty alert ("lần đầu quốc gia/ASN/thiết bị này, đã dùng X lần trước")
  - [ ] So sánh với bình thường ngay trong message, giữ ngắn gọn
  - [ ] Gán "họ tấn công" gợi ý kèm độ tin cậy, ghi rõ là gợi ý
  - [ ] Chống trùng lặp, xếp hạng ưu tiên (mức lạ × độ tin cậy × tầm quan trọng TK)
- [ ] **MR14 [Nên, M] Tương quan chiến dịch**
  - [ ] Gom alert theo ASN/IP/UA/khung giờ thành chiến dịch, kiểm chứng trên cụm ATO của RBA
  - [ ] API và trang "chiến dịch": số TK bị nhắm, timeline, trạng thái
  - [ ] Đồ thị liên kết user–IP–ASN–thiết bị để tìm hạ tầng dùng chung
- [ ] **MR15 [Nên, M] Vòng phản hồi**
  - [ ] Nút "Đúng / Báo nhầm" (kèm ghi chú) và nhật ký kiểm toán
  - [ ] Ngưỡng thích nghi theo user/nhóm; script retrain định kỳ có dùng phản hồi
  - [ ] Đánh giá bằng phản hồi mô phỏng: báo nhầm giảm bao nhiêu sau K vòng
- [ ] **MR16 [Thêm, M] Phản ứng tự động (mô phỏng)**
  - [ ] Web app mẫu có bước xác thực thêm (OTP giả lập) khi rủi ro trung bình
  - [ ] Khoá tạm tài khoản, chặn IP có hạn dùng, admin có nút mở khoá
  - [ ] Test toàn bộ luồng

## Giai đoạn F — Dashboard, tấn công mô phỏng, nghiệm thu

- [ ] **MR17 [Nên, M] Dashboard v2**
  - [ ] Hồ sơ rủi ro theo user (timeline, alert, thiết bị/quốc gia quen)
  - [ ] Trang chiến dịch, hiệu năng rule/ML, sức khoẻ model (drift, phiên bản)
  - [ ] Chỉnh ngưỡng và bật/tắt rule từ giao diện admin
  - [ ] Bộ lọc mở rộng (họ tấn công, rule, chiến dịch, phản hồi); kiểm thử responsive
- [ ] **MR18 [Lõi, M] Thư viện tấn công mô phỏng v2 và scorecard**
  - [ ] Kịch bản: spray chậm, botnet phân tán, proxy cùng quốc gia, UA rotation, TK ngủ đông, Targeted mimic, enumeration, stuffing quy mô lớn, impossible travel
  - [ ] Runner chạy tất cả và ghi: có phát hiện không, thời gian phát hiện, bằng rule/ML/hybrid, số cảnh báo
  - [ ] Scorecard đưa vào báo cáo, **kể cả các ca hệ thống không bắt được**
  - [ ] Dùng lại làm dữ liệu sinh cho mô hình B (MR6)
- [ ] **MR19 [Lõi, M] Tài liệu và nghiệm thu**
  - [ ] `docs/ml-evaluation-v2.md` (kết quả RBA, simulator, live; ablation; giới hạn), model card, data card, ma trận phủ hành vi
  - [ ] Bảng năng lực so với công cụ thương mại (từ tài liệu công khai) và so số với baseline học thuật
  - [ ] Cập nhật checklist, README, api-contract, db-schema, getting-started; hướng dẫn tái lập
  - [ ] Regression, e2e, performance, soak test

## Bổ sung tuỳ chọn (làm sau CP2 nếu còn thời gian)

- [ ] **MR-S1** Nhật ký truy cập sau đăng nhập và phát hiện IDOR/enumeration (module riêng, dữ liệu mô phỏng, ghi rõ ngoài phạm vi "đăng nhập")
- [ ] **MR-S2** Mô hình chuỗi (GRU) hoặc đồ thị — chỉ làm nếu MR6 cho thấy còn dư địa
- [ ] **MR-S3** Trợ lý điều tra dùng LLM tóm tắt chiến dịch từ bằng chứng có cấu trúc (cần API key, có chế độ tắt, không thay giải thích tất định)
- [ ] **MR-S4** Clustering tìm "mẫu lạ mới" tự động
