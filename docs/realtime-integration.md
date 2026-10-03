# Tích hợp realtime — MR12 (CP3)

> ⚠️ **Lỗi thời từ Phase 4.1 (tài liệu lịch sử, giữ để tra cứu).** Phần `hybrid_cp2`/đặc trưng RBA và tầng 3 cũ trong tài liệu này mô tả kiến trúc TRƯỚC Phase 4.1 — cả hai đã gỡ khỏi `/login`. Model AI đang chạy: Isolation Forest trên dataset tổng hợp tái lập được — [`ml-anomaly-model.md`](ml-anomaly-model.md).

Nối rule engine v2 (MR9-10) và hybrid risk engine (MR11) vào luồng `/login` thật, thay vì chỉ chạy trên RBA ngoại
tuyến. Migration schema: [`db-schema.md`](db-schema.md). Không tự sinh từ script như MR9-11 (không có một "lượt chạy
ngoại tuyến" duy nhất để đo) — tài liệu này viết tay, số liệu dẫn nguồn cụ thể để tự kiểm lại được.

## 1. Kiến trúc

`app/detection/pipeline.py` (chạy NỀN sau khi `/login` đã trả response, từ Tuần 5) giờ có thêm một khối MỚI, **CHẠY
SONG SONG** tầng 1 (rule cũ), tầng 2 (risk score) và tầng 3 (ML cũ) — không thay thế, đúng triết lý xuyên suốt dự án:

1. **Parse UA + tra ASN** (`app/utils/device.parse_user_agent`, `app/detection/geoip.lookup_asn`) — ghi vào cột mới
   của `login_events` (`asn`, `os_name`, `browser_name`, `device_type`).
2. **Rule engine v2** (`app/detection/rule_engine_runtime.build_rule_engine`): dựng một `RuleEngine` (MR9) cho MỖI lần
   chấm — trạng thái cửa sổ thời gian (đếm lần sai, IP/UA khác nhau...) nằm trong REDIS THẬT (`RedisStore`, dùng
   chung kết nối với `rate_counter.py`, khoá tiền tố `rule:` không đụng nhau — bền qua restart); lịch sử tài khoản
   (`DbAccountHistory`) và thống kê ASN toàn cục (`DbGlobalStats`) DỰNG LẠI TỪ DB mỗi lần gọi thay vì giữ trong bộ nhớ
   tiến trình — luôn đúng dù chạy nhiều worker hay vừa restart, đổi lại tốn vài truy vấn DB mỗi lần (đo ở mục 4).
   Blocklist (bảng `blocklist` mới) nạp lại thành `Blocklist` trong bộ nhớ, cache 15 giây.
3. **Đặc trưng RBA** (`app/detection/rba_live_features.py`): dựng `HistorySummary` (kiểu đã có sẵn từ MR3,
   `ml/rba/features.py`) bằng 4 truy vấn nhắm chỉ mục, KHÔNG phải một bản sao công thức riêng — cùng hàm
   `features_from_summary` dùng để train `hybrid_cp2` trên RBA. Đếm toàn cục (độ hiếm/LLR) cache TTL 30 giây (không
   nhắm được một chỉ mục hẹp).
4. **Hybrid risk engine** (`app/detection/hybrid_runtime.py`): nạp mô hình theo `model_registry` (mục 3), chấm bằng
   `combine_risk` (MR11) với đầu vào là kết quả bước 2 (`evaluation.hits`) và bước 3 (xác suất ML) → điểm 0-100 +
   hành động, ghi vào `login_events.hybrid_risk_score`/`hybrid_action`.
5. Hành động khác `allow` → tạo `Alert` (`alert_type="hybrid_risk"`, `rule_id`, `explanation` JSON là danh sách đóng
   góp); hành động `step_up`/`lock` → thêm một hàng `response_actions` (**status luôn là `"recommended"` — CHƯA có gì
   thực thi thật, xem mục 5**) và một hàng `audit_log`.

Toàn bộ khối này nằm trong MỘT `try/except` riêng: lỗi ở bất kỳ bước nào (đặc trưng, rule engine, mô hình) được ghi
log và bỏ qua, KHÔNG được làm mất alert của tầng 1-2-3 hay làm sập luồng đăng nhập — kiểm bằng test (mục 6).

## 2. Nạp model theo phiên bản, fallback an toàn

`model_registry` (bảng mới) lưu phiên bản mô hình `hybrid_cp2` đang active (artifact `.joblib`, hồ sơ hiệu chỉnh MR11,
`feature_signature` lúc train). Tự đăng ký lúc ứng dụng khởi động nếu artifact có sẵn trên đĩa và chưa có hàng nào.
`app/detection/hybrid_runtime.HybridEngine.load()` nạp phiên bản active; BẤT KỲ bước nào lỗi (thiếu hàng active, thiếu
file, `feature_signature` lệch với mã hiện tại) đều bị nuốt và ghi log — khi đó dùng **hồ sơ dự phòng cứng** (chỉ
luật + danh tiếng, không có ML, bands rộng rãi `alert_at=40/step_up_at=65/lock_at=85`), KHÔNG BAO GIỜ tắt hẳn việc
phát hiện chỉ vì mô hình lỗi. Kiểm bằng test: thiếu hàng active, file `.joblib` hỏng/thiếu, `feature_signature` lệch,
hàng active không có `profile_path` (`tests/test_hybrid_runtime.py`).

## 3. Kết quả đo độ trễ và tải

### 3.1 Độ trễ pipeline nền (trong tiến trình, `app/detection/perf.py`)

Đo trực tiếp bằng `perf.timer(...)` quanh từng bước, cùng tiến trình Python (không qua HTTP) — phản ánh đúng chi phí
tính toán, không lẫn overhead mạng/bcrypt của endpoint. Trên DB Postgres thật (dev), 21 lần chấm liên tiếp cho một tài
khoản đã có lịch sử:

| Giai đoạn | mean | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| `rule_engine` | 6,7 ms | 8,8 ms | 10,6 ms | 10,7 ms | 10,7 ms |
| `rba_features` | 5,3 ms | 2,9 ms | 3,2 ms | 54,2 ms | 54,2 ms |
| `hybrid` (gồm cả hai trên) | 12,1 ms | 11,8 ms | 13,3 ms | 59,1 ms | 59,1 ms |
| `pipeline` (toàn bộ, gồm GeoIP/tầng 1-2-3/commit) | 28,1 ms | 26,6 ms | 28,6 ms | 134,2 ms | 134,2 ms |

`rba_features` có đúng MỘT lần tính chậm (~54 ms, lần đầu — cache đếm toàn cục còn trống, phải quét); các lần sau
trong TTL (30 giây) chỉ ~3 ms. Kết luận: **bản thân pipeline nền, tính TRONG tiến trình, rất nhanh** — không phải chỗ
nghẽn khi tải cao (mục 3.2).

### 3.2 Độ trễ và tải qua HTTP thật (`scripts/benchmark_login.py`, server thật ở `localhost:8000`, Postgres+Redis Docker)

| Kịch bản | min | median | p95 | p99 | max |
|---|---|---|---|---|---|
| 50 request TUẦN TỰ | 267 ms | 280 ms | 346 ms | 2.300 ms | 2.300 ms |
| 100 request, 10 ĐỒNG THỜI | 1.006 ms | 2.035 ms | 2.703 ms | 3.090 ms | 3.090 ms |
| 200 request, 20 ĐỒNG THỜI | 1.448 ms | 3.612 ms | 4.991 ms | 6.046 ms | 6.111 ms |

So với con số cũ của Tuần 5 (~250-260 ms, chủ yếu bcrypt ~227 ms) thì tuần tự vẫn tương đương (~280 ms trung vị) —
đúng như kỳ vọng, vì MR12 chạy NỀN nên KHÔNG được cộng vào thời gian phản hồi. p99 tuần tự thỉnh thoảng nhảy lên
~2,3 giây (một vài lần trong 50 — nghi cache đếm toàn cục hết hạn đúng lúc, hoặc GC/độ trễ hệ điều hành, chưa cô lập
được nguyên nhân chính xác).

**Phát hiện quan trọng, đã sửa ngay trong MR12:** `run_detection_pipeline` vốn khai báo `async def` nhưng bên trong
gọi TOÀN BỘ I/O ĐỒNG BỘ (SQLAlchemy driver `psycopg2`, redis-py đồng bộ) — nghĩa là chạy trực tiếp trên vòng lặp sự
kiện DÙNG CHUNG cho mọi kết nối, chặn cả việc nhận request MỚI trong lúc một pipeline nền đang chạy. Đo tải (20 request
đồng thời) TRƯỚC khi sửa cho ra `httpx.ReadTimeout` (client bỏ cuộc sau 10 giây) chứ không phải chỉ chậm. Đã sửa bằng
cách tách hàm thành một lõi ĐỒNG BỘ (`_run_detection_pipeline_sync`, giữ nguyên toàn bộ logic) chạy trong
`asyncio.to_thread`, còn `run_detection_pipeline` (`async def`) chỉ còn việc gọi nó rồi broadcast WebSocket (thao tác
`await` DUY NHẤT thật sự cần vòng lặp sự kiện). Cũng tăng `pool_size`/`max_overflow` của SQLAlchemy (mặc định 5+10 —
không đủ khi nhiều pipeline nền cần vài kết nối ngắn cùng lúc) lên 20+20 (`app/database.py`). Sau hai thay đổi này, tải
20 đồng thời KHÔNG CÒN timeout (bảng trên) — nhưng độ trễ vẫn tăng mạnh so với tuần tự.

⚠️ **Còn lại sau khi sửa (ngoài phạm vi MR12, để lại cho việc tối ưu sau):** độ trễ dưới tải vẫn cao (median ~3,6 giây
ở 20 đồng thời) — nghi hai nguyên nhân, CHƯA cô lập rạch ròi được nguyên nhân nào chiếm bao nhiêu: (1) bcrypt (Tuần 5:
~227 ms, thuần CPU) giữ GIL của Python khi băm mật khẩu, nên nhiều request đồng thời không thật sự chạy song song trên
CPU dù có nhiều luồng; (2) mỗi lần chấm cần khoảng 5-10 lượt round-trip DB (lịch sử tài khoản, đặc trưng RBA, ghi
alert/response_action/audit_log) — dưới tải, các lượt này CÓ THỂ xếp hàng chờ dù đã tăng pool. Từng thử nới thêm
executor mặc định của `asyncio.to_thread` (64 luồng) nhưng đo lại KHÔNG thấy cải thiện rõ (có lần còn chậm hơn) nên
đã bỏ thay đổi đó — giữ đúng những gì đo được là có lợi thật (tách thread + tăng pool DB), không giữ lại thay đổi
chưa chứng minh được ích lợi.

## 4. Trôi đặc trưng (PSI) — `ml/rba/drift.py`

`python -m ml.rba.drift`: PSI của 50 đặc trưng RBA, so **tham chiếu** (phân vùng `train` của RBA, 1.139.727 dòng — đúng
phân phối `hybrid_cp2` được huấn luyện) với **hiện tại** (đặc trưng tính lại từ CHÍNH pipeline realtime,
`compute_rba_features`, trên toàn bộ `login_events` thật `is_synthetic=False`, 1.576 dòng tại thời điểm viết tài liệu
này — gồm cả dữ liệu demo có sẵn và các lần đăng nhập thử/đo tải trong phiên làm việc này).

**Kết quả trung thực: phần lớn đặc trưng "trôi đáng kể" (PSI > 1, có đặc trưng > 8)** — bảng đầy đủ ở
`backend/ml/artifacts/drift/report.txt` (không commit — sinh lại bằng `python -m ml.rba.drift > ml/artifacts/drift/report.txt`).
Không bất ngờ và không phải lỗi: web app mẫu có quy mô hoàn toàn khác RBA (66 user demo so với hàng triệu, số ASN/quốc
gia khác nhau xuất hiện đếm được trên đầu ngón tay so với hàng chục nghìn) — các đặc trưng "độ hiếm" (`rare_*`, `llr_*`,
dựa trên `-log(xác suất)` ước lượng từ TẦN SUẤT toàn cục) LUÔN trôi mạnh khi quy mô dân số khác nhau hàng nghìn lần,
bất kể mô hình có "đúng" hay không. Ngược lại, các cờ nhị phân (`new_*`) hoàn toàn ổn định (PSI = 0,000) vì ý nghĩa
của chúng (mới/không mới) không phụ thuộc quy mô dân số.

**Kết luận cho việc dùng `hybrid_cp2` trên dữ liệu thật:** điểm ML tính từ `login_events` hiện tại KHÔNG được xem là
đã hiệu chỉnh đúng cho quy mô dân số nhỏ này — đây là lý do chính hồ sơ MR11 (`docs/hybrid-risk-engine.md`) đã tự nhận
"chưa chuyển miền sang live". Khắc phục đúng cách (hiệu chỉnh lại `MonotonicCalibrator` trên chính phân phối
`login_events`, hoặc chờ đủ dữ liệu thật tích luỹ) nằm ngoài phạm vi MR12; công cụ (`ml.rba.drift`) đã sẵn sàng để
theo dõi định kỳ khi dữ liệu thật tăng lên.

## 5. Giới hạn đã biết (đọc trước khi trình bày)

- **`response_actions`/`blocklist_hit` chỉ là ĐỀ XUẤT** — chưa có gì thực sự khoá tài khoản hay từ chối đăng nhập
  (`status='recommended'` luôn, không có luồng MFA ở web app mẫu). Thực thi thật là việc của MR16, đúng như luật
  `blocklist_hit` (MR9) đã ghi chú từ đầu.
- **Lịch sử tài khoản/thống kê ASN dựng lại từ DB mỗi lần** (không giữ trạng thái tiến trình) — đúng dù restart/nhiều
  worker, nhưng có 2 cache TTL ngắn (đếm toàn cục RBA 30 giây, blocklist 15 giây) nên có độ trễ nhỏ giữa lúc dữ liệu
  đổi và lúc pipeline thấy — chấp nhận được cho quy mô hiện tại, ghi rõ trong docstring từng module.
  Con số nghi vấn của độ trễ: một số truy vấn (đếm toàn cục) quét TOÀN BẢNG `login_events`, không nhắm chỉ mục — với
  bảng lớn hơn nhiều cần thay bằng bộ đếm tăng dần lưu riêng, ngoài phạm vi MR12 (demo hiện có vài nghìn dòng, đủ
  nhanh — xem mục 3.1).
- **PSI cho biết trôi RẤT NHIỀU (mục 4)** — điểm ML trên dữ liệu thật chưa được hiệu chỉnh đúng quy mô, chỉ nên đọc
  điểm hybrid hiện tại như MỘT TÍN HIỆU THAM KHẢO thêm (cùng vai trò với `ml_anomaly_score` của tầng 3 cũ), không phải
  con số đã kiểm định trên chính dữ liệu thật.
- **Độ trễ dưới tải đồng thời cao vẫn còn** sau khi sửa lỗi chặn vòng lặp sự kiện (mục 3.2) — nghi bcrypt (GIL) và số
  lượt round-trip DB mỗi lần chấm; chưa cô lập rạch ròi, để lại cho việc tối ưu sau nếu cần mở rộng tải thật.
- **Migration đã chạy thật** lên Postgres dev (`alembic upgrade head`, revision `e1318f3ac8e5`) — xác nhận bằng truy
  vấn `information_schema` trực tiếp, không chỉ đọc file migration.
