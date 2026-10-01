# Đo & tối ưu tốc độ POST /login (nhiệm vụ 5.2)

> ⚠️ **Cập nhật MR19 (28/09/2026):** số ở mục "Phương pháp/Kết quả" gốc bên dưới là của **Tuần 5** (chỉ tầng 1-2, chưa
> có rule engine v2/hybrid ML/MR16). Số hiện tại — **chậm hơn đáng kể** — và phân tích nguyên nhân ở mục
> "Đo lại sau MR9-18" cuối tài liệu.

## Phương pháp

`backend/scripts/benchmark_login.py` — 50 request tuần tự tới `POST /login`
trên cùng máy (`localhost`), dùng tài khoản `alice`. Đo **trước** khi tối
ưu bằng cách `git stash` tạm quay lại code cuối Tuần 4 (detection engine
chạy đồng bộ, chặn response), rồi `git stash pop` để đo **sau** khi tối ưu
(detection engine chạy nền qua `BackgroundTasks`).

## Kết quả

| | min | avg | median | p95 | max |
|---|---|---|---|---|---|
| **Trước** (Tuần 4, đồng bộ) | 242.2 ms | 289.8 ms | 247.6 ms | 258.8 ms | 2328.5 ms |
| **Sau** (Tuần 5, `BackgroundTasks`) | 248.9 ms | 303.4 ms | 260.3 ms | 282.6 ms | 2337.6 ms |

**Không cải thiện đáng kể — kết quả thật, không chỉnh sửa.** Lý do:

1. **bcrypt chiếm gần hết thời gian phản hồi.** Đo riêng `verify_password()`:

   ```
   bcrypt.checkpw đơn lẻ: min=221.5ms avg=226.8ms max=237.1ms
   ```

   Với cost factor mặc định (12 rounds — cố ý chậm để chống brute force),
   một lần `bcrypt.checkpw()` đã chiếm ~227ms trong tổng ~250-260ms median
   của cả request. Phần detection engine (GeoIP + Redis + vài query DB) mà
   Tuần 4 làm đồng bộ chỉ chiếm phần chênh lệch còn lại (~20-60ms) — dời nó
   ra nền không thể cải thiện quá phần đó.

2. **Benchmark tuần tự trên 1 kết nối HTTP keep-alive** không đo được lợi
   ích thật của `BackgroundTasks`. Lợi ích chính của việc tách detection ra
   nền là **throughput khi có nhiều request đồng thời** (server rảnh tay xử
   lý request tiếp theo trong lúc detection của request trước chạy nền),
   không phải độ trễ của từng request đơn lẻ trên cùng 1 kết nối tuần tự —
   đây là hạn chế của phương pháp đo, không phải tối ưu vô nghĩa.

## Kết luận & khuyến nghị

- Việc dời detection engine ra `BackgroundTasks` (xem
  [`backend/app/detection/pipeline.py`](../backend/app/detection/pipeline.py))
  **vẫn đúng về mặt kiến trúc** — response không còn phụ thuộc vào số bước
  DB/Redis mà detection engine cần (quan trọng nếu sau này detection nặng
  hơn, ví dụ gọi GeoIP qua mạng thay vì file cục bộ, hoặc thêm tầng ML ở
  Tuần 7 chạy chậm hơn nhiều).
- **Ngưỡng "dưới 300ms" (docs/api-contract.md mục 6) khó đạt được** với
  bcrypt cost factor mặc định — đây là đánh đổi cố ý giữa bảo mật (chống
  brute force offline nếu DB bị lộ) và độ trễ. Không hạ cost factor vì đó
  sẽ làm yếu khả năng chống brute force của chính hash — nếu hội đồng hỏi,
  đây là câu trả lời: "chấp nhận ~250-300ms vì đó là chi phí bảo mật của
  bcrypt, không phải lỗi hiệu năng chưa tối ưu."
- Cache GeoIP (`app/detection/geoip.py`) vẫn giữ lại vì có giá trị khi
  chuyển sang provider GeoIP qua mạng trong tương lai, dù hiện tại
  `geoip2.Reader` đọc file cục bộ đã rất nhanh nên không đo được khác biệt.

## Kiểm tra không hồi quy

Toàn bộ 44 unit test (bao gồm rule-based Tuần 3, scoring Tuần 4) vẫn pass
sau khi tái cấu trúc sang `BackgroundTasks` — không có test nào fail thêm
so với trước khi tối ưu.

## Đo lại sau MR9-18 (MR19)

**Đo thật, `scripts/benchmark_login.py` không đổi tham số đo (vẫn tài khoản `alice`), backend/Postgres/Redis dev thật
đang chạy, không có tải nào khác đồng thời (ngoài chính benchmark):**

| Kịch bản | min | avg | median | p95 | p99 / max |
|---|---|---|---|---|---|
| Tuần 5 (gốc, chỉ tầng 1-2) | 242,2 ms | 289,8 ms | 247,6 ms | 258,8 ms | 2328,5 ms |
| **MR19, tuần tự, n=50** | 541,4 ms | 646,1 ms | **614,4 ms** | 669,0 ms | 2809,8 ms |
| **MR19, 3 request đồng thời, n=20** | 705,3 ms | 1373,8 ms | **1061,5 ms** | 3742,1 ms | 3742,1 ms |

`--concurrency 10` (n=100) **timeout thật** (`httpx.ReadTimeout`, giới hạn mặc định 10s của script) — không hoàn
thành được, không phải số bị làm tròn hay bỏ qua.

**Không cải thiện — chậm đi rõ rệt, kết quả thật, không chỉnh sửa cho đẹp.** Đọc mã nguồn xác nhận (không chỉ suy
đoán) hai nguyên nhân cụ thể ở [`rba_live_features.py`](../backend/app/detection/rba_live_features.py):

1. **`_user_events()` (dòng 62-64) lấy TOÀN BỘ lịch sử đăng nhập của tài khoản, không giới hạn số dòng** — tài khoản
   `alice` dùng làm chuẩn benchmark từ Tuần 5 đã tích luỹ **1.422 dòng** (đếm trực tiếp trong Postgres dev lúc viết
   tài liệu này) sau 8 tuần bị dùng lại liên tục để test/demo/benchmark qua toàn bộ MR1-19 — CHÍNH benchmark này mỗi
   lần chạy lại làm `alice` có thêm N dòng, nên lần chạy SAU luôn có xu hướng chậm hơn lần chạy TRƯỚC một chút (hiệu
   ứng tự cộng dồn, không phải nhiễu đo). Với tài khoản mới (0 lịch sử), truy vấn này rẻ; **độ trễ không bị chặn trên
   theo số lần đăng nhập của một tài khoản** — đây là rủi ro mở rộng thật cho một tài khoản dùng lâu năm.
2. **Truy vấn đếm toàn cục cho đặc trưng độ hiếm (`GlobalCountsCache`, dòng ~115) quét TOÀN BẢNG `login_events`**
   (mọi đăng nhập thành công, mọi tài khoản) mỗi khi cache (TTL 30 giây) hết hạn — **không có khoá (`Lock`) chống
   nhiều request cùng lúc cùng làm mới cache**: nếu ≥ 2 request đến đúng lúc cache vừa hết hạn, CẢ HAI đều tự quét lại
   toàn bảng thay vì một request quét, còn lại chờ — khớp với việc độ trễ ở `--concurrency 3` tệ hơn nhiều so với tỉ
   lệ tuyến tính từ số tuần tự (median tăng 73% chỉ với 3 request đồng thời, p95 tăng gần 6 lần).

⚠️ **Chưa profiling để tách chính xác bao nhiêu % do nguyên nhân (1) so với (2)** so với chi phí cố định của
`hybrid_cp2.predict()` (LightGBM + Isolation Forest trên 50 đặc trưng) hay chi phí đồng bộ hoá MR16 thêm cho lần thử
ĐÚNG mật khẩu (docs/api-contract.md ước lượng ~140ms trung vị, đo riêng, không cộng dồn được trực tiếp vào bảng
trên vì đo trên baseline khác) — đây là **hai nguyên nhân xác nhận được qua đọc mã nguồn**, không phải toàn bộ bức
tranh. `run_detection_pipeline` (MR12, `pipeline.py` dòng 516) đã đúng đắn dùng `asyncio.to_thread` nên KHÔNG chặn
event loop — tình trạng chậm ở đây là chi phí DB/CPU thật của từng thread, không phải lỗi kiến trúc async.

**Khuyến nghị (chưa làm, ngoài phạm vi MR19):** giới hạn `_user_events` theo cửa sổ thời gian hoặc số dòng gần nhất
(đã có tiền lệ — `_ip_events`/`_asn_events` cùng file đã giới hạn 24 giờ); thêm khoá hoặc "single-flight" cho
`GlobalCountsCache` khi cache miss; xem xét benchmark bằng tài khoản MỚI mỗi lần chạy thay vì tái sử dụng `alice` để
số đo không tự phình theo thời gian.

## MR20 — đo từng bước, tìm nguyên nhân thật, sửa

⚠️ **Đính chính MR19.** MR19 nêu hai nguyên nhân "xác nhận qua đọc mã nguồn" nhưng chưa đo tách riêng (đã ghi rõ ở
trên). MR20 đo từng bước trên Postgres 16 + Redis thật và thấy: **(1) `_user_events` KHÔNG phải nguyên nhân chính**, (2)
`GlobalCountsCache` là nguyên nhân thật nhưng chỉ khi cache hết hạn, và (3) **nguyên nhân lớn nhất chưa từng được nêu**:
route `POST /login` là `async def` nhưng gọi `bcrypt.checkpw` (~280 ms CPU) **thẳng trên event loop** — câu "kiến trúc
async đúng đắn, KHÔNG chặn event loop" ở MR19 chỉ đúng cho pipeline (`asyncio.to_thread`), SAI cho chính route đăng nhập.

**Môi trường đo:** container Linux 4 CPU (không phải máy dev Windows của MR19 — số tuyệt đối không so trực tiếp được với
bảng MR19, chỉ so trước/sau trên CÙNG máy). Dữ liệu: 50.000 đăng nhập của 200 tài khoản + `alice` 1.422 dòng (đúng số
MR19 đếm được), IP gần như duy nhất mỗi dòng (trường hợp xấu nhất cho `GROUP BY ip`). Chưa có artifact `hybrid_cp2`
(không commit, xem `.gitignore`) nên thành phần ML của hybrid tắt — 50 đặc trưng RBA vẫn được TÍNH đầy đủ, chỉ không
`predict()`; chi phí `predict()` không có trong số đo dưới đây.

### Đo từng truy vấn (`build_history_summary`)

| Bước | 5.000 dòng | 50.000 dòng |
|---|---|---|
| `_user_events` (alice, 1.422 dòng) | 15,0 ms | 14,0 ms |
| `_ip_events` / `_ip_prior_attempts_all` | < 1 ms | < 1 ms |
| `_asn_events` (24 giờ) | 1,9 ms | 6,7 ms |
| `GlobalCountsCache._compute` (khi hết hạn) — **trước** | 71,6 ms | **583,5 ms** |
| `GlobalCountsCache._compute` (khi hết hạn) — **sau** (`GROUP BY`) | 44,1 ms | **165,1 ms** |
| `features_from_summary` (Python) | 3,9 ms | 4,2 ms |

`_user_events` tăng tuyến tính theo lịch sử MỘT tài khoản nhưng ở 1.422 dòng chỉ ~15 ms trên tổng ~350 ms — **không sửa**
ở MR20. Lý do không cắt theo cửa sổ thời gian như MR19 đề xuất: 20 đặc trưng (`u_n_attempts`, `u_n_success`, `new_*`,
`llr_*`, `u_age_days`, `u_fail_streak`) định nghĩa trên TOÀN BỘ lịch sử lúc huấn luyện — cắt bớt sẽ làm lệch đặc trưng
giữa huấn luyện và chạy thật (training/serving skew), đúng loại lỗi không thấy được qua test. Nếu cần sau này: tính các
tổng đó bằng truy vấn gộp trong DB, giữ nguyên giá trị.

### Toàn bộ request (`scripts/benchmark_login.py`, uvicorn thật, cùng dữ liệu, trước/sau trên cùng máy)

| | tuần tự (n=50) | 3 đồng thời (n=30) | 10 đồng thời (n=100) |
|---|---|---|---|
| **Trước MR20** — median / p95 | 347 / 446 ms | 861 / 1.184 ms | 2.820 / 4.928 ms |
| **Sau MR20** — median / p95 | 364 / 510 ms | **433 / 528 ms** | **963 / 1.375 ms** |

Tuần tự không đổi (đúng dự đoán): một request đơn lẻ vẫn là bcrypt (279 ms đo riêng) + pipeline (~55 ms, đo bằng
`app/detection/perf.py`). Khác biệt nằm ở tải đồng thời: trước MR20 mọi request — kể cả dashboard, WebSocket — phải xếp
hàng sau MỖI lần băm bcrypt trên event loop duy nhất (độ trễ tăng gần tuyến tính theo số request đồng thời); sau MR20
bcrypt chạy trong thread (thư viện `bcrypt` nhả GIL khi băm) nên 4 CPU băm song song thật. Ở đây `--concurrency 10`
không timeout cả trước lẫn sau (MR19 timeout trên máy dev chậm hơn) — không khẳng định MR20 "sửa" timeout đó khi chưa đo
lại trên chính máy đó.

### Đã sửa

1. **bcrypt khỏi event loop** — `app/routers/auth.py`: `verify_password` và `hash_otp_code` (bcrypt, nhánh OTP của
   MR16) chạy qua `asyncio.to_thread`. Test: `tests/test_auth.py::test_password_check_runs_off_the_event_loop` (fail
   trước khi sửa).
2. **`GlobalCountsCache`** — đếm bằng `GROUP BY` trong DB (chỉ các giá trị khác nhau đi qua mạng, khoá đếm vẫn đi qua
   CHÍNH `attr_key` của đặc tả MR3); khoá "single-flight": nhiều thread cùng gặp cache hết hạn thì chỉ một thread tính
   lại. Test: kết quả giống hệt `GlobalCounts.from_events` (kể cả cột NULL), 8 thread đồng thời → đúng 1 lần tính (trước
   khi sửa: 8).
3. **`DbGlobalStats`** (luật `rare_network_login`) — **lỗi đúng/sai, không chỉ hiệu năng**: thiếu điều kiện
   `created_at < before`, nên lần thử đang chấm (đã `flush`) bị đếm luôn → ASN chưa từng thấy vẫn ra 1 lần, `never_seen`
   không bao giờ đúng ở luồng thật. Thêm `before`; đếm bằng `count(*)` trong DB thay vì kéo cột ASN mọi dòng về Python
   cho mỗi lần đăng nhập thành công (cache TTL theo instance cũ không bao giờ trúng vì instance dựng mới mỗi lần). Luật
   mặc định ở chế độ `shadow` và cần ≥ 20.000 lượt thành công nên lỗi chưa từng ảnh hưởng quyết định thật trong demo.
4. **Mốc "chưa cache" `-1.0` so với `time.monotonic()`** (blocklist, cấu hình luật, drift) — `monotonic()` trên Linux
   đếm từ lúc máy khởi động; trong TTL giây đầu sau boot `now - (-1.0) < TTL` nên `invalidate_*` không có tác dụng —
   cả mục chặn admin vừa thêm (`routers/blocklist.py`) lẫn **khoá tự động của MR16** (`pipeline.py` gọi
   `invalidate_blocklist_cache()` để lần thử NGAY SAU bị chặn) đều bị bỏ qua tới 15 giây. Đổi sang `-math.inf`. Phát hiện vì chính bộ test fail trên container mới
   bật — trên máy dev chạy lâu ngày không bao giờ lộ ra.

### Còn lại (chưa làm)

- Truy vấn DB đồng bộ khác trong `async def login` (tra blocklist khi cache hết hạn, tra user, commit) vẫn chạy trên event
  loop — mỗi cái vài ms, nhỏ so với bcrypt; cách triệt để là chuyển cả route sang `def` (FastAPI tự chạy trong threadpool)
  hoặc session async.
- **Lộ tài khoản có tồn tại qua thời gian phản hồi**: tên không tồn tại bỏ qua bcrypt nên trả 401 nhanh hơn ~280 ms so
  với sai mật khẩu, dù nội dung 401 giống hệt nhau (`docs/api-contract.md` mục 3 chỉ cam kết nội dung). Sửa bằng băm
  giả với một hash cố định cho tên không tồn tại — đổi lại tốn CPU cho mọi lần credential stuffing vào tên không có thật;
  cần chủ dự án quyết.
