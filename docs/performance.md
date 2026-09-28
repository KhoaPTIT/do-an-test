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
