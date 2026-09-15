# Đo & tối ưu tốc độ POST /login (nhiệm vụ 5.2)

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
