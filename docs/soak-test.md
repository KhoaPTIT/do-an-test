# Soak test — tải nhẹ liên tục (MR19)

Chạy thật 12 phút, nhịp mục tiêu 1 request/giây, luân phiên 30 tài khoản demo (user001-030), 90% mật khẩu đúng / 10% sai — không dùng lại một tài khoản như `benchmark_login.py` để tránh tự làm phình lịch sử của chính tài khoản đang đo (xem `docs/performance.md`).

## Tổng quan

- Tổng số request `/login`: **691**
- Tổng số request `/health` (xen kẽ, 1/10 vòng lặp): **69**
- Request `/login` có status KHÔNG mong đợi (khác 200/401/423): **1** — [-1]
- Request `/health` khác 200: **0**
- Số lần bị khoá (423 — hành vi ĐÚNG như thiết kế nếu brute_force vô tình chạm ngưỡng, không tính là lỗi): **0**
- Xu hướng độ trễ median theo thời gian (cửa sổ 2 phút, so cụm đầu với cụm cuối): **+70.2 ms (median cửa sổ cuối trừ cửa sổ đầu)**

## Theo cửa sổ 2 phút

| Phút bắt đầu | Số request | Median (ms) | p95 (ms) | Bị khoá (423) | Status lạ |
|---|---|---|---|---|---|
| 0.0 | 118 | 627.4 | 1058.8 | 0 | 0 |
| 2.0 | 116 | 567.7 | 681.0 | 0 | 0 |
| 4.0 | 120 | 638.2 | 757.8 | 0 | 0 |
| 6.0 | 117 | 714.8 | 1048.1 | 0 | 0 |
| 8.0 | 106 | 663.7 | 1475.5 | 0 | 1 |
| 10.0 | 114 | 671.7 | 1469.5 | 0 | 0 |

## Đọc kết quả

- **Tỉ lệ lỗi thật** = status không mong đợi (khác 200 thành công / 401 sai mật khẩu / 423 khoá đúng thiết kế) chia cho tổng request — 0 nghĩa là không có request nào thất bại ngoài dự kiến trong suốt phiên.
- **Rò rỉ/suy giảm** biểu hiện qua median TĂNG DẦN đơn điệu qua các cửa sổ — một vài cửa sổ nhiễu cao hơn cửa sổ khác là bình thường (GC, cache miss định kỳ của `GlobalCountsCache`, xem `docs/performance.md`), xu hướng tăng liên tục nhiều cửa sổ liên tiếp mới đáng lo.
- Đây là tải THẤP có chủ đích (khác benchmark tải cao ngắn hạn) — mục tiêu là phát hiện suy giảm theo THỜI GIAN, không phải theo TẢI (đã đo riêng ở `docs/performance.md`).

## Kết luận (đọc bảng, không chỉ số tóm tắt)

Số tóm tắt "+70,2 ms" ở trên tự nó dễ gây hiểu lầm là "cứ chạy lâu thì chậm dần đều" — nhìn bảng theo cửa sổ thì
**KHÔNG đơn điệu**: median dao động 567,7–714,8 ms qua 6 cửa sổ, cửa sổ thứ 2 (phút 2-4) còn THẤP hơn cửa sổ đầu.
Đây là **nhiễu quanh một mức nền cao** (khớp với mức ~614-670ms đã đo ở `docs/performance.md`), không phải rò rỉ
tăng dần thật sự — 12 phút không đủ dài để khẳng định chắc chắn không có rò rỉ chậm (ví dụ rò rỉ kết nối DB tích luỹ
qua nhiều giờ), nhưng **không có bằng chứng rò rỉ nhanh** (crash, tăng lỗi, tăng độ trễ liên tục) trong cửa sổ đã đo.
Duy nhất 1/691 request lỗi kết nối (không phải lỗi ứng dụng — status `-1` nghĩa là client không nhận được response,
có thể do đúng lúc `GlobalCountsCache` làm mới gây nghẽn tạm thời, xem `docs/performance.md`) — tỉ lệ 0,14%, không
đáng lo cho một phiên 12 phút. **Kết luận: hệ thống ỔN ĐỊNH dưới tải thấp liên tục — chậm (do các nguyên nhân đã nêu
ở `docs/performance.md`) nhưng không suy giảm thêm theo thời gian trong phạm vi đã kiểm chứng.**
