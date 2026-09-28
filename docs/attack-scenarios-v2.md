# Thư viện tấn công mô phỏng v2 — scorecard (MR18)

9 kịch bản mới, mỗi kịch bản hiệu chỉnh có chủ đích để vượt hẳn ngưỡng THẬT của một luật cụ thể (`docs/rule-catalog.md`), chạy qua CHÍNH pipeline thật (rule engine v2 + hybrid risk engine, model `hybrid_cp2` thật) — mã nguồn: [`ml/attack_scenarios.py`](../backend/ml/attack_scenarios.py) (đặc tả) + [`scripts/attack_scenario_runner.py`](../backend/scripts/attack_scenario_runner.py) (chạy + đo). Mỗi kịch bản chạy **đúng 1 lần** (không phải nhiều 'trial' — xem docstring runner: các kịch bản xác định, không có nguồn ngẫu nhiên nào để lấy trung bình một cách có ý nghĩa).

## Kết quả chính

- **7/8** kịch bản được kỳ vọng phát hiện được đã thực sự có alert.
- ⚠️ **Bỏ sót NGOÀI dự kiến** (đáng chú ý, không phải kịch bản `targeted_mimic` cố ý khó): Dò danh sách tài khoản.

## Scorecard

| Kịch bản | Luật nhắm tới | Phát hiện? | Bước phát hiện | Số alert | Cơ chế |
|---|---|---|---|---|---|
| Rải mật khẩu chậm | `password_spray_slow` | ✅ | 1/18 | 18 | ml_anomaly |
| Botnet phân tán vào một tài khoản | `distributed_bruteforce` | ✅ | 1/8 | 11 | impossible_travel; ml_anomaly |
| Proxy cùng quốc gia, khác nhà mạng | `rare_network_login` | ✅ | 1/1 | 1 | ml_anomaly |
| Xoay User-Agent | `ua_rotation` | ✅ | 1/9 | 19 | brute_force; high_risk_score; ml_anomaly |
| Tài khoản ngủ đông đăng nhập lại | `dormant_account_login` | ✅ | 1/1 | 2 | hybrid_risk (rule=datacenter_ip); ml_anomaly |
| Mô phỏng tinh vi (Targeted mimic) | `hybrid_ml` | ✅ | 1/1 | 2 | hybrid_risk (chỉ ML, không luật nào khớp); ml_anomaly |
| Dò danh sách tài khoản | `username_enumeration` | ❌ | — | 0 | — |
| Nhồi thông tin đăng nhập quy mô lớn | `credential_stuffing` | ✅ | 10/16 | 13 | credential_stuffing; hybrid_risk (rule=credential_stuffing) |
| Di chuyển bất khả thi | `impossible_travel` | ✅ | 1/2 | 4 | hybrid_risk (rule=impossible_travel); impossible_travel; ml_anomaly |

## Diễn giải

- "Bước phát hiện" là vị trí (1-based) trong CHUỖI TẤN CÔNG (không tính các lần đăng nhập nền thiết lập lịch sử quen thuộc trước đó) mà lần ĐẦU TIÊN xuất hiện alert — không phải "giây" vì tốc độ demo không phản ánh tốc độ tấn công thật.
- ⚠️ **`ml_anomaly` (tầng 3, Tuần 7) gần như LUÔN xuất hiện, kể cả khi đăng nhập KHỚP HỆT thói quen đã thiết lập** — xác nhận trực tiếp bằng đối chứng riêng (tài khoản có 10-35 lần đăng nhập baseline giống hệt nhau, lần tiếp theo CÙNG IP/UA/giờ vẫn bị báo). Mô hình tầng 3 huấn luyện TOÀN CỤC trên user101-140 (`ml/generate_dataset.py`), không huấn luyện lại riêng cho từng tài khoản mới trong kịch bản — một tài khoản hoàn toàn mới có thể tự nhiên "trông lạ" so với phân bố đã học dù hành vi nội tại nhất quán. Vì vậy cột "Cơ chế" ở trên KHÔNG coi `ml_anomaly` là bằng chứng phát hiện ĐÚNG KIỂU tấn công — chỉ các cơ chế CÒN LẠI (luật tầng 1/2 cụ thể, `hybrid_risk` có `rule=`) mới phản ánh tín hiệu THỰC SỰ đặc trưng cho kịch bản. Đây là đặc tính đã biết của tầng 3 (ngoài phạm vi sửa của MR18 — sửa được cần huấn luyện lại/hiệu chỉnh lại ngưỡng, việc của MR6/Tuần 7), không phải bug.
- ⚠️ **Bug thật tự phát hiện khi dựng baseline cho kịch bản**: chèn lịch sử "quen thuộc" bằng cách ghi thẳng `LoginEvent` (không qua pipeline) mà QUÊN tính `device_fingerprint`/GeoIP (`country`/`city`/`latitude`/`longitude`) — giống HỆT cách `scripts/alert_intelligence_sim.py::_seed_history` (MR13) làm — khiến MỌI dòng baseline trông "chưa từng thấy thiết bị/vị trí này" dù được lặp lại hàng chục lần, làm sai lệch `is_new_device`/`is_new_location` (tầng 3) một cách có hệ thống. Đã sửa trong `_insert_baseline()` (tính GeoIP + `compute_device_fingerprint` THẬT, y hệt pipeline sống sẽ làm) — CHƯA sửa ngược lại `alert_intelligence_sim.py` (ngoài phạm vi MR18, để lại ghi chú cho lần sau).
- **`rare_network_login` một mình KHÔNG đủ để tạo alert** (trả lời câu hỏi để ngỏ ở `docs/rule-catalog.md` — "giá trị thật đo bằng kịch bản mô phỏng ở MR18"): kịch bản `same_country_proxy` (cùng nước, cùng thiết bị, CHỈ đổi ASN) chỉ còn `ml_anomaly` (xem caveat trên) — trọng số hiệu chỉnh của `rare_network_login` (2,6%, `app/detection/hybrid/profiles/rba_calibrated.json`) một mình không đủ vượt ngưỡng `alert_at=32`. Rule ở chế độ `shadow` là hợp lý: một tín hiệu yếu, cần corroborate bởi tín hiệu khác mới đáng báo.
- **`distributed_bruteforce` được hiệu chỉnh với trọng số 0,0** (mẫu val chỉ 2 dòng — `rba_calibrated.json`), nghĩa là rule này KHÔNG ĐÓNG GÓP GÌ cho điểm hybrid dù khớp rõ ràng. Kịch bản `distributed_botnet` vẫn được phát hiện — nhưng qua `impossible_travel` (tầng 1), một hệ quả CỦA VIỆC chọn IP botnet cách xa nhau về địa lý, KHÔNG PHẢI vì `distributed_bruteforce` được nhận diện. Một botnet dùng hạ tầng CÙNG khu vực địa lý (vẫn nhiều IP/ASN khác nhau nhưng không kích hoạt di chuyển bất khả thi) nhiều khả năng sẽ KHÔNG bị bắt qua đường này — chưa kiểm chứng trực tiếp (xem Giới hạn).
- **`username_enumeration` (weight mặc định 0,05, chưa hiệu chỉnh) không tạo alert nào** dù vượt hẳn ngưỡng riêng của rule (10 tên >> 8) — không có luật tầng 1 nào dự phòng cho việc dò danh sách tài khoản (khác `impossible_travel`/`brute_force`/`credential_stuffing`, đều có bản gốc tầng 1). Đây là BỎ SÓT THẬT, đáng để ý khi ưu tiên hiệu chỉnh lại rule ở các MR sau.
- `targeted_mimic` CỐ Ý thiết kế khó (không luật enforce nào có lý do khớp, chỉ còn tín hiệu ML yếu) — đây là kịch bản "ML dẫn đầu" mà MR13 (`scripts/alert_intelligence_sim.py`) đã để ngỏ cho MR18. Bị gắn cờ (qua `ml_anomaly`/`hybrid_risk` chỉ ML) — nhưng xem caveat `ml_anomaly` ở trên: KHÔNG thể khẳng định chắc đây là phát hiện ĐÚNG kiểu mô phỏng tinh vi, hay lại là hiệu ứng tài khoản mới. Kết quả mơ hồ này TỰ NÓ là một phát hiện trung thực đáng ghi nhận, không phải một câu trả lời gọn gàng.

## Giới hạn

- Mỗi kịch bản chạy 1 lần với tham số đã hiệu chỉnh để vượt HẲN ngưỡng (không sát ngưỡng) — KHÔNG đo được độ NHẠY ở biên (vd `password_spray_slow` với đúng 15 tài khoản thay vì 18 có còn bắt được không).
- Chưa kiểm chứng biến thể "botnet CÙNG khu vực địa lý" cho `distributed_botnet` (xem Diễn giải) — nghi ngờ có căn cứ (trọng số 0,0 + không có rule dự phòng) nhưng chưa đo trực tiếp bằng một kịch bản chính thức.
- `ml_anomaly` (tầng 3) báo động gần như luôn luôn cho tài khoản MỚI bất kể có tấn công hay không (xem Diễn giải) — làm giảm giá trị của cột "Cơ chế" cho những kịch bản CHỈ có `ml_anomaly`; cần tài khoản có lịch sử SÂU hơn (bằng hoặc hơn phạm vi huấn luyện tầng 3, 30-55 lần/user) hoặc hiệu chỉnh lại ngưỡng tầng 3 mới đo được chính xác — ngoài phạm vi MR18.
- IP CÔNG KHAI THẬT nhưng KHÔNG PHẢI hạ tầng tấn công thật — GeoIP/ASN thật, hành vi tấn công là dàn dựng.
- Không đo trên nhiều tài khoản nạn nhân/hồ sơ lịch sử khác nhau cho mỗi kịch bản — 1 nạn nhân mẫu/kịch bản.
- Dùng làm dữ liệu cho "mô hình B" (địa lý-thời gian): xem mục riêng trong [`docs/model-b-geo-time.md`](model-b-geo-time.md).
