# Dashboard v2 (MR17)

Bốn mảng của checklist: hồ sơ rủi ro theo user, trang chiến dịch/hiệu năng rule-ML/sức khoẻ model, chỉnh ngưỡng +
bật/tắt rule từ giao diện admin, bộ lọc mở rộng + kiểm thử responsive. Không phải một mô phỏng đo độ chính xác như
MR13-16 — tài liệu này ghi lại 2 phát hiện kỹ thuật thật gặp khi xây, không phải số đo ML.

## 1. Rule config chưa từng được nối vào luồng thật (phát hiện, không phải bug mới gây ra)

Trước MR17, `app/detection/pipeline.py` gọi `build_rule_engine(db, before=...)` **không truyền `config`** — tương
đương `RuleConfig()` rỗng, tức là **mọi lần đăng nhập thật LUÔN chấm bằng mặc định của sổ đăng ký**
(`app/detection/engine/registry.py`), bất kể `RuleConfig` (JSON file) đã tồn tại từ MR9 để hiệu chỉnh/replay ngoại
tuyến (MR9, MR10). Không có đường nào — kể cả thủ công — ghi đè được hành vi của `/login` thật.

MR17 thêm bảng `rule_overrides` (DB, không phải file — nhất quán với `blocklist`/`user_risk_profiles`) và
`app/detection/rule_engine_runtime.refresh_rule_config()` (cache TTL 15s, cùng cơ chế `refresh_blocklist`), gọi ngay
trong `build_rule_engine()` khi không có `config` truyền tay — **đây là lần ĐẦU TIÊN** ghi đè của quản trị viên thật
sự có tác dụng lên `/login`. Xác nhận bằng test gọi thẳng `build_rule_engine(db_session)` sau khi ghi một
`RuleOverride` — `tests/test_rules_router.py::test_live_pipeline_now_respects_a_rule_override_that_used_to_be_ignored`.

## 2. `GET /model-health` — độ trễ đo được và cách khống chế

Tính PSI cần (a) đọc file parquet train RBA MỘT LẦN (~1,8 giây cho 1.139.727 dòng, cache VĨNH VIỄN trong tiến trình —
không đổi khi server đang chạy) và (b) tính lại đặc trưng RBA cho MỖI dòng `login_events` thật hiện tại bằng CHÍNH
`compute_rba_features` của pipeline (vài lượt round-trip DB/dòng, xem `docs/realtime-integration.md`).

Đo trực tiếp lúc dựng MR17 trên DB dev (1.576 dòng thật tích luỹ qua nhiều MR trước): **request đầu tiên treo hơn 30
giây** — không chấp nhận được cho một trang admin đang chờ tải. Khống chế bằng `CURRENT_ROWS_LIMIT = 300` (lấy 300
dòng **GẦN NHẤT**, không phải 300 dòng đầu) ở `app/routers/model_health.py` — sau khi giới hạn, cùng phép đo còn
**~2 giây**. Script CLI (`python -m ml.rba.drift`, chạy tay, người dùng chủ động chờ) **không bị giới hạn** — chỉ
endpoint LIVE mới cần, vì đó là chỗ có người đang chờ trang phản hồi.

Cache kết quả drift TTL 10 phút (dài hơn nhiều so với blocklist/rule config 15 giây — trôi đặc trưng không đổi
nhanh), có `?refresh=true` để quản trị viên chủ động tính lại. Nút "🔄 Tính lại" trên `ModelHealthPage.jsx` gọi cờ này.

⚠️ **Bug thật tự phát hiện khi viết test cho endpoint này**: `ml/rba/drift.py::current_frame()` (viết từ MR12, vốn
chỉ để chạy CLI) tự mở `app.database.SessionLocal` bên trong hàm — khi gọi từ một router/test đã inject session RIÊNG
(SQLite in-memory của test, hoặc session theo request của FastAPI), hàm vẫn ÂM THẦM đọc **Postgres dev THẬT** thay vì
session được truyền vào, vì import `SessionLocal` xảy ra bên trong thân hàm chứ không nhận qua tham số. Test đầu tiên
viết cho `GET /model-health` fail vì đúng lý do này (mong đợi `n_current=0` trên DB test rỗng, nhận về hàng nghìn dòng
thật) — sửa bằng cách thêm tham số `db=None` (mặc định vẫn tự mở như cũ cho CLI, nhưng dùng THẲNG session được truyền
vào nếu có, không tự mở thêm). Thêm test hồi quy chặn hẳn `app.database.SessionLocal` để bug này không tái diễn im
lặng (`tests/test_rba_drift.py::test_current_frame_uses_the_injected_session_not_the_real_configured_one`).

## Giới hạn

- PSI trên 300 dòng gần nhất là một **cửa sổ trượt**, không phải toàn bộ lịch sử — hợp lý cho "sức khoẻ HIỆN TẠI"
  nhưng không dùng được để so trôi giữa hai giai đoạn xa nhau (dùng CLI `--days` cho việc đó).
- `GET /users/{id}/profile` không phân trang, giới hạn cứng 50 lần đăng nhập / 20 cảnh báo gần nhất — xem lịch sử đầy
  đủ vẫn phải dùng `GET /login-events?username=`/`GET /alerts` (đã có bộ lọc riêng, phân trang đầy đủ).
- `PUT /rules/{id}` chỉ ghi đè NGUYÊN cả bộ tham số khi gửi `params` (không merge từng key với override cũ) — gửi
  thiếu một tham số nghĩa là tham số đó quay về MẶC ĐỊNH của sổ đăng ký cho ĐỢT GHI ĐÈ này, không phải giữ giá trị
  ghi đè trước đó của riêng tham số đó (đã ghi rõ trong docstring `RuleUpdateRequest`, nhưng dễ hiểu lầm nếu không đọc).
- Chưa có UI cho phép admin THÊM mục blocklist thủ công (kế thừa giới hạn đã ghi ở MR16) hay tạo `rule_overrides` cho
  một luật MỚI thêm sau này mà chưa từng chạy qua `GET /rules` (không phải vấn đề thật — `GET /rules` luôn liệt kê
  MỌI luật trong sổ đăng ký, kể cả chưa có override, nên luật mới tự động xuất hiện).
- Trang chiến dịch (MR14, polish thêm ở MR17) mới thêm bộ lọc trạng thái + phân trang — chưa có bộ lọc theo họ tấn
  công/khoảng thời gian như trang cảnh báo.
