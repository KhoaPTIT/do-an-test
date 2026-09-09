# Hệ thống phát hiện đăng nhập bất thường

Đồ án ngành An toàn thông tin. Hệ thống nhận sự kiện đăng nhập qua API, chấm điểm rủi ro bằng cách kết hợp luật viết tay và mô hình học máy, rồi hiển thị cảnh báo trên dashboard để quản trị viên xử lý.

## Chạy thử trong 5 phút

Không cần cài PostgreSQL, mặc định dùng SQLite.

```bash
cd backend
python -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt

python ml/generate_dataset.py                       # sinh ~19.000 sự kiện mô phỏng
python ml/train.py                                  # huấn luyện mô hình, ~1 phút
python seed_database.py --reset                     # nạp vào database, ~40 giây
uvicorn app.main:app --reload --port 8000
```

Mở trình duyệt:

- Dashboard: http://localhost:8000
- Tài liệu API tự sinh: http://localhost:8000/docs

Mở thêm một cửa sổ dòng lệnh nữa để chạy tấn công thử:

```bash
cd attack-sim
python brute_force.py --target user007
python credential_stuffing.py --victims 20
python account_takeover.py --target user022
```

Cảnh báo sẽ hiện trên dashboard trong vòng 8 giây (dashboard tự tải lại theo nhịp đó).

## Kiến trúc

```
Ứng dụng  ──POST /api/v1/login-event──▶  API
                                          │
                                    ┌─────┴─────┐
                                    │           │
                              Rule engine   Mô hình ML
                                    │           │
                                    └─────┬─────┘
                                          ▼
                                   Điểm rủi ro 0-100
                                          │
                        ┌─────────────────┼─────────────────┐
                        ▼                 ▼                 ▼
                   dưới 40           40 đến 70          từ 70
                   cho qua       bắt xác thực 2 lớp      chặn
                                          │
                                          ▼
                                   Sinh cảnh báo
                                          │
                                          ▼
                                     Dashboard
                                          │
                       Quản trị viên xử lý, gắn nhãn báo động giả
                                          │
                                          ▼
                            Dữ liệu cho lần huấn luyện sau
```

## Cấu trúc thư mục

```
backend/
  app/
    config.py              tham số hệ thống, đọc từ biến môi trường
    database.py            kết nối cơ sở dữ liệu
    models.py              4 bảng: users, login_events, alerts, blocked_ips
    schemas.py             kiểm tra dữ liệu vào ra
    security.py            xác thực API key, giới hạn tần suất
    detection/
      features.py          bối cảnh lịch sử và 16 đặc trưng
      rules.py             8 luật phát hiện
      ml_model.py          nạp mô hình, chấm điểm
      scoring.py           gộp điểm rule và ML
    api/
      events.py            tiếp nhận sự kiện, tra cứu
      alerts.py            quản lý cảnh báo, chặn IP
      stats.py             số liệu cho dashboard
    utils/
      geoip.py             tra cứu vị trí từ IP
      device.py            phân tích user-agent, vân tay thiết bị
  ml/
    generate_dataset.py    sinh dữ liệu mô phỏng có nhãn
    replay.py              tính đặc trưng theo dòng thời gian
    train.py               huấn luyện Isolation Forest và Random Forest
    evaluate.py            xuất bảng số liệu và biểu đồ cho báo cáo
  tests/                   38 kiểm thử tự động
  seed_database.py         nạp dữ liệu mô phỏng vào database
attack-sim/                3 script mô phỏng tấn công
frontend/                  dashboard, HTML và JavaScript thuần
docs/figures/              biểu đồ do evaluate.py sinh ra
```

## Tám luật phát hiện

| Mã | Tên | Điểm | Điều kiện kích hoạt |
|---|---|---|---|
| R01 | Quốc gia mới | 30 | Quốc gia chưa từng có trong lịch sử tài khoản |
| R02 | Di chuyển bất khả thi | 45 | Tốc độ suy ra vượt 900 km/h và quãng đường trên 500 km |
| R03 | Nghi vấn brute-force | 35 | Từ 5 lần đăng nhập sai trong 15 phút |
| R04 | Nghi vấn credential stuffing | 40 | Một IP chạm tới từ 10 tài khoản khác nhau trong 1 giờ |
| R05 | Thiết bị mới | 20 | Vân tay thiết bị chưa từng ghi nhận |
| R06 | Giờ đăng nhập bất thường | 15 | Lệch khỏi khung giờ quen của tài khoản |
| R07 | Mạng rủi ro | 35 hoặc 20 | IP thuộc Tor, hoặc thuộc trung tâm dữ liệu |
| R08 | Công cụ tự động | 30 | User-agent là script, không phải trình duyệt |

Điểm được cộng dồn rồi chặn trên ở 100. Ngưỡng và trọng số nằm trong `app/config.py`, đổi được qua biến môi trường mà không phải sửa mã nguồn.

## Kết quả đánh giá

Chạy `python ml/evaluate.py` để sinh lại bảng này cùng các biểu đồ trong `docs/figures/`.

| Cấu hình | Precision | Recall | F1 | AUC | Báo động giả |
|---|---|---|---|---|---|
| Chỉ luật | 0,838 | 0,957 | 0,894 | 0,998 | 0,71% |
| Chỉ Isolation Forest | 0,565 | 0,995 | 0,720 | 0,997 | 2,94% |
| Chỉ Random Forest | 1,000 | 0,991 | 0,995 | 1,000 | 0,00% |
| Lai luật và ML | 0,724 | 0,981 | 0,833 | 0,998 | 1,43% |

Khả năng phát hiện theo từng loại tấn công, cấu hình lai:

| Loại tấn công | Tỷ lệ phát hiện |
|---|---|
| Brute-force | 99,2% |
| Credential stuffing | 95,8% |
| Chiếm đoạt tài khoản | 100% |

Cách đọc bảng: cấu hình lai đánh đổi Precision để lấy Recall so với dùng luật đơn thuần. Cụ thể là Recall tăng từ 0,957 lên 0,981, đổi lại tỷ lệ báo động giả tăng từ 0,71% lên 1,43%. Với hệ thống có một triệu lượt đăng nhập mỗi ngày thì 0,72% chênh lệch tương đương hơn bảy nghìn lần làm phiền người dùng thật mỗi ngày, nên lựa chọn này phải cân nhắc theo bối cảnh chứ không phải cứ Recall cao là tốt. Đây chính là chỗ để bàn luận trong báo cáo thay vì chỉ đưa bảng số.

Chiếm đoạt tài khoản đạt 100% nhờ luật R02 về di chuyển bất khả thi, nhưng đừng vội mừng: bộ dữ liệu mô phỏng luôn đặt lần đăng nhập của kẻ tấn công ngay sau một lần đăng nhập hợp lệ trong nước. Nếu nạn nhân không hoạt động trong nhiều giờ trước đó thì tốc độ di chuyển suy ra sẽ hợp lý và luật này im lặng.

## Ba điểm cần nhấn khi bảo vệ

### Cơ chế lùi về dùng riêng luật khi thiếu dữ liệu

Mô hình học máy chỉ tham gia chấm điểm khi tài khoản đã có ít nhất 5 lần đăng nhập đáng tin. Dưới ngưỡng đó, đặc trưng hành vi không có ý nghĩa thống kê, nên hệ thống chỉ dùng luật thay vì để mô hình đoán bừa. Trường `mode` trong phản hồi của API cho biết đang chạy ở chế độ nào. Đây là cách xử lý bài toán cold start.

### Chống đầu độc hồ sơ hành vi

Chỉ những lần đăng nhập thành công và không bị luật gắn cờ mới được đưa vào hồ sơ hành vi của tài khoản. Nếu bỏ điều kiện này, kẻ tấn công chỉ cần đăng nhập một lần từ nước ngoài là quốc gia đó trở thành quen thuộc, và mọi lần sau đều trót lọt.

Đây là lỗi thật, phát hiện được khi chạy `account_takeover.py`: lần đăng nhập đầu của kẻ tấn công bị chặn với 92,5 điểm, nhưng ba lần tiếp theo tụt xuống 34,8 điểm và được cho qua. Sau khi sửa, cả bốn lần đều bị chặn với điểm ổn định 93,9. Bộ lọc nằm ở `build_context_from_db()` trong `app/detection/features.py` và ở `Replayer.process()` trong `ml/replay.py`, hai chỗ phải khớp nhau.

### Chống rò rỉ dữ liệu tương lai

Đặc trưng của một sự kiện chỉ được tính từ những gì xảy ra trước nó. Module `ml/replay.py` duyệt sự kiện theo thứ tự thời gian, tính đặc trưng rồi mới cập nhật lịch sử. Cùng đoạn mã đó được dùng cho cả huấn luyện offline và chấm điểm trực tuyến, nên không có chuyện mô hình được huấn luyện trên một cách tính đặc trưng nhưng lúc chạy thật lại nhận cách tính khác.

Tập kiểm thử cũng chia theo thời gian chứ không chia ngẫu nhiên, vì chia ngẫu nhiên sẽ để sự kiện tương lai lọt vào tập huấn luyện.

## Hạn chế đã biết

Cần nêu thẳng trong báo cáo, hội đồng đánh giá cao sự trung thực hơn là con số đẹp.

**Random Forest đạt AUC 1,000 trên dữ liệu mô phỏng.** Con số này không phản ánh năng lực thật. Bộ sinh dữ liệu là một hàm xác định, nên một mô hình đủ mạnh sẽ học ngược lại được chính quy luật sinh. Kết quả của Isolation Forest đáng tin hơn vì nó không nhìn thấy nhãn. Muốn có số liệu thuyết phục thì phải kiểm chứng trên dữ liệu thật, ví dụ bộ RBA Dataset của Wiefling và cộng sự.

**Dữ liệu là mô phỏng, không phải log thật.** Bộ sinh đã cố gắng đưa vào các tình huống khó ở cả hai phía: tấn công ngụy trang bằng IP dân cư và trình duyệt thật, cùng với hành vi hợp lệ dễ bị nhận nhầm như quên mật khẩu gõ sai liên tiếp hoặc bật VPN doanh nghiệp gây di chuyển bất khả thi. Nhưng độ đa dạng vẫn kém xa dữ liệu thật.

**Vân tay thiết bị chỉ dựa trên user-agent.** Hệ thống thật lấy thêm độ phân giải màn hình, danh sách phông chữ, canvas fingerprint từ phía trình duyệt nên phân biệt tốt hơn nhiều.

**Tra cứu vị trí dùng bảng offline dựng sẵn.** Để đồ án chạy được ngay mà không cần đăng ký tài khoản MaxMind. Cách chuyển sang dữ liệu thật đã ghi trong `app/utils/geoip.py`.

**Giới hạn tần suất lưu trong bộ nhớ tiến trình.** Chạy nhiều tiến trình thì phải chuyển sang Redis.

**Vòng phản hồi mới dừng ở mức thu thập nhãn.** Khi quản trị viên đánh dấu báo động giả, nhãn được ghi ngược vào sự kiện gốc, và thống kê tỷ lệ báo động giả theo từng luật đã có ở `/api/v1/stats/rule-frequency`. Nhưng việc huấn luyện lại vẫn phải chạy tay.

## Bảo vệ chính API này

Câu hỏi hội đồng gần như chắc chắn sẽ hỏi. Đã làm:

- Xác thực bằng API key, so sánh bằng `secrets.compare_digest` để không lộ khóa qua chênh lệch thời gian phản hồi
- Giới hạn tần suất gọi cho mỗi khóa
- Kiểm tra dữ liệu đầu vào bằng Pydantic, gồm cả định dạng IP và độ dài chuỗi
- Truy vấn qua ORM có tham số hóa, không nối chuỗi SQL
- CORS liệt kê tên miền cụ thể, không để dấu sao
- Container chạy bằng tài khoản thường, không phải root
- PostgreSQL không mở cổng ra ngoài, chỉ backend trong cùng mạng truy cập được
- Không lưu mật khẩu ở bất kỳ đâu, hệ thống chỉ nhận biết thành công hay thất bại

Còn thiếu và nên nêu ở phần hướng phát triển: xoay vòng khóa định kỳ, chữ ký HMAC cho từng request, ghi log truy cập của quản trị viên, mã hóa hoặc ẩn danh địa chỉ IP khi lưu trữ.

## Quyền riêng tư

Hệ thống lưu địa chỉ IP và vị trí suy ra từ IP, đều là dữ liệu cá nhân theo Nghị định 13/2023 về bảo vệ dữ liệu cá nhân. Trong báo cáo nên nêu bốn nguyên tắc: chỉ thu thập trường thật sự cần cho việc phát hiện, đặt thời hạn lưu trữ, giới hạn ai được xem, và cân nhắc ẩn danh một phần địa chỉ IP sau khi đã dùng xong cho việc chấm điểm.

## Chạy bằng Docker

```bash
cp .env.example .env      # sửa mật khẩu và API key trong .env
docker compose up --build
```

## Chạy kiểm thử

```bash
cd backend
python -m pytest tests/ -v
```

38 kiểm thử, chia theo nhóm: hàm tính khoảng cách, từng luật, cơ chế chấm điểm, chống rò rỉ dữ liệu, tiện ích, và API.

## Phân công cho hai người

| Người A, phần phát hiện | Người B, phần hệ thống |
|---|---|
| `detection/rules.py` | `api/` |
| `detection/features.py` | `models.py`, `schemas.py` |
| `ml/` toàn bộ | `security.py` |
| `attack-sim/` | `frontend/` |
| Chương 1 và phần đánh giá của chương 3 | Chương 2 và phần cài đặt của chương 3 |

Thống nhất định dạng JSON của API ngay tuần đầu. Người B làm dashboard với dữ liệu giả mà không phải chờ người A xong phần phát hiện.

## Việc cần làm trước khi nộp

- [ ] Đổi `LAD_API_KEY` trong `.env`, không dùng khóa mặc định
- [ ] Chạy `ml/evaluate.py`, chèn bảng số liệu và biểu đồ vào báo cáo
- [ ] Chụp màn hình dashboard ở ba trạng thái: bình thường, có cảnh báo, chi tiết cảnh báo
- [ ] Quay video demo dự phòng, phòng khi máy chiếu hoặc mạng trục trặc lúc bảo vệ
- [ ] Tập chạy `attack-sim/` trước ít nhất ba lần cho quen thao tác
- [ ] Kiểm tra `.env` và file `.pkl` không bị đưa lên Git
