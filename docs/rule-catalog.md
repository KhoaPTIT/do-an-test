# Danh mục luật (rule engine v2)

> **Tệp này được TỰ SINH** từ sổ đăng ký luật (`python -m app.detection.engine.catalog --write`) — đừng sửa tay. `tests/test_rule_engine_catalog.py` báo lỗi nếu tệp lỗi thời so với mã.

Mã: [`backend/app/detection/engine/`](../backend/app/detection/engine/) · kiểm thử: `tests/test_rule_engine_*.py` · đo từng luật trên log lịch sử: `python -m app.detection.engine.replay` (kết quả trên RBA: [`rule-replay.md`](rule-replay.md)) · ngưỡng đã tinh chỉnh trên train RBA: [`rule-tuning.md`](rule-tuning.md).

## 1. Tổng quan

**19 luật** trong 4 nhóm; 14 luật mặc định ở chế độ `enforce`, 5 ở chế độ `shadow` (`regular_rhythm`, `country_hop`, `rare_network_login`, `datacenter_ip`, `vpn_ip`) vì chưa được kiểm chứng trên log thật hoặc dễ báo nhầm.

| Mã | Tên | Nhóm | Mức | Chế độ mặc định | MITRE ATT&CK |
|---|---|---|---|---|---|
| [`brute_force`](#brute_force) | Dò mật khẩu một tài khoản | Đoán và dò mật khẩu | cao | enforce | T1110.001 |
| [`credential_stuffing`](#credential_stuffing) | Nhồi thông tin đăng nhập | Đoán và dò mật khẩu | cao | enforce | T1110.004 |
| [`password_spray_slow`](#password_spray_slow) | Rải mật khẩu chậm | Đoán và dò mật khẩu | cao | enforce | T1110.003 |
| [`distributed_bruteforce`](#distributed_bruteforce) | Dò mật khẩu phân tán vào một tài khoản | Đoán và dò mật khẩu | cao | enforce | T1110.001, T1090 |
| [`username_enumeration`](#username_enumeration) | Dò danh sách tài khoản | Đoán và dò mật khẩu | trung bình | enforce | T1589 |
| [`success_after_failures`](#success_after_failures) | Thành công sau chuỗi sai | Đoán và dò mật khẩu | cao | enforce | T1110.001 |
| [`bot_user_agent`](#bot_user_agent) | User-Agent là bot | Tự động hoá | thấp | enforce | T1110 |
| [`scripted_client`](#scripted_client) | Client kịch bản / công cụ | Tự động hoá | trung bình | enforce | T1110 |
| [`ua_rotation`](#ua_rotation) | Xoay User-Agent | Tự động hoá | trung bình | enforce | T1110.004 |
| [`regular_rhythm`](#regular_rhythm) | Nhịp thử đều như máy | Tự động hoá | trung bình | shadow | T1110 |
| [`tor_exit`](#tor_exit) | Đăng nhập từ Tor exit node | Danh tiếng hạ tầng | trung bình | enforce | T1090.003 |
| [`datacenter_ip`](#datacenter_ip) | Đăng nhập từ dải IP datacenter | Danh tiếng hạ tầng | thấp | shadow | T1090.002 |
| [`vpn_ip`](#vpn_ip) | Đăng nhập từ dải IP VPN thương mại | Danh tiếng hạ tầng | thấp | shadow | T1090 |
| [`blocklist_hit`](#blocklist_hit) | Nguồn nằm trong blocklist | Danh tiếng hạ tầng | cao | enforce | — |
| [`impossible_travel`](#impossible_travel) | Di chuyển bất khả thi | Ngữ cảnh tài khoản | cao | enforce | T1078 |
| [`multi_context_simultaneous`](#multi_context_simultaneous) | Đăng nhập cùng lúc từ nhiều quốc gia | Ngữ cảnh tài khoản | cao | enforce | T1078 |
| [`country_hop`](#country_hop) | Tài khoản bị thử từ nhiều quốc gia | Ngữ cảnh tài khoản | trung bình | shadow | T1078, T1090 |
| [`dormant_account_login`](#dormant_account_login) | Tài khoản ngủ đông đăng nhập lại | Ngữ cảnh tài khoản | trung bình | enforce | T1078 |
| [`rare_network_login`](#rare_network_login) | Đăng nhập từ nhà mạng cực hiếm | Ngữ cảnh tài khoản | trung bình | shadow | T1078 |

## 2. Cách hoạt động

- **Đầu vào duy nhất** của mọi luật là `LoginAttempt` (một lần thử đăng nhập đã chuẩn hoá: thời điểm SỰ KIỆN, tên đăng nhập, kết quả, IP, ASN, quốc gia, toạ độ, User-Agent...) và lịch sử tài khoản. Luồng thật (MR12), replay log lịch sử và test đều gọi cùng `RuleEngine.evaluate`; luật không biết dữ liệu đến từ đâu và **không bao giờ đọc nhãn** (`labels`) của log replay.
- **Thời gian là thời gian của sự kiện**, không phải giờ hệ thống: replay log năm 2020 cho đúng kết quả của năm 2020. Cửa sổ là (đầu, hiện tại] — sự kiện đúng bằng đầu cửa sổ không được tính.
- **Trạng thái cửa sổ thời gian** (đếm lần sai, đếm tên/IP/User-Agent khác nhau...) nằm ở `WindowStore`: `MemoryStore` cho replay và test, `RedisStore` cho luồng thật; một bộ test chung chứng minh hai cài đặt cùng hợp đồng và cho cùng kết quả trên lưu lượng ngẫu nhiên. Chi phí mỗi sự kiện bị chặn bởi ngưỡng, không tăng theo độ dài cửa sổ.
- **Ba chế độ** cho mỗi luật: `enforce` (khớp thì tạo cảnh báo), `shadow` (vẫn chạy và ghi nhận để đo tỉ lệ khớp/báo nhầm nhưng KHÔNG tạo cảnh báo), `off` (không chạy).
- **Thiếu dữ liệu ≠ báo động:** luật cần dữ liệu mà lần thử không có (ví dụ chưa có file GeoLite2-ASN) bị **bỏ qua** và `Evaluation.skipped` ghi lý do; luật gặp lỗi được ghi ở `Evaluation.errors` và không ảnh hưởng luật khác hay luồng đăng nhập.
- **Thông điệp** ngắn tiếng Việt cùng phong cách chuỗi cảnh báo hiện có; ba luật gốc (`brute_force`, `credential_stuffing`, `impossible_travel`) giữ đúng chuỗi và ngưỡng mặc định của luật tầng 1 cũ.
- ⚠️ Ánh xạ MITRE ATT&CK là **gần đúng**: ATT&CK mô tả kỹ thuật của kẻ tấn công, còn luật nhận diện dấu hiệu của chúng trong log đăng nhập.

### Cấu hình

Ghi đè chế độ và tham số theo từng luật bằng JSON (`RuleConfig.from_file(...)`); luật không nêu dùng mặc định của bảng dưới. Tham số sai (không tồn tại, sai kiểu, ngoài khoảng) bị từ chối ngay khi nạp. Mặc định ở bảng dưới là giá trị đặt trước; hồ sơ [`profiles/rba_train_tuned.json`](../backend/app/detection/engine/profiles/rba_train_tuned.json) là bộ tham số đã tinh chỉnh trên train RBA (chỉ đúng cho RBA, xem [`rule-tuning.md`](rule-tuning.md)).

```json
{"rules": {"brute_force": {"params": {"threshold": 8, "window_s": 600}}, "vpn_ip": {"mode": "off"}, "country_hop": {"mode": "enforce"}}}
```

## 3. Ánh xạ MITRE ATT&CK

| Kỹ thuật | Tên | Luật |
|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | `bot_user_agent`, `scripted_client`, `regular_rhythm` |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | `brute_force`, `distributed_bruteforce`, `success_after_failures` |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | `password_spray_slow` |
| [T1110.004](https://attack.mitre.org/techniques/T1110/004/) | Brute Force: Credential Stuffing | `credential_stuffing`, `ua_rotation` |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `impossible_travel`, `multi_context_simultaneous`, `country_hop`, `dormant_account_login`, `rare_network_login` |
| [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | `distributed_bruteforce`, `country_hop`, `vpn_ip` |
| [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | Proxy: External Proxy | `datacenter_ip` |
| [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Proxy: Multi-hop Proxy | `tor_exit` |
| [T1589](https://attack.mitre.org/techniques/T1589/) | Gather Victim Identity Information | `username_enumeration` |
| — | không ánh xạ kỹ thuật cụ thể | `blocklist_hit` |

## 4. Dữ liệu cần có

Thiếu dữ liệu thì luật tương ứng bị bỏ qua (xem mục 2).

| Dữ liệu | Ý nghĩa | Luật cần |
|---|---|---|
| `account` | tài khoản tồn tại (không phải tên đăng nhập bịa) | `success_after_failures`, `impossible_travel`, `multi_context_simultaneous`, `dormant_account_login`, `rare_network_login` |
| `asn` | ASN của IP (cần file GeoLite2-ASN.mmdb) | `rare_network_login` |
| `country` | quốc gia của IP (GeoIP) | `multi_context_simultaneous`, `country_hop` |
| `geo` | toạ độ của IP (GeoLite2-City) | `impossible_travel` |
| `user_agent` | User-Agent của request | `ua_rotation` |
| `history` | lịch sử tài khoản (DB hoặc luồng sự kiện đã phát) | `impossible_travel`, `dormant_account_login` |
| `tor_list` | danh sách Tor exit node (python -m scripts.update_threat_feeds) | `tor_exit` |
| `datacenter_list` | danh sách dải IP datacenter | `datacenter_ip` |
| `vpn_list` | danh sách dải IP VPN | `vpn_ip` |
| `global_stats` | thống kê đăng nhập thành công theo ASN toàn hệ thống | `rare_network_login` |

## 5. Chi tiết từng luật

### Đoán và dò mật khẩu

#### <a id="brute_force"></a>`brute_force` — Dò mật khẩu một tài khoản

Nhiều lần đăng nhập sai vào CÙNG một tên đăng nhập trong thời gian ngắn (đoán mật khẩu), từ bất kỳ IP nào.

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Ngưỡng và cửa sổ là luật tầng 1 gốc (docs/api-contract.md mục 6, giả định chưa đối chiếu). Báo ở MỖI lần sai từ lần thứ `threshold` trở đi; gộp cảnh báo trùng là việc của MR13.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `threshold` | `5` | lần | 2–1000 | số lần sai tối thiểu để báo |
| `window_s` | `300` | giây | 10–86400 | độ dài cửa sổ |

#### <a id="credential_stuffing"></a>`credential_stuffing` — Nhồi thông tin đăng nhập

Một IP (hoặc một nhà mạng/ASN) thử nhiều tên đăng nhập KHÁC NHAU với nhiều lần sai trong thời gian ngắn — dùng danh sách tài khoản/mật khẩu bị lộ. So với luật gốc: thêm phạm vi ASN (botnet xoay IP trong cùng nhà mạng), nới ngưỡng một nửa khi thấy xoay User-Agent, và bỏ qua khi tỉ lệ thành công cao (nhiều người dùng thật sau cùng một cổng NAT).

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.004 (Brute Force: Credential Stuffing)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Phạm vi ASN chỉ chạy khi biết ASN (GeoLite2-ASN). Ngưỡng IP (10 lần, 5 tên, 5 phút) là luật gốc.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `300` | giây | 10–86400 | độ dài cửa sổ |
| `min_fails` | `10` | lần | 2–100000 | số lần sai tối thiểu từ một IP |
| `min_users` | `5` | tên | 2–100000 | số tên đăng nhập khác nhau tối thiểu từ một IP |
| `max_success_ratio` | `0.5` | — | 0–1 | quá tỉ lệ thành công này (trên tổng thử của IP/ASN) thì coi là lưu lượng hợp lệ |
| `asn_min_fails` | `40` | lần | 2–1000000 | số lần sai tối thiểu từ một ASN (phạm vi ASN) |
| `asn_min_users` | `20` | tên | 2–1000000 | số tên đăng nhập khác nhau tối thiểu từ một ASN |
| `ua_rotation_min` | `4` | UA | 2–1000 | số User-Agent khác nhau (trong các lần sai của IP) coi là đang xoay UA |
| `ua_rotation_relax` | `0.5` | — | 0.1–1 | hệ số nhân ngưỡng IP khi đang xoay UA (0,5 = nới một nửa) |

#### <a id="password_spray_slow"></a>`password_spray_slow` — Rải mật khẩu chậm

Một IP (hoặc ASN) thử NHIỀU tài khoản nhưng mỗi tài khoản chỉ vài lần, trải dài hàng giờ — một hai mật khẩu phổ biến rải khắp danh sách để né ngưỡng theo tài khoản và theo thời gian ngắn. Không báo khi tốc độ đã đủ nhanh để `credential_stuffing` xử lý.

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.003 (Brute Force: Password Spraying)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Đếm tài khoản khác nhau bị chặn ở 200 (K.CAP) nên tỉ lệ lần sai/tài khoản là cận trên; IP tấn công khổng lồ do `credential_stuffing` bắt.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `86400` | giây | 600–86400 | độ dài cửa sổ |
| `min_users` | `15` | tên | 3–100000 | số tài khoản khác nhau tối thiểu từ một IP trong cửa sổ |
| `max_fails_per_user` | `3` | lần/TK | 1–100 | trung bình tối đa số lần sai mỗi tài khoản (rải mỏng) |
| `max_fails_per_hour` | `120` | lần | 1–100000 | tối đa số lần sai của IP trong 1 giờ gần nhất; 120 = 10 lần/5 phút, ngưỡng nhồi thông tin quy ra giờ (nhanh hơn thì không phải "chậm") |
| `asn_min_users` | `40` | tên | 3–1000000 | số tài khoản khác nhau tối thiểu từ một ASN (phạm vi ASN) |
| `asn_max_fails_per_hour` | `600` | lần | 1–1000000 | tối đa số lần sai của ASN trong 1 giờ gần nhất (nhiều IP nên cho phép nhiều hơn một IP) |

#### <a id="distributed_bruteforce"></a>`distributed_bruteforce` — Dò mật khẩu phân tán vào một tài khoản

Một tài khoản bị đoán mật khẩu từ NHIỀU IP khác nhau (mỗi IP chỉ vài lần nên không chạm ngưỡng theo IP), thường qua proxy hoặc botnet.

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1090 (Proxy)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `3600` | giây | 60–86400 | độ dài cửa sổ |
| `min_fails` | `8` | lần | 2–100000 | số lần sai tối thiểu vào tài khoản |
| `min_ips` | `5` | IP | 2–100000 | số IP khác nhau tối thiểu |

#### <a id="username_enumeration"></a>`username_enumeration` — Dò danh sách tài khoản

Một IP thử nhiều tên đăng nhập KHÔNG tồn tại — dò xem tài khoản nào có thật trước khi đoán mật khẩu.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1589 (Gather Victim Identity Information)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Ánh xạ MITRE gần đúng: ATT&CK xếp việc thu thập danh tính nạn nhân vào giai đoạn trinh sát (T1589), không có kỹ thuật riêng cho dò tên đăng nhập.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `600` | giây | 10–86400 | độ dài cửa sổ |
| `min_usernames` | `8` | tên | 2–100000 | số tên không tồn tại khác nhau tối thiểu từ một IP |

#### <a id="success_after_failures"></a>`success_after_failures` — Thành công sau chuỗi sai

Đăng nhập THÀNH CÔNG vào một tài khoản ngay sau nhiều lần sai gần đây (từ bất kỳ IP nào) — dấu hiệu kẻ tấn công đã đoán trúng mật khẩu.

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)
- **Dữ liệu cần:** `account`
- **Ghi chú:** Người dùng thật cũng gõ sai vài lần rồi đúng; ngưỡng 5 (cao hơn mức 3 của điểm rủi ro tầng 2) để giảm báo nhầm — cần đo trên log thật ở MR10.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `600` | giây | 10–86400 | độ dài cửa sổ nhìn lại |
| `min_fails` | `5` | lần | 2–100000 | số lần sai tối thiểu trước đó vào tài khoản |

### Tự động hoá

#### <a id="bot_user_agent"></a>`bot_user_agent` — User-Agent là bot

User-Agent được thư viện phân tích UA nhận là bot/trình thu thập tự động.

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Chỉ dựa vào UA nên kẻ tấn công nói dối UA là né được; giá trị là bắt các bot lười.

#### <a id="scripted_client"></a>`scripted_client` — Client kịch bản / công cụ

User-Agent thuộc công cụ HTTP/dò quét (curl, python-requests, Hydra, trình duyệt không đầu...) hoặc thiếu hẳn — trình duyệt thật luôn gửi User-Agent.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Các script demo trong attack-sim/ dùng httpx nên khớp luật này.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `markers` | `curl/, wget/, python-requests, python-urllib, python-httpx, aiohttp, go-http-client, libwww-perl, … (26 mục)` | — | — | chuỗi con (chữ thường) của User-Agent coi là client kịch bản |
| `flag_empty_ua` | `true` | — | — | coi User-Agent trống là client kịch bản |

#### <a id="ua_rotation"></a>`ua_rotation` — Xoay User-Agent

Cùng một IP thất bại đăng nhập với NHIỀU User-Agent khác nhau trong thời gian ngắn — công cụ nhồi thông tin đổi UA để né nhận diện.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.004 (Brute Force: Credential Stuffing)
- **Dữ liệu cần:** `user_agent`
- **Ghi chú:** Nhiều người dùng thật sau cùng một NAT có UA khác nhau nhưng hiếm khi cùng thất bại nhiều lần; ngưỡng `min_fails` tách hai trường hợp.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `600` | giây | 10–86400 | độ dài cửa sổ |
| `min_distinct_ua` | `5` | UA | 2–1000 | số User-Agent khác nhau tối thiểu |
| `min_fails` | `8` | lần | 2–100000 | số lần sai tối thiểu của IP |

#### <a id="regular_rhythm"></a>`regular_rhythm` — Nhịp thử đều như máy

Các lần đăng nhập SAI gần nhất từ một IP cách nhau đều đặn và dày (độ lệch chuẩn nhỏ so với trung bình) — con người không gõ đều đến vậy.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** shadow (chỉ ghi nhận)
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Chưa kiểm chứng trên log thật (chỉ dựa vào giả thuyết nhịp), nên mặc định ở chế độ shadow; máy có jitter ngẫu nhiên lớn sẽ né được.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `samples` | `10` | lần | 5–100 | số lần sai gần nhất dùng để đo nhịp |
| `max_mean_interval_s` | `30` | giây | 0–3600 | khoảng cách trung bình tối đa giữa hai lần (chậm hơn thì không tính là dồn dập) |
| `max_cv` | `0.15` | — | 0–1 | hệ số biến thiên tối đa (độ lệch chuẩn / trung bình) của khoảng cách |

### Danh tiếng hạ tầng

#### <a id="tor_exit"></a>`tor_exit` — Đăng nhập từ Tor exit node

IP nguồn nằm trong danh sách exit node chính thức của Tor Project — lưu lượng bị ẩn nguồn gốc qua nhiều chặng.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1090.003 (Proxy: Multi-hop Proxy)
- **Dữ liệu cần:** `tor_list`
- **Ghi chú:** Tor có người dùng hợp lệ (riêng tư, kiểm duyệt) nên chỉ mức trung bình; danh sách là bản chụp, exit node đổi hằng ngày.

#### <a id="datacenter_ip"></a>`datacenter_ip` — Đăng nhập từ dải IP datacenter

IP nguồn thuộc dải của nhà cung cấp hosting/đám mây — người dùng thật hiếm khi đăng nhập từ máy chủ; kẻ tấn công thuê VPS/proxy thì thường.

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** shadow (chỉ ghi nhận)
- **MITRE ATT&CK:** T1090.002 (Proxy: External Proxy)
- **Dữ liệu cần:** `datacenter_list`
- **Ghi chú:** Danh sách cộng đồng (X4BNet lists_vpn) KHÔNG đầy đủ và báo nhầm với VPN/đám mây của chính người dùng (làm việc từ xa); chế độ shadow đến khi đo được tỉ lệ báo nhầm trên log thật.

#### <a id="vpn_ip"></a>`vpn_ip` — Đăng nhập từ dải IP VPN thương mại

IP nguồn thuộc dải của dịch vụ VPN thương mại — che vị trí thật, thường thấy khi kẻ tấn công muốn 'ở cùng nước' với nạn nhân.

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** shadow (chỉ ghi nhận)
- **MITRE ATT&CK:** T1090 (Proxy)
- **Dữ liệu cần:** `vpn_list`
- **Ghi chú:** Nhiều người dùng thật dùng VPN; chỉ có ý nghĩa khi kết hợp với tín hiệu khác (đổi quốc gia, thiết bị mới). Chế độ shadow mặc định.

#### <a id="blocklist_hit"></a>`blocklist_hit` — Nguồn nằm trong blocklist

IP, dải CIDR, ASN hoặc tên đăng nhập của lần thử nằm trong blocklist do quản trị viên đặt (còn hiệu lực).

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** không ánh xạ kỹ thuật cụ thể
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Quyết định của con người nên không ánh xạ kỹ thuật MITRE cụ thể. Hạn dùng của mục chặn so với thời gian của sự kiện. MR16 bổ sung hành động chặn thật.

### Ngữ cảnh tài khoản

#### <a id="impossible_travel"></a>`impossible_travel` — Di chuyển bất khả thi

Hai lần đăng nhập THÀNH CÔNG liên tiếp của một tài khoản cách nhau quá xa so với thời gian trôi qua (tốc độ vượt ngưỡng của máy bay). Lần thử SAI không được tính: nó không chứng minh chủ tài khoản đã ở nơi đó (thử sai từ nhiều nước là việc của country_hop/brute_force).

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `geo`, `history`
- **Ghi chú:** Luật tầng 1 gốc (ngưỡng 900 km/h lấy nguyên văn từ checklist). Bỏ qua khi thiếu GeoIP ở một trong hai lần. VPN/proxy làm sai lệch vị trí. Không chạy được trên RBA (không có toạ độ).

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `max_speed_kmh` | `900` | km/h | 100–20000 | tốc độ di chuyển tối đa hợp lý |

#### <a id="multi_context_simultaneous"></a>`multi_context_simultaneous` — Đăng nhập cùng lúc từ nhiều quốc gia

Một tài khoản có đăng nhập THÀNH CÔNG từ hai quốc gia khác nhau trong vài phút — hai phiên song song không thể cùng một người. Bổ sung cho `impossible_travel` khi thiếu toạ độ.

- **Mức nghiêm trọng:** cao · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `country`
- **Ghi chú:** Người dùng thật dùng VPN trên một thiết bị và đăng nhập thiết bị khác không VPN sẽ khớp; cần đối chiếu thiết bị ở MR11.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `600` | giây | 10–86400 | độ dài cửa sổ |
| `min_countries` | `2` | nước | 2–50 | số quốc gia khác nhau tối thiểu |

#### <a id="country_hop"></a>`country_hop` — Tài khoản bị thử từ nhiều quốc gia

Một tên đăng nhập bị thử (thành công hoặc thất bại) từ nhiều quốc gia khác nhau trong 24 giờ — proxy xoay vòng theo nước hoặc botnet toàn cầu.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** shadow (chỉ ghi nhận)
- **MITRE ATT&CK:** T1078 (Valid Accounts), T1090 (Proxy)
- **Dữ liệu cần:** `country`
- **Ghi chú:** Người hay đi công tác/dùng VPN đổi nước hợp lệ; chưa đo tỉ lệ báo nhầm nên mặc định shadow.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `86400` | giây | 600–604800 | độ dài cửa sổ |
| `min_countries` | `3` | nước | 2–50 | số quốc gia khác nhau tối thiểu |

#### <a id="dormant_account_login"></a>`dormant_account_login` — Tài khoản ngủ đông đăng nhập lại

Tài khoản không có lần đăng nhập thành công nào trong nhiều tháng bỗng đăng nhập lại (mặc định chỉ báo khi kèm quốc gia hoặc thiết bị chưa từng thấy).

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `history`
- **Ghi chú:** Người dùng thật quay lại sau kỳ nghỉ là chuyện thường: mặc định phải kèm dấu hiệu 'mới' để giảm báo nhầm.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `dormant_days` | `90` | ngày | 1–3650 | số ngày không đăng nhập thành công để coi là ngủ đông |
| `require_change` | `true` | — | — | chỉ báo khi lần này có quốc gia hoặc thiết bị mới so với lịch sử |

#### <a id="rare_network_login"></a>`rare_network_login` — Đăng nhập từ nhà mạng cực hiếm

Đăng nhập thành công từ một ASN mà tỉ lệ đăng nhập thành công của CẢ HỆ THỐNG từ ASN đó cực nhỏ (hoặc chưa từng có) — nhà mạng lạ so với mọi người dùng khác.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** shadow (chỉ ghi nhận)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `asn`, `global_stats`
- **Ghi chú:** Thêm theo quyết định D3 ở CP2. Trên RBA, luật một đặc trưng `rare_asn` với ngưỡng ở phân vị 99 của đăng nhập hợp lệ bắt 65,8% trong 38 ATO tương lai (chẩn đoán MR7, chọn sau khi đã thấy ATO) nhưng ATO của bộ dữ liệu tổng hợp đến từ nhà mạng hiếm một cách nhân tạo, nên đánh giá luật trên ATO của RBA mang tính vòng tròn; giá trị thật đo bằng kịch bản mô phỏng ở MR18. Ngưỡng mặc định 2e-5 ≈ phân vị 99 của đăng nhập hợp lệ ở RBA; chỉnh ở MR10.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `max_share` | `2e-05` | — | 0–0.01 | tỉ lệ đăng nhập thành công của cả hệ thống từ ASN này (bằng hoặc thấp hơn thì báo) |
| `min_total` | `20000` | lần | 100–100000000 | số đăng nhập thành công toàn hệ thống tối thiểu trước khi luật có hiệu lực (thống kê quá ít thì ASN nào cũng 'hiếm') |
