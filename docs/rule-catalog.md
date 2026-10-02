# Danh mục luật (rule engine v2)

> **Tệp này được TỰ SINH** từ sổ đăng ký luật (`python -m app.detection.engine.catalog --write`) — đừng sửa tay. `tests/test_rule_engine_catalog.py` báo lỗi nếu tệp lỗi thời so với mã.

Mã: [`backend/app/detection/engine/`](../backend/app/detection/engine/) · kiểm thử: `tests/test_rule_engine_*.py` · đo từng luật trên log lịch sử: `python -m app.detection.engine.replay` (kết quả trên RBA: [`rule-replay.md`](rule-replay.md)) · ngưỡng đã tinh chỉnh trên train RBA: [`rule-tuning.md`](rule-tuning.md).

## 1. Tổng quan

**23 luật** trong 5 nhóm; 20 luật mặc định ở chế độ `enforce`, 3 ở chế độ `shadow` (`rare_network_login`, `datacenter_ip`, `vpn_ip`) vì chưa được kiểm chứng trên log thật hoặc dễ báo nhầm.

| Mã | Tên | Nhóm | Mức | Chế độ mặc định | Kiểm chứng | MITRE ATT&CK |
|---|---|---|---|---|---|---|
| [`brute_force`](#brute_force) | Dò mật khẩu một tài khoản | Đoán và dò mật khẩu | cao | enforce | verified | T1110.001 |
| [`credential_stuffing`](#credential_stuffing) | Nhồi thông tin đăng nhập | Đoán và dò mật khẩu | cao | enforce | verified | T1110.004 |
| [`password_spray_slow`](#password_spray_slow) | Rải mật khẩu chậm | Đoán và dò mật khẩu | cao | enforce | verified | T1110.003 |
| [`distributed_bruteforce`](#distributed_bruteforce) | Dò mật khẩu phân tán vào một tài khoản | Đoán và dò mật khẩu | cao | enforce | verified | T1110.001, T1090 |
| [`username_enumeration`](#username_enumeration) | Dò danh sách tài khoản | Đoán và dò mật khẩu | trung bình | enforce | verified | T1589 |
| [`success_after_failures`](#success_after_failures) | Thành công sau chuỗi sai | Đoán và dò mật khẩu | cao | enforce | verified | T1110.001 |
| [`bot_user_agent`](#bot_user_agent) | User-Agent là bot | Tự động hoá | thấp | enforce | verified | T1110 |
| [`scripted_client`](#scripted_client) | Client kịch bản / công cụ | Tự động hoá | thấp | enforce | verified | T1110 |
| [`ua_rotation`](#ua_rotation) | Xoay User-Agent | Tự động hoá | trung bình | enforce | verified | T1110.004 |
| [`regular_rhythm`](#regular_rhythm) | Nhịp thử đều như máy | Tự động hoá | trung bình | enforce | verified | T1110 |
| [`tor_exit`](#tor_exit) | Đăng nhập từ Tor exit node | Danh tiếng hạ tầng | trung bình | enforce | verified | T1090.003 |
| [`datacenter_ip`](#datacenter_ip) | Đăng nhập từ dải IP datacenter | Danh tiếng hạ tầng | thấp | shadow | experimental | T1090.002 |
| [`vpn_ip`](#vpn_ip) | Đăng nhập từ dải IP VPN thương mại | Danh tiếng hạ tầng | thấp | shadow | experimental | T1090 |
| [`blocklist_hit`](#blocklist_hit) | Nguồn nằm trong blocklist | Danh tiếng hạ tầng | cao | enforce | verified | — |
| [`impossible_travel`](#impossible_travel) | Di chuyển bất khả thi | Ngữ cảnh tài khoản | cao | enforce | verified | T1078 |
| [`multi_context_simultaneous`](#multi_context_simultaneous) | Đăng nhập cùng lúc từ nhiều quốc gia | Ngữ cảnh tài khoản | cao | enforce | experimental | T1078 |
| [`country_hop`](#country_hop) | Tài khoản bị thử từ nhiều quốc gia | Ngữ cảnh tài khoản | trung bình | enforce | verified | T1078, T1090 |
| [`dormant_account_login`](#dormant_account_login) | Tài khoản ngủ đông đăng nhập lại | Ngữ cảnh tài khoản | trung bình | enforce | verified | T1078 |
| [`rare_network_login`](#rare_network_login) | Đăng nhập từ nhà mạng cực hiếm | Ngữ cảnh tài khoản | trung bình | shadow | experimental | T1078 |
| [`unusual_device`](#unusual_device) | Thiết bị chưa từng thấy | Hồ sơ hành vi | thấp | enforce | verified | T1078 |
| [`unusual_location`](#unusual_location) | Vị trí chưa từng thấy | Hồ sơ hành vi | trung bình | enforce | verified | T1078 |
| [`unusual_hour`](#unusual_hour) | Giờ đăng nhập khác thói quen | Hồ sơ hành vi | thấp | enforce | experimental | T1078 |
| [`login_velocity_spike`](#login_velocity_spike) | Đăng nhập thành công dồn dập bất thường | Hồ sơ hành vi | trung bình | enforce | verified | T1078 |

## 2. Cách hoạt động

- **Đầu vào duy nhất** của mọi luật là `LoginAttempt` (một lần thử đăng nhập đã chuẩn hoá: thời điểm SỰ KIỆN, tên đăng nhập, kết quả, IP, ASN, quốc gia, toạ độ, User-Agent...) và lịch sử tài khoản. Luồng thật (MR12), replay log lịch sử và test đều gọi cùng `RuleEngine.evaluate`; luật không biết dữ liệu đến từ đâu và **không bao giờ đọc nhãn** (`labels`) của log replay.
- **Thời gian là thời gian của sự kiện**, không phải giờ hệ thống: replay log năm 2020 cho đúng kết quả của năm 2020. Cửa sổ là (đầu, hiện tại] — sự kiện đúng bằng đầu cửa sổ không được tính.
- **Trạng thái cửa sổ thời gian** (đếm lần sai, đếm tên/IP/User-Agent khác nhau...) nằm ở `WindowStore`: `MemoryStore` cho replay và test, `RedisStore` cho luồng thật; một bộ test chung chứng minh hai cài đặt cùng hợp đồng và cho cùng kết quả trên lưu lượng ngẫu nhiên. Chi phí mỗi sự kiện bị chặn bởi ngưỡng, không tăng theo độ dài cửa sổ.
- **Ba chế độ** cho mỗi luật: `enforce` (khớp thì tạo cảnh báo), `shadow` (vẫn chạy và ghi nhận để đo tỉ lệ khớp/báo nhầm nhưng KHÔNG tạo cảnh báo), `off` (không chạy).
- **Kiểm chứng** (Phase 3): chỉ luật `enforce` + `verified` (đã qua `scripts/behavior_verification.py`, bằng chứng ở `artifacts/behavior_verification/`) TỰ tạo cảnh báo; luật `experimental` vẫn chạy, ghi `matched_rules`/`secondary_signals` và góp điểm hybrid nhưng không tự cảnh báo. Không luật nào tự step_up/lock — hành động do điểm hybrid quyết định.
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
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | `unusual_device`, `unusual_location`, `unusual_hour`, `login_velocity_spike`, `impossible_travel`, `multi_context_simultaneous`, `country_hop`, `dormant_account_login`, `rare_network_login` |
| [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | `distributed_bruteforce`, `country_hop`, `vpn_ip` |
| [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | Proxy: External Proxy | `datacenter_ip` |
| [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Proxy: Multi-hop Proxy | `tor_exit` |
| [T1589](https://attack.mitre.org/techniques/T1589/) | Gather Victim Identity Information | `username_enumeration` |
| — | không ánh xạ kỹ thuật cụ thể | `blocklist_hit` |

## 4. Dữ liệu cần có

Thiếu dữ liệu thì luật tương ứng bị bỏ qua (xem mục 2).

| Dữ liệu | Ý nghĩa | Luật cần |
|---|---|---|
| `account` | tài khoản tồn tại (không phải tên đăng nhập bịa) | `success_after_failures`, `unusual_device`, `unusual_location`, `unusual_hour`, `login_velocity_spike`, `impossible_travel`, `multi_context_simultaneous`, `dormant_account_login`, `rare_network_login` |
| `asn` | ASN của IP (cần file GeoLite2-ASN.mmdb) | `rare_network_login` |
| `country` | quốc gia của IP (GeoIP) | `unusual_location`, `multi_context_simultaneous`, `country_hop` |
| `geo` | toạ độ của IP (GeoLite2-City) | `impossible_travel` |
| `user_agent` | User-Agent của request | `ua_rotation`, `unusual_device` |
| `history` | lịch sử tài khoản (DB hoặc luồng sự kiện đã phát) | `unusual_device`, `unusual_location`, `unusual_hour`, `login_velocity_spike`, `impossible_travel`, `dormant_account_login` |
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
- **Ghi chú:** Ngưỡng và cửa sổ là luật tầng 1 gốc (docs/api-contract.md mục 6, giả định chưa đối chiếu). Báo ở MỖI lần sai từ lần thứ `threshold` trở đi; gộp cảnh báo trùng là việc của MR13. Milestone C: bỏ qua khi lần thành công của tài khoản chiếm > `max_success_ratio` trong cửa sổ — lộ ra từ lưu lượng bình thường v3 (tài khoản dùng chung kiểu kiosk: 5 lần gõ sai lẫn trong 4–9 lần đúng trong vài phút); dò mật khẩu thì gần như chỉ có thất bại. Alert tầng 1 gốc (`alert_type=brute_force`) KHÔNG đổi.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `threshold` | `5` | lần | 2–1000 | số lần sai tối thiểu để báo |
| `window_s` | `300` | giây | 10–86400 | độ dài cửa sổ |
| `max_success_ratio` | `0.2` | — | 0–1 | quá tỉ lệ lần THÀNH CÔNG của tài khoản trong cửa sổ này thì coi là tài khoản dùng chung gõ sai lẫn trong nhiều lần đúng |

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
- **Ghi chú:** Người dùng thật cũng gõ sai vài lần rồi đúng; ngưỡng 5 (cao hơn mức 3 của điểm rủi ro tầng 2) để giảm báo nhầm. Milestone C: bỏ qua khi các lần thành công XEN GIỮA chiếm > `max_prior_success_ratio` — lộ ra từ lưu lượng bình thường v3: tài khoản dùng chung kiểu kiosk (nhiều người, nhiều lần đúng, lẫn vài lần gõ sai) có 4–9 lần thành công xen giữa 5–6 lần sai trong 10 phút; đoán mật khẩu thì thất bại áp đảo rồi mới trúng (0 lần xen giữa).

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `600` | giây | 10–86400 | độ dài cửa sổ nhìn lại |
| `min_fails` | `5` | lần | 2–100000 | số lần sai tối thiểu trước đó vào tài khoản |
| `max_prior_success_ratio` | `0.2` | — | 0–1 | quá tỉ lệ lần THÀNH CÔNG xen giữa này (trên tổng lần thử trước đó trong cửa sổ) thì coi là tài khoản dùng chung gõ sai lẫn trong nhiều lần đúng, không phải đoán trúng |

### Tự động hoá

#### <a id="bot_user_agent"></a>`bot_user_agent` — User-Agent là bot

User-Agent được thư viện phân tích UA nhận là bot/trình thu thập tự động.

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Chỉ dựa vào UA nên kẻ tấn công nói dối UA là né được; giá trị là bắt các bot lười.

#### <a id="scripted_client"></a>`scripted_client` — Client kịch bản / công cụ

User-Agent thuộc một công cụ HTTP/dò quét ĐÃ BIẾT (curl, python-requests, HTTPie, Hydra, trình duyệt không đầu...).

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Milestone B (B0.2): User-Agent TRỐNG không còn được coi là client kịch bản — đó là THIẾU telemetry (proxy/SDK có thể bỏ header), không phải bằng chứng tự động hoá; pipeline ghi `telemetry_gaps=["missing_user_agent"]` trong giải thích cảnh báo thay vào đó. `okhttp` cố ý không nằm trong danh sách (thư viện của ứng dụng Android thật). Các script demo trong attack-sim/ dùng httpx nên khớp luật này.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `markers` | `curl/, wget/, httpie/, python-requests, python-urllib, python-httpx, aiohttp, go-http-client, … (27 mục)` | — | — | chuỗi con (chữ thường) của User-Agent coi là client kịch bản |
| `flag_empty_ua` | `false` | — | — | coi User-Agent trống là client kịch bản (mặc định KHÔNG: thiếu UA chỉ là thiếu telemetry) |

#### <a id="ua_rotation"></a>`ua_rotation` — Xoay User-Agent

Cùng một IP thất bại đăng nhập nhiều lần với NHIỀU họ User-Agent khác nhau trong thời gian ngắn, gần như không có lần thành công — công cụ tấn công đổi UA để né nhận diện. Đếm HỌ đã chuẩn hoá (loại thiết bị | HĐH | trình duyệt, bỏ phiên bản).

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110.004 (Brute Force: Credential Stuffing)
- **Dữ liệu cần:** `user_agent`
- **Ghi chú:** Milestone B: (1) đếm họ UA chuẩn hoá — cập nhật phiên bản trình duyệt không còn bị tính là UA khác; (2) bỏ qua khi tỉ lệ thành công của IP > `max_success_ratio`: NAT dùng chung có nhiều người gõ sai nhưng phần lớn là đăng nhập thành công, công cụ xoay UA thì gần như chỉ thất bại. Là tín hiệu ĐÁNH DẤU (tự động hoá): khi nhồi thông tin/brute force cũng khớp, hành vi đó làm detector chính, ua_rotation là tín hiệu phụ.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `600` | giây | 10–86400 | độ dài cửa sổ |
| `min_distinct_ua` | `5` | UA | 2–1000 | số User-Agent (họ chuẩn hoá nếu `canonical_agents`) khác nhau tối thiểu |
| `min_fails` | `8` | lần | 2–100000 | số lần sai tối thiểu của IP |
| `canonical_agents` | `true` | — | — | đếm HỌ User-Agent chuẩn hoá thay vì chuỗi thô (Chrome 120/121 là một) |
| `max_success_ratio` | `0.2` | — | 0–1 | quá tỉ lệ đăng nhập thành công này của IP trong cửa sổ thì coi là lưu lượng người dùng thật (NAT dùng chung) |

#### <a id="regular_rhythm"></a>`regular_rhythm` — Nhịp thử đều như máy

Các lần đăng nhập SAI gần nhất từ một IP cách nhau đều đặn và dày (độ lệch chuẩn nhỏ so với trung bình) — con người không gõ đều đến vậy.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1110 (Brute Force)
- **Dữ liệu cần:** không (chỉ cần `LoginAttempt`)
- **Ghi chú:** Milestone C+: kiểm chứng trên kịch bản tổng hợp (20 dương tính / 20 âm tính sát ngưỡng / lưu lượng bình thường v3) — chưa kiểm chứng trên log thật. Là tín hiệu ĐÁNH DẤU: khi brute force/nhồi thông tin/Tor cùng khớp thì chúng làm detector chính. Máy có jitter ngẫu nhiên lớn (CV > 0,15) hoặc chậm hơn 30s/lần sẽ né được; dịch vụ cấu hình sai mật khẩu thử lại đều đặn sẽ khớp.

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

Một tên đăng nhập bị thử SAI từ nhiều quốc gia khác nhau trong 24 giờ — proxy xoay vòng theo nước hoặc botnet toàn cầu. Mặc định chỉ đếm lần THẤT BẠI: người đi công tác đăng nhập ĐÚNG ở nhiều nước không phải dấu hiệu tấn công.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts), T1090 (Proxy)
- **Dữ liệu cần:** `country`
- **Ghi chú:** Milestone B: chỉ khớp ở lần thử THẤT BẠI và chỉ đếm quốc gia của lần thất bại (`failures_only`) — trước đó đếm cả lần thành công nên khách du lịch hợp lệ có thể khớp. Người dùng VPN đổi nước liên tục vẫn có thể khớp nếu gõ sai nhiều lần.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `window_s` | `86400` | giây | 600–604800 | độ dài cửa sổ |
| `min_countries` | `3` | nước | 2–50 | số quốc gia khác nhau tối thiểu |
| `failures_only` | `true` | — | — | chỉ đếm quốc gia của các lần thử THẤT BẠI (false = mọi lần thử, hành vi trước Milestone B) |

#### <a id="dormant_account_login"></a>`dormant_account_login` — Tài khoản ngủ đông đăng nhập lại

Tài khoản không có lần đăng nhập thành công nào trong nhiều tháng bỗng đăng nhập lại (mặc định chỉ báo khi kèm quốc gia hoặc thiết bị chưa từng thấy).

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `history`
- **Ghi chú:** Người dùng thật quay lại sau kỳ nghỉ là chuyện thường: mặc định phải kèm dấu hiệu 'mới' để giảm báo nhầm. Thiết bị so theo HỌ chuẩn hoá (Milestone C, cùng unusual_device): chỉ cập nhật phiên bản trình duyệt không phải thiết bị mới.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `dormant_days` | `90` | ngày | 1–3650 | số ngày không đăng nhập thành công để coi là ngủ đông |
| `require_change` | `true` | — | — | chỉ báo khi lần này có quốc gia hoặc thiết bị mới so với lịch sử |

#### <a id="rare_network_login"></a>`rare_network_login` — Đăng nhập từ nhà mạng cực hiếm

Đăng nhập THÀNH CÔNG từ một ASN (nhà mạng) hiếm so với toàn hệ thống, theo mức trưởng thành của dữ liệu: COLD_START (quá ít lượt thành công toàn hệ thống) không chấm; WARM: ASN chưa từng có trong lịch sử thành công của CHÍNH tài khoản (hồ sơ đã trưởng thành) VÀ chiếm ≤ `warm_max_share` lượt thành công toàn hệ thống; MATURE: tỉ lệ toàn hệ thống ≤ `max_share` (luật gốc).

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** shadow (chỉ ghi nhận)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `asn`, `global_stats`
- **Ghi chú:** Thêm theo quyết định D3 ở CP2. Trên RBA, luật một đặc trưng `rare_asn` với ngưỡng ở phân vị 99 của đăng nhập hợp lệ bắt 65,8% trong 38 ATO tương lai (chẩn đoán MR7, chọn sau khi đã thấy ATO) nhưng ATO của bộ dữ liệu tổng hợp đến từ nhà mạng hiếm một cách nhân tạo, nên đánh giá luật trên ATO của RBA mang tính vòng tròn. Ngưỡng MATURE 2e-5 ≈ phân vị 99 của đăng nhập hợp lệ ở RBA. Milestone C+ (thiết kế C7 ở Phase 2): thêm COLD_START/WARM — trước đó luật cần 20.000 lượt thành công nên không bao giờ khớp ở DB demo. Người dùng thật đổi sang nhà mạng hiếm (wifi khách sạn, nhà mạng nhỏ) sẽ khớp ở WARM.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `min_successes` | `10` | lần | 1–10000 | số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành |
| `min_profile_days` | `7` | ngày | 0–3650 | tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên) |
| `warm_min_total` | `500` | lần | 10–100000000 | số đăng nhập thành công toàn hệ thống tối thiểu để thoát COLD_START (ít hơn thì không chấm) |
| `warm_max_share` | `0.01` | — | 0–0.5 | WARM: tỉ lệ đăng nhập thành công toàn hệ thống từ ASN này (bằng hoặc thấp hơn thì coi là hiếm) |
| `max_share` | `2e-05` | — | 0–0.01 | MATURE: tỉ lệ đăng nhập thành công của cả hệ thống từ ASN này (bằng hoặc thấp hơn thì báo) |
| `min_total` | `20000` | lần | 100–100000000 | số đăng nhập thành công toàn hệ thống tối thiểu để vào MATURE (luật gốc theo tỉ lệ toàn hệ thống) |

### Hồ sơ hành vi

#### <a id="unusual_device"></a>`unusual_device` — Thiết bị chưa từng thấy

Đăng nhập THÀNH CÔNG từ một thiết bị (họ chuẩn hoá: loại thiết bị | hệ điều hành | trình duyệt, bỏ phiên bản) mà tài khoản CHƯA từng đăng nhập thành công, khi hồ sơ của tài khoản đã trưởng thành.

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `history`, `user_agent`
- **Ghi chú:** Thiết bị chuẩn hoá theo họ nên cập nhật phiên bản (Chrome 120 → 121) KHÔNG phải thiết bị mới; User-Agent không nhận diện được giữ nguyên làm họ riêng. Không phân biệt được người dùng MUA thiết bị mới với kẻ tấn công — vì vậy mức thấp, chỉ cảnh báo, không tự step_up/lock. Khi một hành vi tấn công rõ hơn cùng khớp (impossible_travel, tài khoản ngủ đông...), hành vi đó làm detector chính và unusual_device là bằng chứng bổ trợ.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `min_successes` | `10` | lần | 1–10000 | số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành |
| `min_profile_days` | `7` | ngày | 0–3650 | tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên) |

#### <a id="unusual_location"></a>`unusual_location` — Vị trí chưa từng thấy

Đăng nhập THÀNH CÔNG từ một QUỐC GIA chưa từng xuất hiện trong lịch sử đăng nhập thành công của tài khoản, khi hồ sơ đã trưởng thành. Thành phố mới trong một quốc gia đã quen không bị coi là lạ.

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `history`, `country`
- **Ghi chú:** So với TOÀN BỘ hồ sơ vị trí (mọi quốc gia/thành phố từng đăng nhập thành công, kèm số lần/thấy lần đầu/lần cuối), không chỉ lần trước. Thiếu GeoIP (không có quốc gia) thì bỏ qua. Không phân biệt được chuyến đi hợp lệ ĐẦU TIÊN tới một nước với kẻ tấn công — mức trung bình, chỉ cảnh báo. Hai lần thành công cách nhau quá xa so với thời gian là impossible_travel (detector chính), vị trí mới là bằng chứng bổ trợ.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `min_successes` | `10` | lần | 1–10000 | số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành |
| `min_profile_days` | `7` | ngày | 0–3650 | tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên) |

#### <a id="unusual_hour"></a>`unusual_hour` — Giờ đăng nhập khác thói quen

Đăng nhập THÀNH CÔNG vào một giờ nằm NGOÀI mọi khung giờ mà CHÍNH tài khoản đã từng đăng nhập thành công (histogram 24 giờ làm mượt vòng tròn), khi hồ sơ đã trưởng thành và có khung giờ rõ ràng. Không có giờ nào 'luôn nguy hiểm': người làm ca đêm có khung giờ ban đêm; người có nhiều khung giờ (sáng, trưa, tối) được coi là bình thường ở cả ba.

- **Mức nghiêm trọng:** thấp · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `history`
- **Ghi chú:** Milestone C.1 thay detector 3σ quanh giờ trung tâm (giả định một cụm đối xứng — báo nhầm 32 lần trên lưu lượng bình thường v3, artifacts/candidates/unusual_hour/fp_analysis.json). Hồ sơ = histogram 24 ô theo giờ UTC, CHỈ học từ lần thành công. Giờ tính theo UTC nhất quán cho cả hồ sơ và lần đăng nhập (hệ thống không có múi giờ người dùng; không mô phỏng DST). Một lần thành công duy nhất ở một giờ đã đủ đưa giờ đó (± bán kính) vào khung quen.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `min_successes` | `10` | lần | 1–10000 | số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành |
| `min_profile_days` | `7` | ngày | 0–3650 | tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên) |
| `smoothing_hours` | `2` | giờ | 0–6 | bán kính làm mượt vòng tròn của histogram giờ (nhân tam giác): giờ cách một lần thành công ≤ bán kính thuộc khung giờ đã thiết lập |
| `max_coverage` | `0.75` | — | 0–1 | tỉ lệ tối đa của 24 giờ đã thuộc khung giờ quen; vượt mức này hồ sơ quá phân tán — NOT_APPLICABLE, không cảnh báo |

#### <a id="login_velocity_spike"></a>`login_velocity_spike` — Đăng nhập thành công dồn dập bất thường

NHIỀU lần đăng nhập THÀNH CÔNG vào cùng một tài khoản trong 10 phút, vượt hẳn đỉnh lịch sử của chính tài khoản trong cùng độ dài cửa sổ. Khác brute_force (nhiều lần THẤT BẠI): đây là phiên đăng nhập hợp lệ bị dùng dồn dập (bot dùng thông tin đăng nhập đã chiếm được, chia sẻ tài khoản...).

- **Mức nghiêm trọng:** trung bình · **chế độ mặc định:** enforce (tạo cảnh báo)
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Dữ liệu cần:** `account`, `history`
- **Ghi chú:** Cửa sổ cố định 600s để so cùng độ dài với đỉnh lịch sử (`AccountHistory.baseline_peak`: chỉ các cửa sổ kết thúc TRƯỚC cửa sổ hiện tại, nên chính đợt dồn dập không tự nâng nền; chỉ học từ lần thành công — lần thất bại không làm tăng nền). Tài khoản dịch vụ/lập trình viên có đỉnh lịch sử cao nên cần dồn dập hơn hẳn mới khớp. Chỉ sự kiện XÁC THỰC (/login) được tính; làm mới phiên/token không đi qua pipeline này.

| Tham số | Mặc định | Đơn vị | Khoảng | Ý nghĩa |
|---|---|---|---|---|
| `min_successes` | `10` | lần | 1–10000 | số lần đăng nhập thành công tối thiểu để hồ sơ được coi là trưởng thành |
| `min_profile_days` | `7` | ngày | 0–3650 | tuổi hồ sơ tối thiểu (từ lần thành công đầu tiên) |
| `min_successes_in_window` | `8` | lần | 2–10000 | số lần thành công tối thiểu trong cửa sổ 10 phút (gồm lần này) |
| `min_velocity_ratio` | `2` | lần | 1–100 | tối thiểu số lần gấp ĐỈNH lịch sử của tài khoản trong cùng cửa sổ |
