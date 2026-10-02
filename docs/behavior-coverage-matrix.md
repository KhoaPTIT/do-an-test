# Ma trận phủ hành vi (cập nhật cuối — Phase 3, kết thúc bổ sung hành vi phát hiện)

Bảng DUY NHẤT trả lời "hành vi X có được phát hiện không, bằng detector nào, đo được tới đâu". Bản này thay bản MR19
(xem lịch sử git của file này): ở MR19 nhiều hành vi chỉ "có luật" hoặc khớp luật nhưng **không tạo cảnh báo đúng luật**;
Phase 3 đo lại MỌI hành vi qua pipeline `/login` thật theo QUY KẾT, với bằng chứng do máy sinh.

**Kết quả cuối: 20 hành vi VERIFIED / 21 hành vi đo được qua pipeline** (1 PARTIAL: `unusual_hour`). Phát triển hành vi
phát hiện dừng ở đây (Milestone C+ là milestone bổ sung hành vi cuối cùng) — không mở thêm milestone hành vi.

Bằng chứng: [`artifacts/behavior_verification/`](../artifacts/behavior_verification/) — sinh bởi
`cd backend && python -m scripts.behavior_verification` trên worktree sạch tại commit `a465dfb`
(`summary.json`, một file `<hành vi>.json` cho mỗi hành vi, `cross_behavior_results.json`, `normal_traffic.json`,
`milestone_cplus_summary.json`). Không số nào trong bảng được sửa tay.

## Tiêu chí VERIFIED (giữ nguyên suốt Phase 3)

Một hành vi chỉ VERIFIED khi đạt **cả năm** điều kiện:

1. ≥ 20 kịch bản dương tính, recall ≥ 90% — "phát hiện" = có cảnh báo với `rule_id` == ĐÚNG detector (cảnh báo của
   detector khác không được tính);
2. ≤ 1/20 báo nhầm trên kịch bản âm tính SÁT NGƯỠNG (ngưỡng − 1, ngoài cửa sổ, người dùng thật dễ nhầm...);
3. **0** cảnh báo của detector đó trên lưu lượng bình thường (63 người dùng × 30 ngày, 5.647 lần đăng nhập, 2.053
   lần lịch sử — `verification/normal_traffic.py` v3, chốt trước khi đo Milestone C và không sửa sau đó);
4. quy kết đúng ≥ 90% (mọi lần detector khớp ở chế độ enforce đều có `primary_detector` == detector đó);
5. cảnh báo thật đi qua pipeline (`run_detection_pipeline` → rule engine → hybrid → attribution → bảng `alerts`), không
   dùng nhãn kịch bản trong detector.

Luật `experimental` (chưa VERIFIED) không tự tạo cảnh báo; tạo cảnh báo không bao giờ đổi hành động `step_up`/`lock`
(do điểm hybrid quyết định, điểm dùng mọi luật khớp kể cả `shadow`).

## Bảng — 21 hành vi đo qua pipeline

| # | Hành vi tấn công | Detector | Milestone | Trạng thái | TP/20 | FP âm tính | Recall | Quy kết | Báo nhầm lưu lượng bình thường |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Dò mật khẩu một tài khoản | `brute_force` | baseline | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 2 | Nhồi thông tin đăng nhập | `credential_stuffing` | baseline | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 3 | Nguồn trong blocklist | `blocklist_hit` | baseline | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 4 | Di chuyển bất khả thi | `impossible_travel` | baseline | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 5 | Dò danh sách tài khoản | `username_enumeration` | A | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 6 | Rải mật khẩu chậm | `password_spray_slow` | A | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 7 | Dò mật khẩu phân tán (botnet) | `distributed_bruteforce` | A | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 8 | Thành công sau chuỗi sai | `success_after_failures` | A | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 9 | Tài khoản ngủ đông đăng nhập lại | `dormant_account_login` | A | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 10 | Tor exit node | `tor_exit` | A | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 11 | Tài khoản bị thử từ nhiều quốc gia | `country_hop` | B | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 12 | Xoay User-Agent | `ua_rotation` | B | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 13 | Client kịch bản (curl, python-requests…) | `scripted_client` | B | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 14 | Bot User-Agent | `bot_user_agent` | B | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 15 | Thiết bị lạ | `unusual_device` | B | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 |
| 16 | Vị trí (quốc gia) lạ | `unusual_location` | C | ✅ VERIFIED | 19 | 0/20 | 0,95 | 1,00 | 0 |
| 17 | Đăng nhập thành công dồn dập | `login_velocity_spike` | C | ✅ VERIFIED | 19 | 0/20 | 0,95 | 1,00 | 0 |
| 18 | Giờ đăng nhập lạ | `unusual_hour` | C / C.1 | 🌓 **PARTIAL** | 20* | 0/20* | 1,00* | 1,00* | **4*** |
| 19 | Nhịp thử đều như máy | `regular_rhythm` | C+ | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 † |
| 20 | Nhà mạng (ASN) cực hiếm | `rare_network_login` | C+ | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 † |
| 21 | Đăng nhập cùng lúc từ nhiều quốc gia | `multi_context_simultaneous` | C+ | ✅ VERIFIED | 20 | 0/20 | 1,00 | 1,00 | 0 † |

"baseline" = 4 hành vi VERIFIED ở audit Phase 1, đo lại ở Milestone A. Mỗi bộ 20+20 kịch bản dùng seed cố định
(`verification/scenarios.py`).

\* `unusual_hour` vẫn `experimental` nên ở lần chạy chính thức không tự tạo cảnh báo (`unusual_hour.json` ghi recall 0 —
do trạng thái, không phải do detector). Số có dấu \* là detector hiện tại (histogram 24 giờ, Milestone C.1) đo ở trạng
thái ứng viên trên CÙNG bộ đánh giá ([`unusual_hour_comparison.json`](../artifacts/behavior_verification/unusual_hour_comparison.json)):
detector 3σ cũ báo nhầm 32 lần, histogram còn **4** (cả 4 thuộc nhóm `TAIL_EXTENSION` — đăng nhập muộn hơn mọi lần trước
2,1–4,1 giờ, [`unusual_hour_fp_analysis.json`](../artifacts/behavior_verification/unusual_hour_fp_analysis.json)) ⇒ chưa
đạt "0 báo nhầm" ⇒ PARTIAL; không chỉnh ngưỡng để ép VERIFIED.

† Lưu lượng bình thường THỬ THÁCH yếu ba detector C+ — tính thẳng từ dữ liệu sinh ra, ghi ở
`milestone_cplus_summary.json` → `normal_traffic_exposure`:

| Detector | Tình huống gần ngưỡng trong lưu lượng bình thường | Nghĩa của "0 báo nhầm" |
|---|---|---|
| `regular_rhythm` | 22 IP có ≥ 10 lần sai, nhưng khoảng cách trung bình nhỏ nhất trên 10 lần sai liên tiếp là 564 giây (ngưỡng 30 giây) | không có tình huống nào gần ngưỡng |
| `rare_network_login` | chỉ 3 lần tài khoản trưởng thành đăng nhập từ nhà mạng mới với chính nó; tỉ lệ toàn hệ thống 1,96%, 5,82%, 25,9% (ngưỡng 1%) | bằng chứng yếu (3 ca, ca gần nhất cách ngưỡng ~2 lần) |
| `multi_context_simultaneous` | 0 cặp đăng nhập thành công ở hai quốc gia trong 1 giờ | không phải bằng chứng — sức nặng nằm ở 20 kịch bản âm tính |

## Quy kết khi nhiều detector cùng khớp — cross-behavior 19/19

Khi nhiều detector khớp cùng một chuỗi sự kiện, cảnh báo quy cho detector đặc hiệu nhất (`attribution.PRIORITY`: đoán/dò
mật khẩu → ngữ cảnh tài khoản → dồn dập → dấu hiệu hạ tầng/tự động hoá → hồ sơ hành vi), các detector còn lại vẫn nằm trong
`secondary_signals` (hoặc `superseded_detectors` khi bị tiếp quản), và cả chuỗi là MỘT cảnh báo chiến dịch.
[`cross_behavior_results.json`](../artifacts/behavior_verification/cross_behavior_results.json): 19/19 ca đúng, gồm 6 ca
Milestone C+ (`regular_rhythm` + `scripted_client`; `brute_force` + `regular_rhythm`; `rare_network_login` +
`unusual_location` / `unusual_device`; `impossible_travel` + `multi_context_simultaneous`; `multi_context_simultaneous` +
`unusual_location` khi thiếu toạ độ).

## Không VERIFIED / ngoài phạm vi (giữ nguyên trạng thái, không làm tiếp)

| Hành vi | Trạng thái | Lý do |
|---|---|---|
| Giờ đăng nhập lạ (`unusual_hour`) | 🌓 PARTIAL (`experimental`) | 4 báo nhầm trên lưu lượng bình thường (mục trên) |
| IP datacenter (`datacenter_ip`) | 🌓 SHADOW | không thuộc 3 hành vi Milestone C+ đã chọn (quyết định của người dùng) — dễ báo nhầm VPN doanh nghiệp |
| VPN thương mại (`vpn_ip`) | 🌓 SHADOW | như trên |
| Mô phỏng tinh vi (`targeted_mimic`, MR18) | 🌓 mơ hồ | không có luật phù hợp; chỉ tín hiệu ML yếu — cố ý giữ kết quả mơ hồ |
| Chiếm tài khoản thật trên bộ RBA | — | đánh giá MÔ HÌNH offline (`hybrid_cp2`: recall 36,8% @ FPR 1%, `ml-evaluation-v2.md`), không phải hành vi chạy qua pipeline |
| Tầng 3 ML (`ml_anomaly`, mô hình B) | — | TẮT trong mọi phép đo Phase 3 (harness dùng hồ sơ dự phòng của hybrid) — số đo tầng 3 vẫn ở `ml-evaluation.md` / `model-b-geo-time.md` |

## Khoảng trống của bản MR19 — đã xử lý tới đâu

1. `username_enumeration` không tạo được cảnh báo (MR18) → **đã sửa**: luật `enforce` + VERIFIED tạo cảnh báo trực tiếp
   (`alert_reason="rule_enforced"`), không cần hạ ngưỡng điểm hybrid.
2. `distributed_bruteforce` trọng số hybrid 0 → **VERIFIED** bằng luật xác định (trọng số giữ nguyên số đã hiệu chỉnh,
   không sửa cho đẹp); botnet CÙNG khu vực địa lý có trong kịch bản dương tính.
3. ATO ở tài khoản chưa có lịch sử: 0% recall → **vẫn là khoảng trống** (thuộc mô hình, ngoài phạm vi bổ sung hành vi).
4. `rapid_fire` (tầng 3) yếu → thay bằng luật `login_velocity_spike` (**VERIFIED**).
5. Kẻ bắt chước hoàn hảo → **vẫn là giới hạn kiến trúc**.
6. 5 luật `shadow` → `country_hop`, `regular_rhythm`, `rare_network_login` **đã enforce + VERIFIED**; `datacenter_ip`,
   `vpn_ip` vẫn `shadow`.
7. Tầng 3 không thấy hạ tầng/tốc độ → không đổi (tầng 3 ngoài phạm vi Phase 3).

## Giới hạn chung (đọc trước khi trích dẫn)

- **Dữ liệu tổng hợp:** kịch bản và lưu lượng bình thường do chính người viết detector thiết kế, dựa trên ngưỡng đã
  biết. VERIFIED chứng minh IMPLEMENTATION + PIPELINE + QUY KẾT đúng trên định nghĩa hành vi; KHÔNG chứng minh tỉ lệ phát
  hiện/báo nhầm trên tấn công và người dùng thật. "0 báo nhầm" là điều kiện CẦN.
- **Telemetry là TEST FIXTURE:** GeoIP/ASN/threat intel giả lập (dải RFC 5737, 198.18.0.0/24 cho IP GeoIP chỉ biết quốc
  gia, ASN private). GeoIP thật (GeoLite2) và danh sách thật cũ dần theo thời gian.
- **Không có múi giờ người dùng:** hồ sơ giờ tính theo UTC; không mô phỏng DST/đổi múi giờ.
- **Nguồn báo nhầm thật đã biết nhưng không mô phỏng:** VPN trên một thiết bị + thiết bị khác không VPN
  (`multi_context_simultaneous`), wifi khách sạn/nhà mạng nhỏ (`rare_network_login` ở WARM), dịch vụ cấu hình sai mật khẩu
  thử lại đều đặn (`regular_rhythm`), IP di động CGNAT định vị sai thành phố (`impossible_travel`).
- **`rare_network_login`:** chỉ trạng thái WARM (500–20.000 lượt thành công toàn hệ thống) được kiểm chứng bằng kịch bản;
  MATURE (≥ 20.000) chỉ có test đơn vị.
- **Alert tầng 1/2 cũ** (`high_risk_score`, `brute_force` tầng 1...) không đi qua gộp chiến dịch: lưu lượng bình thường
  vẫn sinh 114 `high_risk_score` + 6 `brute_force` tầng 1 — chỉ đo, không refactor
  ([`alert_noise_final.json`](../artifacts/behavior_verification/alert_noise_final.json)).

## Tái lập

```bash
cd backend
python -m scripts.behavior_verification                       # 21 hành vi + cross-behavior + nghiên cứu unusual_hour (~45 phút)
python -m scripts.behavior_verification --only regular_rhythm  # một hành vi (gộp vào summary.json sẵn có)
python -m pytest tests/behavior_detection/                     # test hành vi (dương tính, âm tính, biên, quy kết, đầu độc hồ sơ)
```

Đo một detector chưa VERIFIED ở trạng thái như sau khi nâng cấp (chỉ trong tiến trình đo, không đổi registry):
`--candidates <rule_id>`. Số đo ứng viên trước khi nâng cấp từng luật: [`artifacts/candidates/`](../artifacts/candidates/).
Mốc tổng hợp các milestone trước: [`artifacts/milestones/`](../artifacts/milestones/).
