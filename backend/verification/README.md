# Kiểm chứng hành vi (Phase 3)

Hạ tầng đo "hành vi X có được phát hiện THẬT không, quy kết đúng detector không" — qua **pipeline thật**
(`run_detection_pipeline` → rule engine → hybrid risk engine → `app/detection/attribution.py` → bảng `alerts`).
Detector (`app/detection/*`) không import gì từ thư mục này.

| Thành phần | Vai trò |
|---|---|
| `harness.py` | Môi trường cô lập (SQLite in-memory + fakeredis), vá nguồn telemetry sang fixture, ghi lại verdict thật từng lần thử |
| `scenarios.py` | Bộ sinh 20 kịch bản dương tính + 20 âm tính/hành vi, seed cố định |
| `normal_traffic.py` | Lưu lượng bình thường tổng hợp: 50 người dùng × 30 ngày |
| `../scripts/behavior_verification.py` | Runner: chấm TP/FP/TN/FN, precision/recall/F1, quy kết; ghi `artifacts/behavior_verification/*.json` |
| `../tests/behavior_detection/` | Test positive / negative / boundary / attribution cho từng hành vi |

## Ba loại dữ liệu — KHÔNG được lẫn

| Loại | Vị trí | Dùng cho | Ghi chú |
|---|---|---|---|
| **TEST FIXTURE** | `backend/verification/fixtures/` (`geoip.json`, `threat_intel/`) | pytest, verification runner | Dải địa chỉ tài liệu RFC 5737 + ASN private RFC 6996. Có tệp `TEST_FIXTURE.txt`; `ThreatIntel.status()` báo `data_kind="fixture"` |
| **DEMO DATA** | `backend/threat_intel_demo/` | Demo cục bộ (`THREAT_INTEL_DIR=threat_intel_demo`) | **Không phải threat intelligence thực tế.** Có tệp `DEMO_DATA.txt`; khởi động sẽ log cảnh báo `data_kind="demo"` |
| **RUNTIME / REAL** | `backend/threat_intel/` (ngoài git), `backend/geoip/*.mmdb` (ngoài git) | Vận hành thật | Tải bằng `python -m scripts.update_threat_feeds`; GeoLite2 tải riêng (license MaxMind) |

Không luật nào chứa địa chỉ IP: luật chỉ tra danh sách đã nạp. Fixture chỉ cung cấp **telemetry** (vị trí, ASN,
danh sách danh tiếng, lịch sử đăng nhập) — nhãn tấn công (`Scenario.behavior/kind`) chỉ runner đọc để chấm điểm.

## Giới hạn tự thừa nhận

- Kịch bản do chính người viết detector thiết kế dựa trên ngưỡng đã biết → recall cao chứng minh **implementation +
  pipeline + quy kết đúng**, không chứng minh hiệu quả trên tấn công thật.
- Lưu lượng bình thường là tổng hợp: 0 báo nhầm là điều kiện cần, không phải tỉ lệ báo nhầm ngoài thực tế.
- Thành phần ML của hybrid (`hybrid_cp2`, cần bộ RBA ~9GB) bị tắt trong môi trường kiểm chứng — kết quả không phụ thuộc nó.
- Các luật danh tiếng (tor/datacenter/vpn) được kiểm chứng với danh sách **fixture**: chứng minh luật hoạt động khi có
  danh sách, **không** chứng minh độ phủ hay tỉ lệ báo nhầm của danh sách thật.

Chạy: `cd backend && python -m scripts.behavior_verification` (≈15 phút) · `python -m pytest tests/behavior_detection`
