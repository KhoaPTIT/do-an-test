# attack-sim — Script giả lập tấn công (nhiệm vụ 6.1)

4 script test hệ thống tự phát hiện đúng loại tấn công tương ứng. Chạy
bằng venv của backend (đã có `httpx` cài sẵn):

```bash
cd backend
venv\Scripts\activate
cd ..\attack-sim

python brute_force.py --target user001
python credential_stuffing.py
python success_after_fail.py --target user001 --correct-password Demo@12345
python impossible_travel.py --target user001 --password Demo@12345
```

Trên Windows, thêm `set PYTHONIOENCODING=utf-8` trước nếu chữ tiếng Việt bị lỗi.

| Script | Kịch bản | Alert kỳ vọng |
|---|---|---|
| `brute_force.py` | Nhiều lần sai mật khẩu, cùng 1 tài khoản | `brute_force` |
| `credential_stuffing.py` | Nhiều username khác nhau, cùng 1 IP | `credential_stuffing` |
| `success_after_fail.py` | Chuỗi fail rồi đăng nhập đúng ngay sau | `high_risk_score` (risk score +50) |
| `impossible_travel.py` | 2 vị trí cách xa nhau, đăng nhập gần như đồng thời | `impossible_travel` |

Mọi script đều nhận `--base-url` và `--delay` (giây nghỉ giữa các request)
để chỉnh tốc độ khi trình diễn trực tiếp — xem `common.py`.

`impossible_travel.py` cần backend bật `TRUST_FORWARDED_FOR=true` trong
`.env` (mặc định TẮT, chỉ dùng demo cục bộ — xem cảnh báo trong
`backend/app/config.py` và `docs/api-contract.md` mục 3).

Kết quả kiểm thử end-to-end đầy đủ (bảng test case, lỗi phát hiện & đã
sửa): [`docs/e2e-test-report.md`](../docs/e2e-test-report.md).
