# Mốc so sánh nhiễu cảnh báo (Milestone B — B9)

Hai tệp `summary.json` do `backend/scripts/behavior_verification.py` sinh ra, chép NGUYÊN VĂN (không sửa tay):

| Tệp | Mã được đo | Cách chạy |
|---|---|---|
| `before_b0_summary.json` | mã Milestone A (commit `7b692a9`) | git worktree tại `7b692a9` + runner/bộ kịch bản của Milestone B (để cùng bộ kịch bản và cùng cách đo) |
| `after_b0_summary.json` | mã sau B0 (nội dung commit `9ff7311`) | runner chạy trên cây làm việc ngay trước khi commit B0 (trường `git` ghi commit cha + `dirty: true`) |

`alert_noise_comparison.json` ở `artifacts/behavior_verification/` được runner tự sinh từ hai tệp này + lần chạy cuối.
