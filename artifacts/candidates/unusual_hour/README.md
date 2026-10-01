# unusual_hour — đo ở trạng thái ỨNG VIÊN (Milestone C)

Sinh bởi `python -m scripts.behavior_verification --only unusual_hour --candidates unusual_hour` trên worktree sạch tại
cùng commit với bằng chứng chính thức trong `artifacts/behavior_verification/`.

`--candidates` bật detector như thể đã được nâng cấp (enforce + verified) **chỉ trong tiến trình đo** — registry vẫn để
`unusual_hour` ở `experimental`, nên ở lần chạy chính thức nó không tự tạo cảnh báo (recall 0 ở đó là do trạng thái, không
phải do detector). Kết quả ứng viên: 20/20 dương tính, 0/20 âm tính sát ngưỡng, nhưng **32 báo nhầm trên lưu lượng bình
thường** ⇒ không đạt tiêu chí VERIFIED, giữ PARTIAL. Không hạ/nâng ngưỡng sau khi xem kết quả.

## Milestone C.1 — BASELINE trước khi sửa

Các file `unusual_hour.json`, `normal_traffic.json`, `summary.json` ở đây là BASELINE của detector 3σ (a58bc12):
TP 20, FN 0, FP kịch bản 0, TN 20, recall 1,00, quy kết 1,00, **32 báo nhầm trên lưu lượng bình thường**, PARTIAL.

`fp_analysis.json`: phân tích cả 32 báo nhầm (giờ hiện tại, các giờ đăng nhập thành công trước đó, số mẫu, tuổi hồ sơ,
giờ trung tâm, độ phân tán, ngưỡng, độ lệch, lý do detector khớp, nhóm nguyên nhân) — sinh bởi
`python -m verification.unusual_hour_study --detector legacy_sigma --fp-analysis fp_analysis.json` trên worktree sạch, ở
commit TRƯỚC khi detector được sửa. So sánh cũ/mới cuối cùng: `artifacts/behavior_verification/unusual_hour_comparison.json`.
