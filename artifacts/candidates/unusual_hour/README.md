# unusual_hour — đo ở trạng thái ỨNG VIÊN (Milestone C)

Sinh bởi `python -m scripts.behavior_verification --only unusual_hour --candidates unusual_hour` trên worktree sạch tại
cùng commit với bằng chứng chính thức trong `artifacts/behavior_verification/`.

`--candidates` bật detector như thể đã được nâng cấp (enforce + verified) **chỉ trong tiến trình đo** — registry vẫn để
`unusual_hour` ở `experimental`, nên ở lần chạy chính thức nó không tự tạo cảnh báo (recall 0 ở đó là do trạng thái, không
phải do detector). Kết quả ứng viên: 20/20 dương tính, 0/20 âm tính sát ngưỡng, nhưng **32 báo nhầm trên lưu lượng bình
thường** ⇒ không đạt tiêu chí VERIFIED, giữ PARTIAL. Không hạ/nâng ngưỡng sau khi xem kết quả.
