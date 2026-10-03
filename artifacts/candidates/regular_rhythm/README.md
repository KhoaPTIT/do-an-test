# regular_rhythm — đo ở trạng thái ỨNG VIÊN (Milestone C+)

Sinh bởi `python -m scripts.behavior_verification --only regular_rhythm --candidates regular_rhythm` trên worktree sạch
(commit ghi trong từng file), TRƯỚC khi đổi registry. Kết quả: TP 20/20, FP kịch bản 0/20, quy kết 20/20, 0 báo nhầm
trên lưu lượng bình thường v3 ⇒ đạt tiêu chí VERIFIED ⇒ registry `experimental/shadow` → `verified/enforce`. Bằng chứng
chính thức: lần chạy cuối trong `artifacts/behavior_verification/`.
