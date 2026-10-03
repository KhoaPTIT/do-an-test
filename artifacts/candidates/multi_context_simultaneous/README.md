# multi_context_simultaneous — đo ở trạng thái ỨNG VIÊN (Milestone C+)

Sinh bởi `python -m scripts.behavior_verification --only multi_context_simultaneous --candidates multi_context_simultaneous`
trên worktree sạch (commit ghi trong từng file), TRƯỚC khi đổi registry. Kết quả: TP 20/20, FP kịch bản 0/20, quy kết
20/20, 0 báo nhầm trên lưu lượng bình thường v3 ⇒ đạt tiêu chí VERIFIED ⇒ `experimental` → `verified` (luật vốn `enforce`).

⚠️ Lưu lượng bình thường v3 KHÔNG có cặp đăng nhập thành công ở hai quốc gia trong 1 giờ, nên "0 báo nhầm" ở đó không
phải bằng chứng; sức nặng nằm ở 20 kịch bản âm tính. Nguồn báo nhầm thật đã biết (VPN trên một thiết bị, thiết bị khác
không VPN) không được mô phỏng.
