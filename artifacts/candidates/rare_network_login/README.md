# rare_network_login — đo ở trạng thái ỨNG VIÊN (Milestone C+)

Sinh bởi `python -m scripts.behavior_verification --only rare_network_login --candidates rare_network_login` trên worktree
sạch (commit ghi trong từng file), TRƯỚC khi đổi registry. Kết quả: TP 20/20, FP kịch bản 0/20, quy kết 20/20, 0 báo nhầm
trên lưu lượng bình thường v3 ⇒ đạt tiêu chí VERIFIED ⇒ `experimental/shadow` → `verified/enforce`.

⚠️ Độ mạnh của bằng chứng "0 báo nhầm": lưu lượng bình thường v3 chỉ có 3 lần một tài khoản trưởng thành đăng nhập từ nhà
mạng mới với chính nó (tỉ lệ toàn hệ thống 1,96%, 5,82%, 25,9% — đều > 1%). Chỉ trạng thái WARM được kiểm chứng bằng
kịch bản; MATURE (≥ 20.000 lượt) chỉ có test đơn vị.
