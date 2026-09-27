# Hồ sơ hiệu chỉnh hybrid risk engine

Mỗi tệp JSON ở đây là một `HybridProfile` (`app/detection/hybrid/calibration.py`): trọng số từng luật (dùng làm bằng chứng
trong noisy-OR), đường hiệu chỉnh mô hình ML (điểm thô -> xác suất) và ba ngưỡng hành động (`alert_at`, `step_up_at`,
`lock_at`) trên thang 0-100. Nạp bằng `HybridProfile.from_file(...)`.

- `rba_calibrated.json` — hiệu chỉnh trên RBA (MR11): trọng số luật đo trên `val` (mẫu ML, xem giới hạn ở dưới), đường
  hiệu chỉnh của `hybrid_cp2` (hồi quy isotonic trên `attack_ip/val`), ngưỡng hành động chọn trên đăng nhập hợp lệ thành
  công của `val` cho FPR 1% / 0,1% / 0,01%. **Sinh tự động** bởi `python -m ml.rba.hybrid_calibrate` — đừng sửa tay. Căn
  cứ, số đo trên test/late/ATO và giới hạn: [`docs/hybrid-risk-engine.md`](../../../../../docs/hybrid-risk-engine.md).
  ⚠️ Bốn luật nhóm "Danh tiếng hạ tầng" (`tor_exit`, `datacenter_ip`, `vpn_ip`, `blocklist_hit`) và ba luật khác
  (`username_enumeration`, `regular_rhythm`, `impossible_travel`) không đánh giá được trên RBA (xem
  `docs/rule-tuning.md` mục 6) nên trọng số của chúng là giá trị đặt trước (`calibrated: false`), không phải số đo.
