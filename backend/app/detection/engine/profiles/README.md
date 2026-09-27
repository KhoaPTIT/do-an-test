# Hồ sơ cấu hình luật

Mỗi tệp JSON ở đây là một `RuleConfig` (chế độ và tham số ghi đè theo từng luật) nạp bằng `RuleConfig.from_file(...)`; luật không nêu dùng mặc định của sổ đăng ký (xem [`docs/rule-catalog.md`](../../../../../docs/rule-catalog.md)).

- `rba_train_tuned.json` — tham số đã tinh chỉnh trên giai đoạn train của RBA (MR10), theo quy trình sửa "train ∧ val" và trừ các bậc thang bị loại; luật không chọn được bậc nào ở ngân sách 5 lần khớp/10.000 đăng nhập
  hợp lệ thành công chuyển sang `shadow`. **Sinh tự động** bởi `python -m ml.rba.rule_tuning tune` — đừng sửa tay. Căn cứ, số đo trên val/test/late và giới hạn: [`docs/rule-tuning.md`](../../../../../docs/rule-tuning.md).
  ⚠️ Chỉ được tinh chỉnh cho RBA (dữ liệu tổng hợp, chỉ gồm tài khoản có thật); không phải mặc định của hệ thống và không tự nhiên phù hợp với lưu lượng khác.
