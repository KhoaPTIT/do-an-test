# Chồng lấn giữa luật và mô hình (MR10)

> ⚠️ **Lỗi thời từ Phase 4.1 (tài liệu lịch sử, giữ để tra cứu).** Nghiên cứu OFFLINE trên bộ RBA (cần file 9GB ngoài repo). Từ Phase 4.1 `hybrid_cp2` KHÔNG còn chạy trong `/login`; số liệu dưới đây không phải hiệu năng của hệ thống đang chạy. So sánh luật vs ML của hệ thống đang chạy: `artifacts/ml/rule_ml_overlap.md`. Model AI đang chạy: Isolation Forest trên dataset tổng hợp tái lập được — [`ml-anomaly-model.md`](ml-anomaly-model.md).

> Báo cáo TỰ SINH bởi `python -m ml.rba.rule_overlap` (sau `collect` và `tune` của [`rule_tuning.py`](../backend/ml/rba/rule_tuning.py)) — đừng sửa tay. Mã: [`rule_overlap.py`](../backend/ml/rba/rule_overlap.py).

## 1. Cách đọc

- **Mô hình:** `hybrid_cp2` (bản chốt ở CP2), ngưỡng chọn trên đăng nhập hợp lệ thành công của val cho FPR 1% (2.391) và 0,1% (3.345).
- **Luật** (bốn bộ, cách chọn ở [`rule-tuning.md`](rule-tuning.md)): `default_enforce` = các luật mặc định enforce ở tham số mặc định; `train_only_enforce` = cùng các luật ở bậc chọn theo quy trình đặt trước (chỉ train, ngân sách 5 lần khớp/10.000 đăng nhập hợp lệ thành công); `tuned_enforce` = quy trình sửa (train ∧ val) trừ các bậc thang bị loại — chính là hồ sơ cấu hình; `tuned_all` thêm luật mặc định shadow nếu chọn được. Một dòng "bị luật báo" khi có ít nhất một luật của bộ khớp (luật báo cả lần thất bại, mô hình chủ yếu chấm lần thành công).
- **Cùng dòng, cùng trọng số, cùng định nghĩa dương/âm** với khung đánh giá ML: tài khoản có thật trong mẫu phân tầng, `pop_weight`, dòng tấn công theo nhóm IP của giai đoạn; `ato/*` so ATO với đăng nhập hợp lệ thành công. Kẻ tấn công mô phỏng không có ở đây: chúng chỉ đăng nhập thành công một lần, vô hình với các luật đếm lần sai.
- **Bảng chồng lấn** chia mọi dòng dương tính (tính theo trọng số) thành: *cả hai* bắt, *chỉ mô hình*, *chỉ luật*, *cả hai bỏ sót*. **Bảng bằng chứng** so recall của bộ gộp với recall của CHỈ mô hình được nới ngưỡng đến đúng tổng tỉ lệ báo nhầm của bộ gộp trên cùng tập âm tính — so công bằng, vì gộp hai bộ luôn báo nhầm nhiều hơn mỗi bộ riêng. Cột "Bộ gộp hơn" ÂM nghĩa là chỉ nới ngưỡng mô hình còn tốt hơn thêm luật.
- ⚠️ Khoảng tin cậy 95% lấy mẫu lại theo cụm (IP cho `attack_ip/*`, tài khoản cho `ato/*`); ATO chỉ có 38 (tương lai) và 130 (tất cả) ca nên khoảng rất rộng. 38 ca tương lai đã bị nhìn ở MR7. `rare_network_login` (mặc định shadow) vòng tròn với cách RBA sinh ATO, nên bộ `tuned_all` trên ATO không dùng để tuyên bố. `ato/all` gồm cả train, nơi luật và mô hình đều được chọn/huấn luyện (lạc quan).

## 2. Tóm tắt

Mỗi dòng: bộ luật kết hợp với mô hình ở mức FPR nêu ở cột 2. *Hơn* = recall bộ gộp trừ recall CHỈ mô hình được nới ngưỡng đến cùng tổng báo nhầm ("khác 0" khi khoảng tin cậy 95% không chứa 0).

| Bài | FPR mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Hơn** |
|---|---|---|---|---|---|---|---|---|
| `attack_ip/test` | 1.0% | `tuned_enforce` | 12.1% | 0.3% | 12.3% | 0.93% | 12.3% | **-0.0 điểm [-0.2; +0.2]** |
| `attack_ip/test` | 0.1% | `tuned_enforce` | 3.9% | 0.3% | 4.1% | 0.23% | 7.5% | **-3.4 điểm [-4.7; -2.3] — khác 0** |
| `attack_ip/test` | 1.0% | `default_enforce` | 12.1% | 38.0% | 47.1% | 18.64% | 60.0% | **-13.0 điểm [-15.3; -10.5] — khác 0** |
| `attack_ip/test` | 0.1% | `default_enforce` | 3.9% | 38.0% | 41.1% | 18.00% | 57.8% | **-16.7 điểm [-19.6; -13.9] — khác 0** |
| `attack_ip/late` | 1.0% | `tuned_enforce` | 7.1% | 1.6% | 8.6% | 1.00% | 7.2% | **+1.4 điểm [-0.0; +4.0]** |
| `attack_ip/late` | 0.1% | `tuned_enforce` | 2.1% | 1.6% | 3.7% | 0.31% | 3.2% | **+0.5 điểm [-1.2; +3.2]** |
| `attack_ip/late` | 1.0% | `default_enforce` | 7.1% | 44.0% | 50.2% | 24.46% | 63.8% | **-13.6 điểm [-17.7; -9.7] — khác 0** |
| `attack_ip/late` | 0.1% | `default_enforce` | 2.1% | 44.0% | 45.8% | 23.83% | 62.7% | **-16.9 điểm [-21.6; -12.6] — khác 0** |
| `ato/future` | 1.0% | `tuned_enforce` | 31.6% | 2.6% | 31.6% | 0.98% | 36.8% | **-5.3 điểm [-13.2; +0.0]** |
| `ato/future` | 0.1% | `tuned_enforce` | 7.9% | 2.6% | 7.9% | 0.17% | 7.9% | **+0.0 điểm [+0.0; +0.0]** |
| `ato/future` | 1.0% | `default_enforce` | 31.6% | 13.2% | 39.5% | 10.64% | 86.8% | **-47.4 điểm [-63.2; -34.2] — khác 0** |
| `ato/future` | 0.1% | `default_enforce` | 7.9% | 13.2% | 18.4% | 9.89% | 84.2% | **-65.8 điểm [-78.9; -50.0] — khác 0** |
| `ato/all` | 1.0% | `tuned_enforce` | 29.2% | 3.8% | 29.2% | 0.88% | 31.5% | **-2.3 điểm [-5.3; +0.0]** |
| `ato/all` | 0.1% | `tuned_enforce` | 6.2% | 3.8% | 8.5% | 0.15% | 7.7% | **+0.8 điểm [-1.6; +3.8]** |
| `ato/all` | 1.0% | `default_enforce` | 29.2% | 13.1% | 33.8% | 6.11% | 58.5% | **-24.6 điểm [-33.1; -17.3] — khác 0** |
| `ato/all` | 0.1% | `default_enforce` | 6.2% | 13.1% | 16.9% | 5.41% | 58.5% | **-41.5 điểm [-51.5; -33.6] — khác 0** |

## Bài `attack_ip/test`

IP tấn công so với bình thường, giai đoạn test (có trọng số; cụm = IP)

### Chồng lấn (phần dương tính theo trọng số) — bộ luật `tuned_enforce`

| Mức FPR của mô hình | Cả hai | Chỉ mô hình | Chỉ luật | Cả hai bỏ sót | Báo nhầm: mô hình | luật | gộp |
|---|---|---|---|---|---|---|---|
| 1.0% (n = 5,709) | 0.0% (3) | 12.0% (720) | 0.2% (20) | 87.7% (4,966) | 0.80% | 0.15% | 0.93% |
| 0.1% (n = 5,709) | 0.0% (2) | 3.8% (235) | 0.3% (21) | 95.9% (5,451) | 0.08% | 0.15% | 0.23% |

### Bằng chứng cho hybrid: bộ gộp so với CHỈ mô hình ở cùng tổng tỉ lệ báo nhầm

| Mức FPR của mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Bộ gộp hơn** |
|---|---|---|---|---|---|---|---|
| 1.0% | `default_enforce` | 12.1% [8.5%–15.7%] | 38.0% [36.0%–39.9%] | 47.1% [44.7%–49.5%] | 18.64% | 60.0% [57.0%–63.1%] | **-13.0 điểm [-15.3; -10.5] — khác 0** |
| 0.1% | `default_enforce` | 3.9% [2.2%–5.6%] | 38.0% [36.0%–39.9%] | 41.1% [39.1%–42.9%] | 18.00% | 57.8% [54.6%–60.8%] | **-16.7 điểm [-19.6; -13.9] — khác 0** |
| 1.0% | `train_only_enforce` | 12.1% [8.5%–15.7%] | 2.3% [1.9%–2.9%] | 14.1% [10.5%–17.7%] | 3.30% | 15.0% [11.1%–19.1%] | **-0.9 điểm [-2.2; +0.2]** |
| 0.1% | `train_only_enforce` | 3.9% [2.2%–5.6%] | 2.3% [1.9%–2.9%] | 6.1% [4.4%–8.1%] | 2.61% | 14.4% [10.5%–18.3%] | **-8.3 điểm [-10.9; -5.6] — khác 0** |
| 1.0% | `tuned_enforce` | 12.1% [8.5%–15.7%] | 0.3% [0.1%–0.4%] | 12.3% [8.8%–15.9%] | 0.93% | 12.3% [8.8%–16.0%] | **-0.0 điểm [-0.2; +0.2]** |
| 0.1% | `tuned_enforce` | 3.9% [2.2%–5.6%] | 0.3% [0.1%–0.4%] | 4.1% [2.4%–5.9%] | 0.23% | 7.5% [5.0%–10.5%] | **-3.4 điểm [-4.7; -2.3] — khác 0** |
| 1.0% | `tuned_all` | 12.1% [8.5%–15.7%] | 0.3% [0.1%–0.4%] | 12.3% [8.8%–15.9%] | 0.94% | 12.3% [8.8%–16.0%] | **-0.0 điểm [-0.2; +0.2]** |
| 0.1% | `tuned_all` | 3.9% [2.2%–5.6%] | 0.3% [0.1%–0.4%] | 4.1% [2.4%–5.9%] | 0.25% | 8.3% [5.5%–11.4%] | **-4.2 điểm [-5.8; -2.8] — khác 0** |

### Luật nào bắt phần mô hình bỏ sót (bộ `tuned_enforce`)

| Mức FPR của mô hình | Luật (bậc thang) | Phần ca mô hình bỏ sót mà luật bắt | Số dòng |
|---|---|---|---|
| 1.0% | `distributed_bruteforce` | 0.1% | 13 |
| 1.0% | `ua_rotation` | 0.0% | 2 |
| 1.0% | `credential_stuffing/ip` | 0.0% | 3 |
| 1.0% | `multi_context_simultaneous` | 0.0% | 1 |
| 1.0% | `brute_force` | 0.0% | 1 |
| 0.1% | `distributed_bruteforce` | 0.1% | 14 |
| 0.1% | `ua_rotation` | 0.0% | 2 |
| 0.1% | `credential_stuffing/ip` | 0.0% | 3 |
| 0.1% | `multi_context_simultaneous` | 0.0% | 1 |
| 0.1% | `brute_force` | 0.0% | 1 |

## Bài `attack_ip/late`

IP tấn công so với bình thường, giai đoạn late (có trọng số; cụm = IP)

### Chồng lấn (phần dương tính theo trọng số) — bộ luật `tuned_enforce`

| Mức FPR của mô hình | Cả hai | Chỉ mô hình | Chỉ luật | Cả hai bỏ sót | Báo nhầm: mô hình | luật | gộp |
|---|---|---|---|---|---|---|---|
| 1.0% (n = 7,137) | 0.1% (15) | 6.9% (488) | 1.5% (78) | 91.4% (6,556) | 0.81% | 0.21% | 1.00% |
| 0.1% (n = 7,137) | 0.1% (7) | 2.0% (128) | 1.6% (86) | 96.3% (6,916) | 0.10% | 0.21% | 0.31% |

### Bằng chứng cho hybrid: bộ gộp so với CHỈ mô hình ở cùng tổng tỉ lệ báo nhầm

| Mức FPR của mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Bộ gộp hơn** |
|---|---|---|---|---|---|---|---|
| 1.0% | `default_enforce` | 7.1% [4.9%–9.8%] | 44.0% [41.6%–46.4%] | 50.2% [48.2%–52.4%] | 24.46% | 63.8% [59.7%–68.2%] | **-13.6 điểm [-17.7; -9.7] — khác 0** |
| 0.1% | `default_enforce` | 2.1% [1.2%–3.3%] | 44.0% [41.6%–46.4%] | 45.8% [43.7%–47.9%] | 23.83% | 62.7% [58.4%–67.2%] | **-16.9 điểm [-21.6; -12.6] — khác 0** |
| 1.0% | `train_only_enforce` | 7.1% [4.9%–9.8%] | 10.7% [8.9%–13.3%] | 17.5% [14.6%–20.8%] | 7.01% | 20.6% [17.5%–24.0%] | **-3.1 điểm [-6.0; +0.3]** |
| 0.1% | `train_only_enforce` | 2.1% [1.2%–3.3%] | 10.7% [8.9%–13.3%] | 12.7% [10.8%–15.3%] | 6.34% | 17.5% [14.3%–20.8%] | **-4.8 điểm [-8.5; -0.8] — khác 0** |
| 1.0% | `tuned_enforce` | 7.1% [4.9%–9.8%] | 1.6% [0.2%–4.3%] | 8.6% [5.6%–12.2%] | 1.00% | 7.2% [5.0%–10.0%] | **+1.4 điểm [-0.0; +4.0]** |
| 0.1% | `tuned_enforce` | 2.1% [1.2%–3.3%] | 1.6% [0.2%–4.3%] | 3.7% [1.7%–6.5%] | 0.31% | 3.2% [2.0%–4.6%] | **+0.5 điểm [-1.2; +3.2]** |
| 1.0% | `tuned_all` | 7.1% [4.9%–9.8%] | 1.7% [0.3%–4.3%] | 8.6% [5.6%–12.2%] | 1.01% | 7.2% [5.0%–10.0%] | **+1.4 điểm [-0.0; +4.0]** |
| 0.1% | `tuned_all` | 2.1% [1.2%–3.3%] | 1.7% [0.3%–4.3%] | 3.7% [1.7%–6.5%] | 0.32% | 3.4% [2.2%–4.8%] | **+0.3 điểm [-1.5; +3.0]** |

### Luật nào bắt phần mô hình bỏ sót (bộ `tuned_enforce`)

| Mức FPR của mô hình | Luật (bậc thang) | Phần ca mô hình bỏ sót mà luật bắt | Số dòng |
|---|---|---|---|
| 1.0% | `credential_stuffing/ip` | 1.4% | 50 |
| 1.0% | `brute_force` | 0.1% | 14 |
| 1.0% | `distributed_bruteforce` | 0.1% | 9 |
| 1.0% | `password_spray_slow/ip` | 0.0% | 1 |
| 1.0% | `ua_rotation` | 0.0% | 2 |
| 1.0% | `multi_context_simultaneous` | 0.0% | 3 |
| 0.1% | `credential_stuffing/ip` | 1.3% | 53 |
| 0.1% | `distributed_bruteforce` | 0.1% | 13 |
| 0.1% | `brute_force` | 0.1% | 15 |
| 0.1% | `multi_context_simultaneous` | 0.0% | 4 |
| 0.1% | `password_spray_slow/ip` | 0.0% | 1 |
| 0.1% | `ua_rotation` | 0.0% | 2 |

## Bài `ato/future`

38 ATO tương lai (09–11/2020) so với đăng nhập hợp lệ thành công giai đoạn test

### Chồng lấn (phần dương tính theo trọng số) — bộ luật `tuned_enforce`

| Mức FPR của mô hình | Cả hai | Chỉ mô hình | Chỉ luật | Cả hai bỏ sót | Báo nhầm: mô hình | luật | gộp |
|---|---|---|---|---|---|---|---|
| 1.0% (n = 38) | 2.6% (1) | 28.9% (11) | 0.0% (0) | 68.4% (26) | 0.93% | 0.07% | 0.98% |
| 0.1% (n = 38) | 2.6% (1) | 5.3% (2) | 0.0% (0) | 92.1% (35) | 0.11% | 0.07% | 0.17% |

### Bằng chứng cho hybrid: bộ gộp so với CHỈ mô hình ở cùng tổng tỉ lệ báo nhầm

| Mức FPR của mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Bộ gộp hơn** |
|---|---|---|---|---|---|---|---|
| 1.0% | `default_enforce` | 31.6% [18.4%–47.4%] | 13.2% [5.2%–26.3%] | 39.5% [23.7%–52.6%] | 10.64% | 86.8% [76.3%–97.4%] | **-47.4 điểm [-63.2; -34.2] — khác 0** |
| 0.1% | `default_enforce` | 7.9% [0.0%–15.8%] | 13.2% [5.2%–26.3%] | 18.4% [7.9%–31.6%] | 9.89% | 84.2% [73.7%–94.7%] | **-65.8 điểm [-78.9; -50.0] — khác 0** |
| 1.0% | `train_only_enforce` | 31.6% [18.4%–47.4%] | 7.9% [0.0%–18.4%] | 36.8% [23.7%–52.6%] | 3.84% | 68.4% [52.6%–81.6%] | **-31.6 điểm [-47.4; -18.4] — khác 0** |
| 0.1% | `train_only_enforce` | 7.9% [0.0%–15.8%] | 7.9% [0.0%–18.4%] | 13.2% [5.2%–23.7%] | 3.05% | 65.8% [50.0%–79.0%] | **-52.6 điểm [-68.4; -36.8] — khác 0** |
| 1.0% | `tuned_enforce` | 31.6% [18.4%–47.4%] | 2.6% [0.0%–7.9%] | 31.6% [18.4%–47.4%] | 0.98% | 36.8% [23.7%–52.6%] | **-5.3 điểm [-13.2; +0.0]** |
| 0.1% | `tuned_enforce` | 7.9% [0.0%–15.8%] | 2.6% [0.0%–7.9%] | 7.9% [0.0%–15.8%] | 0.17% | 7.9% [0.0%–15.8%] | **+0.0 điểm [+0.0; +0.0]** |
| 1.0% | `tuned_all` | 31.6% [18.4%–47.4%] | 2.6% [0.0%–7.9%] | 31.6% [18.4%–47.4%] | 0.98% | 36.8% [23.7%–52.6%] | **-5.3 điểm [-13.2; +0.0]** |
| 0.1% | `tuned_all` | 7.9% [0.0%–15.8%] | 2.6% [0.0%–7.9%] | 7.9% [0.0%–15.8%] | 0.19% | 7.9% [0.0%–15.8%] | **+0.0 điểm [+0.0; +0.0]** |

### Luật nào bắt phần mô hình bỏ sót (bộ `tuned_enforce`)

| Mức FPR của mô hình | Luật (bậc thang) | Phần ca mô hình bỏ sót mà luật bắt | Số dòng |
|---|---|---|---|
| 1.0% | `—` | 0.0% | 0 |
| 0.1% | `—` | 0.0% | 0 |

## Bài `ato/all`

130 ATO (nhìn lại, lạc quan hơn) so với đăng nhập hợp lệ thành công train+val+test

### Chồng lấn (phần dương tính theo trọng số) — bộ luật `tuned_enforce`

| Mức FPR của mô hình | Cả hai | Chỉ mô hình | Chỉ luật | Cả hai bỏ sót | Báo nhầm: mô hình | luật | gộp |
|---|---|---|---|---|---|---|---|
| 1.0% (n = 130) | 3.8% (5) | 25.4% (33) | 0.0% (0) | 70.8% (92) | 0.84% | 0.07% | 0.88% |
| 0.1% (n = 130) | 1.5% (2) | 4.6% (6) | 2.3% (3) | 91.5% (119) | 0.09% | 0.07% | 0.15% |

### Bằng chứng cho hybrid: bộ gộp so với CHỈ mô hình ở cùng tổng tỉ lệ báo nhầm

| Mức FPR của mô hình | Bộ luật | Recall mô hình | Recall luật | Recall bộ gộp | Báo nhầm bộ gộp | Recall CHỈ mô hình cùng báo nhầm | **Bộ gộp hơn** |
|---|---|---|---|---|---|---|---|
| 1.0% | `default_enforce` | 29.2% [20.9%–37.0%] | 13.1% [7.8%–18.5%] | 33.8% [24.6%–41.9%] | 6.11% | 58.5% [49.6%–66.9%] | **-24.6 điểm [-33.1; -17.3] — khác 0** |
| 0.1% | `default_enforce` | 6.2% [2.3%–10.9%] | 13.1% [7.8%–18.5%] | 16.9% [10.8%–23.3%] | 5.41% | 58.5% [49.6%–66.9%] | **-41.5 điểm [-51.5; -33.6] — khác 0** |
| 1.0% | `train_only_enforce` | 29.2% [20.9%–37.0%] | 6.2% [2.3%–10.1%] | 30.8% [22.3%–38.6%] | 1.88% | 50.0% [40.9%–58.0%] | **-19.2 điểm [-26.4; -12.4] — khác 0** |
| 0.1% | `train_only_enforce` | 6.2% [2.3%–10.9%] | 6.2% [2.3%–10.1%] | 10.0% [5.3%–15.5%] | 1.16% | 36.9% [29.3%–45.0%] | **-26.9 điểm [-34.9; -18.6] — khác 0** |
| 1.0% | `tuned_enforce` | 29.2% [20.9%–37.0%] | 3.8% [0.8%–7.6%] | 29.2% [20.9%–37.0%] | 0.88% | 31.5% [23.8%–38.8%] | **-2.3 điểm [-5.3; +0.0]** |
| 0.1% | `tuned_enforce` | 6.2% [2.3%–10.9%] | 3.8% [0.8%–7.6%] | 8.5% [3.9%–13.2%] | 0.15% | 7.7% [3.1%–12.4%] | **+0.8 điểm [-1.6; +3.8]** |
| 1.0% | `tuned_all` | 29.2% [20.9%–37.0%] | 5.4% [2.2%–9.8%] | 30.0% [22.0%–38.0%] | 0.89% | 31.5% [23.8%–38.8%] | **-1.5 điểm [-4.6; +1.5]** |
| 0.1% | `tuned_all` | 6.2% [2.3%–10.9%] | 5.4% [2.2%–9.8%] | 9.2% [5.3%–14.6%] | 0.16% | 7.7% [3.1%–12.4%] | **+1.5 điểm [-1.6; +4.6]** |

### Luật nào bắt phần mô hình bỏ sót (bộ `tuned_enforce`)

| Mức FPR của mô hình | Luật (bậc thang) | Phần ca mô hình bỏ sót mà luật bắt | Số dòng |
|---|---|---|---|
| 1.0% | `—` | 0.0% | 0 |
| 0.1% | `multi_context_simultaneous` | 2.5% | 3 |

## Giới hạn

- Chỉ RBA (tổng hợp): dòng tấn công là IP trong danh sách của bộ dữ liệu, không phải kẻ tấn công thích ứng; ATO của RBA có đặc điểm nhân tạo (nhà mạng hiếm).
- Bộ luật đã chọn trên train theo ngân sách báo nhầm, mô hình chọn ngưỡng trên val — cả hai được báo cáo trên giai đoạn sau chúng, nhưng 38 ATO tương lai đã bị nhìn ở MR7.
- Luật báo cả lần thất bại nên tỉ lệ báo nhầm của luật trong cùng bài lấy trên mọi dòng bình thường; ở `ato/*` mẫu số là đăng nhập hợp lệ thành công nên luật chỉ tính trên lần thành công ở đó.
