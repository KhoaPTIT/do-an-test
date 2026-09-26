# Kiểm chứng "kiểu tấn công mới", ablation và phân tích lỗi (MR7)

Trả lời ba câu hỏi bằng thí nghiệm, không bằng lập luận: (1) mô hình có bắt được kiểu tấn công **chưa từng thấy** không? (2) sức mạnh của nó có đến từ một **đường tắt** không? (3) nó **sai ở đâu**? Khung đo và cách đọc: [`rba-evaluation.md`](rba-evaluation.md); mô hình: [`model-card-rba.md`](model-card-rba.md); kết quả MR6: [`ml-evaluation-v2.md`](ml-evaluation-v2.md). Dữ liệu là **tổng hợp** ([`rba-data-card.md`](rba-data-card.md)). Mọi số ở **FPR 1%** (chỉ báo nhầm 1% đăng nhập hợp lệ), giai đoạn test, trọng số dân số, trừ khi ghi khác.

> ⚠️ **Cập nhật CP2 (26/09/2026):** thí nghiệm ở tài liệu này chạy trên các mô hình MR6 (50 đặc trưng). Đề xuất của mục 4.3 (Isolation Forest bỏ nhóm `infra_ip`) đã được chốt ở CP2 nhưng chọn lại trên 92 ATO quá khứ thay vì 38 ca tương lai ([`ml-model-selection.md`](ml-model-selection.md)); đề xuất bỏ `infra_ip` khỏi `gbm_attack_ip` **không** được chọn theo val (val cho `infra_asn`) và cũng bị phủ quyết theo `late`. Các số hold-out, ablation và phân tích lỗi giữ nguyên là của bản MR6.

## Tóm tắt

1. **AI học từ nhãn không tự bắt được họ tấn công chưa từng thấy.** Giấu một họ IP tấn công khỏi huấn luyện thì ở 6 họ mà LightGBM bắt được khi đã thấy (15–56%), recall của họ bị giấu rơi xuống **0,0–1,1% (5 họ) hoặc 11,9% (1 họ)**; hai họ còn lại nó không bắt được cả khi đã thấy (≤ 1,0%). Hybrid chưa thấy họ: 0,0–2,9%. Bộ phát hiện không cần nhãn cũng yếu: Isolation Forest 0,1–6,2%, kNN 0,1–10,1%. Bỏ các đặc trưng "định danh" (độ hiếm) hay hạ tầng IP **không** làm mô hình tổng quát tốt hơn. Nên **không thể nói "AI phát hiện được tấn công mới nhờ so sánh với bình thường"** dựa trên các thí nghiệm này.
2. **Với kẻ tấn công mô phỏng thì tổng quát tốt hơn nhiều**: giấu Naive vẫn bắt 40,6% (so với 59,1% khi đã thấy), giấu VPN 41,4% (50,9%), giấu Targeted 8,6% (28,5%) — hơn Freeman, Isolation Forest và kNN ở kiểu chưa thấy. Lý do: các kiểu này chung một dấu hiệu "thuộc tính/IP lạ với tài khoản".
3. **Không có nhóm đặc trưng "đường tắt" nào tự mang tín hiệu** ở mô hình học từ kẻ tấn công mô phỏng: sáu nhóm nhịp/lịch sử/hạ tầng/độ hiếm/thiết bị hiện tại mỗi nhóm một mình chỉ đạt 0,0–1,7% (mức ngẫu nhiên); sức mạnh nằm ở nhóm Freeman (40,6% / 27,8% Naive / VPN) và novelty, cộng tương tác với nhịp và IP. Mô hình IP tấn công thì dư thừa (bỏ một nhóm đổi tối đa ±3 điểm) nhưng **nhóm độ hiếm một mình (18,4%) hơn cả mô hình đủ 50 đặc trưng (15,0%)**, và nhóm hạ tầng IP còn làm giảm hiệu năng.
4. **Isolation Forest bắt ATO thật nhờ độ hiếm/novelty của nhà mạng**, không nhờ nhịp hay lịch sử: bỏ nhóm `novelty`, `rarity` hoặc `infra_asn` làm recall ATO rơi từ 31,6% xuống 10,5–13,2%; bỏ nhóm hạ tầng IP thì **tăng gần gấp đôi** (60,5%).
5. **103 trong 130 ATO thật bị hybrid bỏ sót** (0/46 ở tài khoản chưa có lịch sử) — nhưng chúng không "trông bình thường": nhà mạng của chúng hiếm hơn phân vị 99 của đăng nhập hợp lệ (trung vị `rare_asn` của ATO là 12,0; phân vị 99 của đăng nhập hợp lệ là 10,9). **Một luật một đặc trưng `rare_asn`, không học gì, bắt 65,8% ATO tương lai — hơn mọi mô hình (hybrid 26,3%)**. Đây là chẩn đoán chọn sau khi đã thấy ATO nên không phải phép so sánh công bằng, nhưng nó cho thấy ATO của bộ dữ liệu "dễ" theo một cách mà tấn công ngoài đời chưa chắc dễ.
6. **Báo nhầm tập trung ở đăng nhập từ quốc gia hoặc nhà mạng mới**: 8,5% số đăng nhập nhưng 29,8% số báo nhầm (gấp 3,5 lần mức chung).
7. **Giới hạn với Targeted**: hybrid bắt 58,9% khi kẻ tấn công đăng nhập trong 1 phút sau lần thành công trước nhưng chỉ **6,5% khi cách hơn 30 ngày** (mức báo nhầm cùng lát cắt 0,78%): kẻ tấn công biết trọn hồ sơ phiên chỉ lộ ở IP mới, và đăng nhập hợp lệ sau một tháng cũng hay đổi IP.

## 1. Giấu từng họ tấn công IP khỏi huấn luyện

**Cách làm.** Với mỗi họ F: bỏ **mọi dòng tấn công của F** khỏi train **và val** (dừng sớm cũng không thấy F), huấn luyện lại `gbm_attack_ip` (cùng siêu tham số và hạt giống), rồi đo recall của **chính F ở giai đoạn test** (chưa dùng khi học) so với đúng mô hình ấy khi đã thấy F. Luật tinh chỉnh cũng học lại không có F. Isolation Forest và kNN không dùng nhãn nên không đổi. Âm tính = đăng nhập hợp lệ giai đoạn test. RBA gần như không có thiết bị bot (2 trong 2,5 triệu dòng hợp lệ) nên "bot/thiết bị" của kế hoạch được thay bằng loại thiết bị. Họ theo hành vi được xác định bằng thống kê cả giai đoạn của IP — chỉ để phân nhóm khi đánh giá, không dùng làm đặc trưng.

| Họ | Định nghĩa |
|---|---|
| **Chậm và ít** | IP chỉ có ≤ 10 lượt thử trong toàn bộ dữ liệu (dò chậm hoặc thử một lần) |
| **Rải rộng** | IP nhắm > 30 tài khoản thật khác nhau (nhồi/rải mật khẩu quy mô lớn) |
| **Mạng chiếm ưu thế** | IP thuộc ASN 393398, mạng chiếm ~62% số dòng tấn công |
| **Ngoài Mỹ** | IP nguồn không phải Mỹ (Mỹ chiếm 71% số dòng tấn công) |
| **Mạng đuôi (nhóm 0)** | IP thuộc ASN ≠ 393398 với ASN mod 3 = 0 |
| **Mạng đuôi (nhóm 1)** | IP thuộc ASN ≠ 393398 với ASN mod 3 = 1 |
| **Mạng đuôi (nhóm 2)** | IP thuộc ASN ≠ 393398 với ASN mod 3 = 2 |
| **Máy tính / máy tính bảng** | dòng tấn công từ máy tính hoặc máy tính bảng (họ thiểu số: 13%, còn lại là điện thoại) |

Kết quả (recall @ FPR 1%; khoảng tin cậy 95% bootstrap theo IP cho LightGBM; Tier 2 tối đa 0,2% và Freeman tối đa 2,3% ở mọi họ nên không đưa vào bảng):

| Họ bị giấu | Dòng test (số IP) | % dòng tấn công bị loại khỏi huấn luyện | Luật tinh chỉnh (học không có họ) | Isolation Forest | kNN | **LightGBM đã thấy họ** | **LightGBM chưa thấy họ** | Hybrid chưa thấy họ |
|---|---|---|---|---|---|---|---|---|
| **Chậm và ít** | 343 (194) | 7% | 0.0% | 5.2% | 3.1% | 1.0% [0%–2%] | 0.0% [0%–0%] | 2.2% |
| **Rải rộng** | 4,706 (246) | 77% | 0.2% | 0.4% | 0.8% | 15.1% [11%–20%] | 0.8% [0%–1%] | 0.9% |
| **Mạng chiếm ưu thế** | 3,757 (117) | 60% | 0.0% | 0.1% | 0.1% | 0.5% [0%–2%] | 0.0% [0%–0%] | 0.0% |
| **Ngoài Mỹ** | 1,426 (384) | 31% | 0.1% | 3.7% | 5.1% | 26.6% [16%–37%] | 0.0% [0%–0%] | 2.1% |
| **Mạng đuôi (nhóm 0)** | 455 (157) | 11% | 0.0% | 1.2% | 1.0% | 55.0% [46%–66%] | 11.9% [8%–17%] | 2.2% |
| **Mạng đuôi (nhóm 1)** | 890 (254) | 16% | 2.4% | 0.9% | 0.8% | 55.6% [43%–66%] | 1.1% [0%–3%] | 0.6% |
| **Mạng đuôi (nhóm 2)** | 607 (116) | 13% | 0.3% | 6.2% | 10.1% | 43.9% [22%–63%] | 0.6% [0%–2%] | 2.9% |
| **Máy tính / máy tính bảng** | 739 (229) | 14% | 1.0% | 3.1% | 6.3% | 33.4% [20%–45%] | 0.1% [0%–0%] | 2.3% |

**Đọc kết quả.**

- **Mô hình có giám sát gần như mù với họ chưa thấy**: 0,0–1,1% ở 7/8 họ; ngoại lệ mạng đuôi nhóm 0 (11,9%). Cùng mô hình khi đã thấy họ đạt 15–56% (6 họ bắt được). Khoảng cách này là điều mà "học từ nhãn" không vượt qua được, dù đã bỏ chính đặc trưng định danh (mục 1.1).
- **Bộ phát hiện không nhãn không phụ thuộc họ nhưng yếu**: Isolation Forest 0,1–6,2%, kNN 0,1–10,1%. Đó là mức "bắt kiểu mới" thật sự của bộ phát hiện bất thường trên các họ này: một vài phần trăm ở FPR 1%; bộ tốt hơn trong hai bộ cao hơn LightGBM chưa thấy họ ở 5/8 họ và cao hơn luật (0,0–2,4%), nhưng xa mức 15–56% của mô hình đã thấy họ.
- **Hai họ mà mô hình không bắt được ngay cả khi đã thấy**: "chậm và ít" (1,0%) và "mạng chiếm ưu thế" (0,5%). Mạng thứ hai chiếm **60–66% số dòng tấn công** (train, test): phần lớn lưu lượng tấn công của RBA đến từ một mạng mà mô hình không phân biệt được với lưu lượng thường — đây là lý do recall tổng thể của `gbm_attack_ip` chỉ 15% (MR6).
- **Mạng đuôi (ASN khác nhóm nào cũng 44–56% khi đã thấy, 0,6–11,9% khi giấu nhóm ấy)**: mô hình nhận ra "các mạng tấn công đã biết", và không chuyển sang mạng khác dù cùng nhóm hành vi. Đây là dạng học thuộc theo mạng mà cắt IP theo nhóm (MR2) không ngăn được: IP tách rời nhưng mạng thì chung.
- Hybrid chưa thấy họ (0,0–2,9%) ngang hoặc thấp hơn Isolation Forest/kNN: khi thành phần IP tấn công mất họ, khả năng bắt chỉ còn đến từ Isolation Forest và mô hình chiếm tài khoản.

### 1.1 Bỏ đặc trưng "định danh" có giúp tổng quát không?

Giả thuyết: mô hình chỉ thuộc lòng mạng/quốc gia nhờ nhóm `rarity`. Thử ba biến thể đặc trưng (mỗi biến thể huấn luyện lại cho mỗi họ; ô = "đã thấy → **chưa thấy**"):

| Họ bị giấu | Dòng test | đủ 50 đặc trưng | bỏ độ hiếm (43) | bỏ hạ tầng IP (43) | chỉ độ hiếm (7) |
|---|---|---|---|---|---|
| **Chậm và ít** | 343 | 1.0% → **0.0%** | 0.2% → **0.0%** | 0.0% → **0.0%** | 0.9% → **0.9%** |
| **Rải rộng** | 4,706 | 15.1% → **0.8%** | 12.5% → **0.3%** | 20.1% → **1.1%** | 20.7% → **0.7%** |
| **Mạng chiếm ưu thế** | 3,757 | 0.5% → **0.0%** | 0.1% → **0.0%** | 9.1% → **0.0%** | 9.9% → **0.0%** |
| **Ngoài Mỹ** | 1,426 | 26.6% → **0.0%** | 14.1% → **0.9%** | 19.8% → **0.0%** | 18.1% → **0.0%** |
| **Mạng đuôi (nhóm 0)** | 455 | 55.0% → **11.9%** | 38.9% → **11.8%** | 28.4% → **0.0%** | 33.9% → **0.6%** |
| **Mạng đuôi (nhóm 1)** | 890 | 55.6% → **1.1%** | 54.2% → **2.8%** | 53.8% → **0.0%** | 52.1% → **0.0%** |
| **Mạng đuôi (nhóm 2)** | 607 | 43.9% → **0.6%** | 26.5% → **1.2%** | 26.9% → **0.0%** | 26.2% → **0.0%** |
| **Máy tính / máy tính bảng** | 739 | 33.4% → **0.1%** | 13.9% → **0.0%** | 25.2% → **0.0%** | 23.1% → **1.6%** |

**Không biến thể nào cứu được**: chưa thấy họ vẫn 0,0–2,8% (trừ mạng đuôi nhóm 0 khi bỏ độ hiếm: 11,8%, như mô hình đủ 11,9%). Kết luận: vấn đề không phải một nhóm đặc trưng "gian lận"; các họ khác nhau về hành vi nên mẫu học từ họ này không áp lên họ kia bằng bất kỳ tập đặc trưng nào ở đây.

## 2. Giấu từng kiểu kẻ tấn công mô phỏng

Cùng cách làm cho `gbm_attacker_sim`: bỏ kiểu kẻ tấn công đó khỏi train và val (nạn nhân giai đoạn train/val), chấm trên đúng kiểu đó ở test. "Học chỉ từ Naive" kiểm tra khả năng leo từ kẻ tấn công yếu lên mạnh.

| Học từ | Chấm trên | Ca dương | `freeman_all` | `isolation_forest` | `knn_distance` | `gbm_attacker_sim (đã thấy kiểu)` | `gbm_attacker_sim (chưa thấy kiểu)` | `hybrid (đã thấy kiểu)` | `hybrid (chưa thấy kiểu)` |
|---|---|---|---|---|---|---|---|---|---|
| vpn + targeted | **naive** (chưa thấy) | 2,000 | 35.0% | 11.8% | 14.2% | 59.1% | 40.6% [38%–43%] | 47.1% | 30.3% [28%–32%] |
| naive + targeted | **vpn** (chưa thấy) | 1,995 | 26.5% | 6.0% | 8.2% | 50.9% | 41.4% [39%–44%] | 37.2% | 29.6% [27%–31%] |
| naive + vpn | **targeted** (chưa thấy) | 1,916 | 1.5% | 0.5% | 0.9% | 28.5% | 8.6% [7%–10%] | 17.8% | 4.3% [3%–5%] |
| naive | **vpn** (chưa thấy) | 1,995 | 26.5% | 6.0% | 8.2% | 50.9% | 46.5% [44%–49%] | 37.2% | 31.6% [29%–33%] |
| naive | **targeted** (chưa thấy) | 1,916 | 1.5% | 0.5% | 0.9% | 28.5% | 8.4% [7%–10%] | 17.8% | 4.3% [3%–5%] |

- **Tổng quát một phần và tốt hơn bộ phát hiện không học**: giấu Naive còn 40,6% (69% so với khi đã thấy), giấu VPN còn 41,4% (81%), học chỉ từ Naive vẫn bắt 46,5% VPN. Cao hơn Freeman ở Naive (35,0%), VPN (26,5%) và ở Targeted (8,6% so với 1,5%), cao hơn hẳn Isolation Forest và kNN.
- **Targeted là bước nhảy khó**: chưa thấy chỉ 8,4–8,6%, khi đã thấy 28,5%. Dấu hiệu của Targeted (IP mới sát lần đăng nhập trước, mục 6) không có ở hai kiểu yếu hơn nên phải học riêng.
- **Giải thích khả dĩ (chưa kiểm chứng riêng)**: ba kiểu này chung một dấu hiệu tổng quát "thuộc tính/IP lạ so với lịch sử tài khoản" mà mô hình học được từ hai kiểu còn lại; các họ IP tấn công thì khác nhau về mạng/hành vi. **Lưu ý:** cả ba kiểu do chính tôi mô phỏng theo cùng một khuôn nên tổng quát giữa chúng dễ hơn kẻ tấn công thật; đây là cận trên lạc quan.

## 3. ATO thật: họ chưa từng thấy theo thiết kế

141 ca ATO không bao giờ vào huấn luyện hay chọn mô hình nên là họ "chưa từng thấy" theo thiết kế (kết quả ở [`ml-evaluation-v2.md`](ml-evaluation-v2.md) mục 3): LightGBM học từ IP tấn công và từ kẻ tấn công mô phỏng bắt **0%**, Isolation Forest bắt 42,1% [26–55%], hybrid 26,3% [13–39%]. Mục 4.3 và 5.1 giải thích vì sao.

## 4. Ablation theo nhóm đặc trưng

Huấn luyện lại (cùng siêu tham số, hạt giống, dừng sớm trên val) với: bỏ **một** nhóm (8 nhóm), **chỉ** một nhóm, bỏ 1 và 3 đặc trưng quan trọng nhất. Ô = giá trị (thay đổi so với đối chứng, điểm phần trăm). Nhóm: `cur` (2 đặc trưng), `novelty` (9), `history` (3), `rhythm` (8), `freeman` (8), `rarity` (7), `infra_ip` (7), `infra_asn` (6).

### 4.1 LightGBM học từ nhãn IP tấn công (recall @ FPR 1%, `attack_ip/test`)

| Cấu hình | Số đặc trưng | `attack_ip/test` |
|---|---|---|
| tất cả (đối chứng) | 50 | 15.0% (+0.0) |
| bỏ nhóm `cur` | 48 | 14.8% (-0.1) |
| bỏ nhóm `novelty` | 41 | 15.1% (+0.2) |
| bỏ nhóm `history` | 47 | 14.8% (-0.1) |
| bỏ nhóm `rhythm` | 42 | 14.4% (-0.5) |
| bỏ nhóm `freeman` | 42 | 14.6% (-0.4) |
| bỏ nhóm `rarity` | 43 | 12.1% (-2.9) |
| bỏ nhóm `infra_ip` | 43 | 17.8% (+2.8) |
| bỏ nhóm `infra_asn` | 44 | 14.6% (-0.4) |
| chỉ nhóm `cur` | 2 | 0.0% (-15.0) |
| chỉ nhóm `novelty` | 9 | 0.2% (-14.8) |
| chỉ nhóm `history` | 3 | 3.0% (-11.9) |
| chỉ nhóm `rhythm` | 8 | 3.7% (-11.2) |
| chỉ nhóm `freeman` | 8 | 7.6% (-7.4) |
| chỉ nhóm `rarity` | 7 | 18.4% (+3.5) |
| chỉ nhóm `infra_ip` | 7 | 4.6% (-10.4) |
| chỉ nhóm `infra_asn` | 6 | 12.8% (-2.2) |
| bỏ đặc trưng quan trọng nhất | 49 | 17.8% (+2.9) |
| bỏ 3 đặc trưng quan trọng nhất | 47 | 15.8% (+0.8) |

- **Không phụ thuộc mong manh vào một đặc trưng hay một nhóm**: bỏ bất kỳ nhóm nào ngoài `rarity` (−2,9) và `infra_ip` (+2,8) đổi ≤ 0,5 điểm; bỏ đặc trưng quan trọng nhất (`ip_prior_attempts_all`, 25% gain) thậm chí **tăng** 2,9 điểm, bỏ ba đặc trưng đầu (thêm `asn_fail_ratio_24h`, `rare_country`) tăng 0,8.
- **Tín hiệu nằm ở nhóm độ hiếm và ASN**: `rarity` một mình đạt 18,4% (hơn cả 15,0% của mô hình đủ), `infra_asn` 12,8%; các nhóm còn lại một mình ≤ 7,6%, `cur` và `novelty` gần 0.
- **Nhóm `infra_ip` làm hại ở test** (bỏ nó: 15,0% → 17,8%). Đây là đặc trưng theo IP cụ thể (số lượt thử trước đó của chính IP) nên dễ khớp thừa IP của train. Đề xuất chọn lại nhóm đặc trưng trên **val** ở MR8 (không chọn trên test).

### 4.2 LightGBM học từ kẻ tấn công mô phỏng (recall @ FPR 1%)

| Cấu hình | Số đặc trưng | `attacker/naive` | `attacker/vpn` | `attacker/targeted` | `ato/future` |
|---|---|---|---|---|---|
| tất cả (đối chứng) | 50 | 59.1% (+0.0) | 50.9% (+0.0) | 28.5% (+0.0) | 0.0% (+0.0) |
| bỏ nhóm `cur` | 48 | 58.6% (-0.5) | 50.9% (-0.1) | 28.9% (+0.3) | 0.0% (+0.0) |
| bỏ nhóm `novelty` | 41 | 58.1% (-1.0) | 48.8% (-2.2) | 29.0% (+0.4) | 5.3% (+5.3) |
| bỏ nhóm `history` | 47 | 59.6% (+0.5) | 51.0% (+0.1) | 28.6% (+0.1) | 0.0% (+0.0) |
| bỏ nhóm `rhythm` | 42 | 54.8% (-4.3) | 43.7% (-7.3) | 20.0% (-8.6) | 0.0% (+0.0) |
| bỏ nhóm `freeman` | 42 | 58.8% (-0.3) | 50.7% (-0.2) | 27.6% (-1.0) | 0.0% (+0.0) |
| bỏ nhóm `rarity` | 43 | 57.4% (-1.7) | 49.4% (-1.5) | 27.2% (-1.3) | 0.0% (+0.0) |
| bỏ nhóm `infra_ip` | 43 | 52.6% (-6.5) | 44.2% (-6.8) | 21.6% (-7.0) | 0.0% (+0.0) |
| bỏ nhóm `infra_asn` | 44 | 58.5% (-0.6) | 49.7% (-1.2) | 28.8% (+0.2) | 0.0% (+0.0) |
| chỉ nhóm `cur` | 2 | 0.2% (-58.9) | 0.2% (-50.8) | 0.0% (-28.5) | 0.0% (+0.0) |
| chỉ nhóm `novelty` | 9 | 25.6% (-33.5) | 4.6% (-46.3) | 0.5% (-28.1) | 10.5% (+10.5) |
| chỉ nhóm `history` | 3 | 1.4% (-57.7) | 1.2% (-49.8) | 0.9% (-27.6) | 0.0% (+0.0) |
| chỉ nhóm `rhythm` | 8 | 1.2% (-57.9) | 1.7% (-49.3) | 1.2% (-27.3) | 0.0% (+0.0) |
| chỉ nhóm `freeman` | 8 | 40.6% (-18.5) | 27.8% (-23.2) | 3.6% (-24.9) | 23.7% (+23.7) |
| chỉ nhóm `rarity` | 7 | 1.1% (-58.0) | 0.9% (-50.0) | 1.0% (-27.6) | 0.0% (+0.0) |
| chỉ nhóm `infra_ip` | 7 | 0.8% (-58.3) | 0.8% (-50.2) | 0.7% (-27.8) | 2.6% (+2.6) |
| chỉ nhóm `infra_asn` | 6 | 1.2% (-57.9) | 0.9% (-50.1) | 1.1% (-27.4) | 0.0% (+0.0) |
| bỏ đặc trưng quan trọng nhất | 49 | 59.0% (-0.1) | 50.6% (-0.4) | 28.2% (-0.4) | 5.3% (+5.3) |
| bỏ 3 đặc trưng quan trọng nhất | 47 | 53.6% (-5.5) | 44.1% (-6.9) | 16.8% (-11.7) | 0.0% (+0.0) |

- **Không nhóm "đường tắt" nào tự mang tín hiệu**: `cur`, `history`, `rhythm`, `rarity`, `infra_ip`, `infra_asn` — sáu nhóm mà kiểm định dấu vân tay yêu cầu phải ≈ 0,5 — mỗi nhóm một mình chỉ đạt **0,0–1,7%**, tức mức ngẫu nhiên. Sức mạnh đến từ `freeman` (40,6% / 27,8% Naive / VPN) và `novelty` (25,6% / 4,6%).
- **Targeted cần kết hợp**: `freeman` một mình chỉ 3,6% nhưng mô hình đủ 28,5%; bỏ `rhythm` mất 8,6 điểm, bỏ `infra_ip` mất 7,0; bỏ riêng đặc trưng đầu (`new_ip`) gần như không đổi (−0,4) vì `llr_ip` mã hoá cùng thông tin, nhưng bỏ cả ba (`new_ip`, `llr_sum`, `llr_ip`) mất 11,7 — đúng tương tác "IP mới × khoảng cách từ lần thành công trước" (mục 6), không phải một đặc trưng đơn lẻ.
- **Cấu hình bổ sung** (giả thuyết: kẻ tấn công mô phỏng hoà lẫn về hạ tầng theo thiết kế nên hạ tầng/độ hiếm chỉ dạy mô hình "hạ tầng lạ = an toàn"):

| Cấu hình | Số đặc trưng | `attacker/naive` | `attacker/vpn` | `attacker/targeted` | `ato/future` |
|---|---|---|---|---|---|
| tất cả (đối chứng) | 50 | 59.1% (+0.0) | 50.9% (+0.0) | 28.5% (+0.0) | 0.0% (+0.0) |
| chỉ các nhóm quan hệ với lịch sử (`novelty`, `freeman`, `rhythm`, `history`) | 28 | 47.7% (-11.4) | 37.7% (-13.2) | 16.2% (-12.4) | 2.6% (+2.6) |
| bỏ nhóm `rarity` + `infra_asn` | 37 | 55.8% (-3.3) | 47.4% (-3.6) | 25.2% (-3.3) | 5.3% (+5.3) |
| bỏ nhóm `rarity` + `infra_asn` + `infra_ip` | 30 | 47.2% (-11.8) | 39.4% (-11.5) | 16.1% (-12.4) | 2.6% (+2.6) |

Bỏ `rarity` + `infra_asn` chỉ mất 3,3 điểm và **không** làm mô hình bắt ATO thật (0% → 5,3%). Cột `ato/future` chỉ là chẩn đoán, không dùng để chọn: nó cho thấy mô hình học từ kẻ tấn công mô phỏng không chuyển sang ATO thật dưới bất kỳ tập đặc trưng nào thử ở đây, trừ `chỉ freeman` (23,7% ATO tương lai, thấp hơn 18,5 điểm ở Naive) — gợi ý mô hình chỉ dùng quan hệ với lịch sử tổng quát hơn nhưng kém hơn trên chính họ mô phỏng.

### 4.3 Isolation Forest và ATO thật (recall @ FPR 1%)

Isolation Forest nhẹ (100 cây, 200.000 dòng) để chạy 17 cấu hình, nên đối chứng (31,6%) thấp hơn Isolation Forest chính (42,1%); đọc **thay đổi tương đối**.

| Cấu hình | Số đặc trưng | `ato/future` | `ato/all` |
|---|---|---|---|
| tất cả (đối chứng) | 50 | 31.6% (+0.0) | 38.5% (+0.0) |
| bỏ nhóm `cur` | 48 | 39.5% (+7.9) | 42.3% (+3.8) |
| bỏ nhóm `novelty` | 41 | 10.5% (-21.1) | 11.5% (-26.9) |
| bỏ nhóm `history` | 47 | 39.5% (+7.9) | 40.8% (+2.3) |
| bỏ nhóm `rhythm` | 42 | 28.9% (-2.6) | 33.8% (-4.6) |
| bỏ nhóm `freeman` | 42 | 34.2% (+2.6) | 40.8% (+2.3) |
| bỏ nhóm `rarity` | 43 | 13.2% (-18.4) | 15.4% (-23.1) |
| bỏ nhóm `infra_ip` | 43 | 60.5% (+28.9) | 54.6% (+16.2) |
| bỏ nhóm `infra_asn` | 44 | 10.5% (-21.1) | 12.3% (-26.2) |
| chỉ nhóm `cur` | 2 | 0.0% (-31.6) | 0.0% (-38.5) |
| chỉ nhóm `novelty` | 9 | 39.5% (+7.9) | 33.8% (-4.6) |
| chỉ nhóm `history` | 3 | 0.0% (-31.6) | 0.8% (-37.7) |
| chỉ nhóm `rhythm` | 8 | 5.3% (-26.3) | 4.6% (-33.8) |
| chỉ nhóm `freeman` | 8 | 5.3% (-26.3) | 5.4% (-33.1) |
| chỉ nhóm `rarity` | 7 | 34.2% (+2.6) | 40.0% (+1.5) |
| chỉ nhóm `infra_ip` | 7 | 0.0% (-31.6) | 0.0% (-38.5) |
| chỉ nhóm `infra_asn` | 6 | 18.4% (-13.2) | 18.5% (-20.0) |

ROC-AUC tương ứng:

| Cấu hình | Số đặc trưng | `ato/future` | `ato/all` |
|---|---|---|---|
| tất cả (đối chứng) | 50 | 0.948 (+0.000) | 0.936 (+0.000) |
| bỏ nhóm `cur` | 48 | 0.930 (-0.018) | 0.920 (-0.016) |
| bỏ nhóm `novelty` | 41 | 0.924 (-0.024) | 0.929 (-0.008) |
| bỏ nhóm `history` | 47 | 0.956 (+0.008) | 0.941 (+0.005) |
| bỏ nhóm `rhythm` | 42 | 0.950 (+0.002) | 0.945 (+0.009) |
| bỏ nhóm `freeman` | 42 | 0.949 (+0.001) | 0.944 (+0.008) |
| bỏ nhóm `rarity` | 43 | 0.886 (-0.062) | 0.858 (-0.079) |
| bỏ nhóm `infra_ip` | 43 | 0.962 (+0.014) | 0.954 (+0.017) |
| bỏ nhóm `infra_asn` | 44 | 0.825 (-0.123) | 0.820 (-0.116) |
| chỉ nhóm `cur` | 2 | 0.667 (-0.281) | 0.710 (-0.226) |
| chỉ nhóm `novelty` | 9 | 0.681 (-0.267) | 0.639 (-0.297) |
| chỉ nhóm `history` | 3 | 0.461 (-0.487) | 0.491 (-0.445) |
| chỉ nhóm `rhythm` | 8 | 0.583 (-0.365) | 0.584 (-0.352) |
| chỉ nhóm `freeman` | 8 | 0.687 (-0.261) | 0.607 (-0.329) |
| chỉ nhóm `rarity` | 7 | 0.959 (+0.011) | 0.965 (+0.029) |
| chỉ nhóm `infra_ip` | 7 | 0.271 (-0.677) | 0.312 (-0.624) |
| chỉ nhóm `infra_asn` | 6 | 0.956 (+0.008) | 0.942 (+0.006) |

- **Khả năng bắt ATO nằm ở mới lạ/độ hiếm của nhà mạng**: bỏ `novelty` (−21,1 điểm), `rarity` (−18,4) hoặc `infra_asn` (−21,1) làm gần như mất; `novelty` hoặc `rarity` một mình bằng hoặc hơn mô hình đủ (39,5% và 34,2% so với 31,6%). Nhịp, Freeman, lịch sử, thiết bị một mình chỉ 5,3%, 5,3%, 0,0%, 0,0%.
- **Nhóm hạ tầng IP làm loãng tín hiệu**: bỏ nó tăng recall từ 31,6% lên 60,5% (ATO tương lai) và 38,5% lên 54,6% (130 ca). Số đếm hoạt động của từng IP là nhiễu đối với ATO.
- **Kết luận**: ATO của bộ dữ liệu này phân biệt được bằng "đăng nhập từ nhà mạng lạ/hiếm", không nhờ hành vi. Đúng như chẩn đoán một luật ở mục 5.1.

### 4.4 Kết luận về "đường tắt"

- Mô hình học từ **kẻ tấn công mô phỏng** không dựa vào nhóm nhịp/lịch sử/hạ tầng/độ hiếm/thiết bị (kiểm định dấu vân tay ở MR6 ↔ ablation ở đây đồng thuận): bằng chứng bộ mô phỏng sau bảy lần sửa không còn lối tắt theo nhóm. Không loại trừ được lối tắt theo tương tác nhiều đặc trưng.
- Mô hình **IP tấn công** không mong manh nhưng **thiên về danh tính mạng/quốc gia** (nhóm `rarity` một mình đủ; không tổng quát sang mạng chưa thấy — mục 1) và có nhóm `infra_ip` thừa.
- Với ATO thật, sức mạnh của Isolation Forest đến từ một dấu hiệu duy nhất (nhà mạng lạ).

## 5. Phân tích lỗi

### 5.1 ATO thật nào bị bỏ sót

Ngưỡng hybrid chọn trên val cho FPR 1% (2,410). 130 ca sau warm-up:

| Lát cắt ca ATO | Số ca | Hybrid bắt được | Do `ip_tan_cong` | Do `chiem_tai_khoan` | Do `bat_thuong` |
|---|---|---|---|---|---|
| tất cả (130 ca) | 130 | 27 (21%) | 0 | 2 | 25 |
| tương lai (test) | 38 | 10 (26%) | 0 | 1 | 9 |
| quá khứ | 92 | 17 (18%) | 0 | 1 | 16 |
| lịch sử: chưa có lịch sử | 46 | 0 (0%) | 0 | 0 | 0 |
| lịch sử: mỏng (1–4) | 50 | 10 (20%) | 0 | 0 | 10 |
| lịch sử: dày (≥ 5) | 34 | 17 (50%) | 0 | 2 | 15 |
| IP bị gắn nhãn tấn công | 70 | 14 (20%) | 0 | 1 | 13 |
| IP không gắn nhãn | 60 | 13 (22%) | 0 | 1 | 12 |

- **Tài khoản chưa có lịch sử: 0/46**; mỏng 20%; dày 50%. Thành phần bắt được ATO là Isolation Forest (`bat_thuong`: 25/27 ca); mô hình IP tấn công (`ip_tan_cong`) **không bắt ca nào** dù 70/130 ca đến từ IP đã bị gắn nhãn tấn công — giải thích khả dĩ: đó là đăng nhập **thành công** vào tài khoản thật, không giống lưu lượng dò mật khẩu của chính IP ấy. Bắt được 20% ca từ IP gắn nhãn và 22% ca từ IP không gắn nhãn: nhãn IP không giúp gì.

Trung vị các đặc trưng chính của ca bắt được và bỏ sót:

| Đặc trưng (trung vị) | bắt được | bỏ sót |
|---|---|---|
| `rare_asn` | 12.84 | 11.85 |
| `rare_country` | 6.82 | 6.51 |
| `new_country` | 1.00 | 1.00 |
| `new_asn` | 1.00 | 1.00 |
| `new_ip` | 1.00 | 1.00 |
| `ip_prior_attempts_all` | 1.00 | 0.00 |
| `asn_attempts_24h` | 1.00 | 1.00 |
| `u_secs_since_last_success` | 605,894.69 | 2,399,525.50 |
| `u_n_success` | 6.00 | 1.00 |
| `llr_sum` | 9.78 | 0.00 |
| `số ca` | 27 | 103 |

- Ca bỏ sót **không có gì bình thường về nhà mạng**: `rare_asn` trung vị 11,85 (bắt được: 12,84), cao hơn phân vị 99 của đăng nhập hợp lệ (10,92). Cái khác là **lịch sử**: bỏ sót có trung vị 1 lần thành công trước đó (bắt được: 6), `llr_sum` 0 (không có gì để so). Isolation Forest cần novelty theo lịch sử để nổi bật; tài khoản mỏng/mới thì tín hiệu độ hiếm bị chìm trong 50 chiều.
- **Chẩn đoán một đặc trưng (không học)** — điểm = đúng một đặc trưng độ hiếm:

| Bài | Điểm = một đặc trưng | ROC-AUC | Recall @ FPR 1% | Recall @ FPR 0,1% | Chưa có lịch sử | Mỏng | Dày |
|---|---|---|---|---|---|---|---|
| `ato/future` (38 ca) | `rare_asn` | 0.986 | 65.8% | 13.2% | 62% | 75% | 50% |
| `ato/future` (38 ca) | `rare_country` | 0.923 | 5.3% | 2.6% | 0% | 10% | 0% |
| `ato/future` (38 ca) | `rare_asn + rare_country` | 0.980 | 71.1% | 10.5% | 75% | 80% | 50% |
| `ato/future` (38 ca) | `rare_ip` | 0.773 | 0.0% | 0.0% | 0% | 0% | 0% |
| `ato/all` (130 ca) | `rare_asn` | 0.967 | 64.6% | 11.5% | 72% | 68% | 50% |
| `ato/all` (130 ca) | `rare_country` | 0.936 | 7.7% | 1.5% | 7% | 6% | 12% |
| `ato/all` (130 ca) | `rare_asn + rare_country` | 0.973 | 69.2% | 6.2% | 74% | 76% | 53% |
| `ato/all` (130 ca) | `rare_ip` | 0.771 | 3.1% | 0.0% | 4% | 2% | 3% |

  `rare_asn` bắt **65,8%** ATO tương lai (62% ở tài khoản chưa có lịch sử), hơn mọi mô hình. Phân vị của `rare_asn` ở đăng nhập hợp lệ: trung vị 2,06; phân vị 95: 7,91; phân vị 99: 10,92; ATO tương lai: trung vị 12,23. **Đây là chẩn đoán chọn sau khi thấy ATO** (nên không công bằng với các mô hình đã đánh giá) và ATO của RBA nhiều khả năng mang đặc điểm nhân tạo của cách tạo dữ liệu; nhưng nó nói thẳng rằng trên bộ dữ liệu này **không thể tuyên bố AI hơn luật ở bài ATO** — một luật độ hiếm nhà mạng đơn giản thắng.

### 5.2 Đăng nhập hợp lệ nào bị báo nhầm

Đăng nhập hợp lệ thành công giai đoạn test, chia theo kiểu (kiểu đứng trước thắng nếu khớp nhiều kiểu). RBA có thể chứa tấn công chưa gắn nhãn nên một phần "báo nhầm" có thể đúng.

Ngưỡng 2.410; tỉ lệ báo nhầm thực tế trên test 1.02% (477,017 đăng nhập hợp lệ thành công).

| Kiểu đăng nhập hợp lệ | % đăng nhập | % bị báo nhầm | Gấp mấy lần mức chung | % trong số báo nhầm | Thành phần báo (`ip` / `chiếm TK` / `bất thường`) |
|---|---|---|---|---|---|
| Tài khoản chưa có lịch sử | 18.0% | 0.57% | 0.6× | 10.1% | 80% / 0% / 20% |
| Quốc gia hoặc nhà mạng mới với tài khoản | 8.5% | 3.58% | 3.5× | 29.8% | 12% / 41% / 47% |
| IP có hoạt động lạ (nhiều tài khoản / nhiều lần thất bại) | 17.1% | 1.35% | 1.3× | 22.7% | 17% / 14% / 69% |
| Thiết bị/trình duyệt mới hoàn toàn | 26.5% | 0.63% | 0.6× | 16.5% | 6% / 69% / 25% |
| IP mới sau khi nghỉ > 30 ngày | 1.2% | 0.09% | 0.1× | 0.1% | 60% / 27% / 13% |
| Không thuộc kiểu nào ở trên | 28.6% | 0.74% | 0.7× | 20.8% | 22% / 26% / 52% |

- **Quốc gia hoặc nhà mạng mới với tài khoản** là kiểu bị báo nhầm nhiều nhất (3,58%, gấp 3,5 lần mức chung) và chiếm gần ba mươi phần trăm số báo nhầm, do `chiem_tai_khoan` (41%) và `bat_thuong` (47%). Đó là hành vi "hợp lý nhưng đáng ngờ": người đi du lịch hoặc đổi mạng bị xác thực lại; đổi lại chính kiểu này cũng là dấu hiệu chiếm tài khoản.
- **Tài khoản chưa có lịch sử** không bị báo nhầm nhiều (0,6×), và 80% báo nhầm ở nhóm này do mô hình IP tấn công (IP có hoạt động lạ), không do so với lịch sử.
- Các kiểu còn lại bị báo nhầm 0,1–1,3× mức chung: báo nhầm không dồn vào một nhóm người dùng nào khác.

## 6. Giới hạn với kẻ tấn công Targeted

Targeted (mô phỏng) biết trọn hồ sơ phiên của nạn nhân và chỉ khác ở IP. Hybrid bắt 17,8% ở FPR 1% (MR6); bảng dưới tách theo **khoảng cách từ lần đăng nhập thành công trước** của nạn nhân. Ngưỡng chọn trên val (chỉ tài khoản đã có lịch sử); trong ngoặc là tỉ lệ báo nhầm của đăng nhập hợp lệ **cùng lát cắt** ở ngưỡng ấy:

| Lát cắt | Ca dương | Bắt được @FPR 1.0% (báo nhầm cùng lát cắt) | Bắt được @FPR 0.1% (báo nhầm cùng lát cắt) |
|---|---|---|---|
| < 1 phút | 56 | 58.9% (1.79%) | 32.1% (0.36%) |
| 1–10 phút | 178 | 52.2% (2.09%) | 19.7% (0.34%) |
| 10 phút–1 giờ | 94 | 42.6% (1.90%) | 17.0% (0.34%) |
| 1–24 giờ | 267 | 25.8% (1.21%) | 6.7% (0.16%) |
| 1–7 ngày | 383 | 12.5% (0.75%) | 2.3% (0.07%) |
| 7–30 ngày | 446 | 8.7% (0.65%) | 1.6% (0.03%) |
| > 30 ngày | 492 | 6.5% (0.78%) | 0.8% (0.04%) |

Theo độ dày lịch sử:

| Lát cắt | Ca dương | Bắt được @FPR 1.0% (báo nhầm cùng lát cắt) | Bắt được @FPR 0.1% (báo nhầm cùng lát cắt) |
|---|---|---|---|
| mỏng (1–4) | 571 | 11.9% (0.85%) | 2.3% (0.05%) |
| dày (≥ 5) | 1,345 | 21.3% (1.17%) | 7.0% (0.17%) |

Nguyên nhân gốc: đăng nhập **hợp lệ** đổi IP thường xuyên hơn nhiều khi cách lâu (đăng nhập hợp lệ thành công của tài khoản đã có lịch sử, giai đoạn test):

| Khoảng cách từ lần thành công trước | % đăng nhập hợp lệ | % dùng IP mới |
|---|---|---|
| < 1 phút | 4.0% | 2.4% |
| 1–10 phút | 10.7% | 5.4% |
| 10 phút–1 giờ | 5.1% | 12.0% |
| 1–24 giờ | 11.2% | 22.3% |
| 1–7 ngày | 17.2% | 35.1% |
| 7–30 ngày | 21.4% | 53.9% |
| > 30 ngày | 30.3% | 75.9% |

Đối chiếu Naive (thuộc tính lạ hoàn toàn so với nạn nhân):

| Lát cắt | Ca dương | Bắt được @FPR 1.0% (báo nhầm cùng lát cắt) | Bắt được @FPR 0.1% (báo nhầm cùng lát cắt) |
|---|---|---|---|
| < 1 phút | 74 | 98.6% (1.79%) | 91.9% (0.36%) |
| 1–10 phút | 185 | 83.8% (2.09%) | 50.8% (0.34%) |
| 10 phút–1 giờ | 78 | 70.5% (1.90%) | 33.3% (0.34%) |
| 1–24 giờ | 268 | 67.5% (1.21%) | 38.1% (0.16%) |
| 1–7 ngày | 382 | 54.7% (0.75%) | 28.0% (0.07%) |
| 7–30 ngày | 503 | 29.2% (0.65%) | 13.7% (0.03%) |
| > 30 ngày | 510 | 26.7% (0.78%) | 11.6% (0.04%) |

- **Khoảng cách quyết định**: Targeted bắt được 58,9% trong 1 phút nhưng chỉ 12,5% ở 1–7 ngày và **6,5% sau hơn 30 ngày** (báo nhầm cùng lát cắt 0,78%). Gần một nửa ca Targeted (938/1.916) cách hơn 7 ngày. Ở FPR 0,1% thì còn 0,8% sau 30 ngày. Lý do (bảng "IP mới" ở trên): đăng nhập hợp lệ dùng IP mới chỉ 2,4% khi vừa đăng nhập trong 1 phút nhưng **75,9% khi cách hơn 30 ngày** — kẻ tấn công Targeted luôn có IP mới nên chỉ nổi bật ở khoảng cách ngắn.
- **Ngay cả Naive** cũng rơi từ 98,6% xuống 26,7% khi cách hơn 30 ngày: hệ thống dựa vào quan hệ với lần đăng nhập gần nhất nên kém với tài khoản ít đăng nhập.
- **Giả định quan trọng (đã nêu ở [`rba-evaluation.md`](rba-evaluation.md) mục 5.3)**: kẻ tấn công mô phỏng đăng nhập "đúng nhịp" của nạn nhân. Kẻ tấn công thật đăng nhập độc lập; phân phối khoảng cách của họ khác (dài hơn), nên kết quả ngoài đời có thể **thấp hơn** bảng trên.
- **Sàn lý thuyết**: kẻ tấn công dùng đúng IP, thiết bị và nhà mạng của nạn nhân (proxy trên máy nạn nhân, đánh cắp phiên) có đặc trưng **giống hệt** một đăng nhập thật, nên recall bằng đúng tỉ lệ báo nhầm — không phương pháp chấm điểm theo thuộc tính đăng nhập nào phát hiện được. Cần biện pháp khác (ràng buộc phiên với thiết bị, dấu vân tay thiết bị, hành vi sau đăng nhập).

## 7. Kết luận trung thực

| Khẳng định | Có chứng cứ? | Số liệu |
|---|---|---|
| "Hybrid phát hiện được ATO/IP tấn công/kẻ tấn công mô phỏng hơn hẳn rule Tier 2 hiện tại" | **Có**, trên bộ RBA tổng hợp | MR6: 26,3% / 12,3% / 47–18% so với ≤ 1,6% |
| "Mô hình học từ kẻ tấn công đã biết bắt được **kiểu tấn công cùng họ chưa thấy**" | **Một phần**, chỉ với kẻ tấn công mô phỏng | giữ 30–91% recall (mục 2) |
| "AI phát hiện được **tấn công hoàn toàn mới** nhờ so sánh với bình thường" | **Không** | họ IP tấn công chưa thấy: 0,0–1,1% (LightGBM), ≤ 10,1% (kNN) |
| "AI hơn rule ở bài chiếm tài khoản thật" | **Không** trên RBA | luật `rare_asn` không học: 65,8%; hybrid 26,3% |
| "Mô hình dựa vào đường tắt/dấu vân tay của bộ mô phỏng" | **Không thấy** ở mức nhóm đặc trưng | mục 4.2 |
| "Hệ thống chống được kẻ tấn công Targeted" | **Chỉ khi nó đăng nhập sát lần trước**; sau > 30 ngày ≈ 6,5% | mục 6 |

**Nên nói trong báo cáo:** hệ thống lai bắt được các họ tấn công *đã có nhãn hoặc đã mô phỏng* tốt hơn hẳn rule cố định, cần **huấn luyện lại khi có họ mới**, không tuyên bố phát hiện kiểu mới; bộ phát hiện không nhãn chỉ là lưới an toàn yếu (vài phần trăm); rule hạ tầng (độ hiếm nhà mạng) là thành phần không thể thay bằng học máy trên dữ liệu này.

**Việc tiếp theo (đề xuất, cần bạn quyết ở CP2/MR8):**
1. **Dùng 92 ca ATO quá khứ làm tập chọn ngoài** (giữ nguyên 38 ca tương lai để báo cáo cuối) để chọn nhóm đặc trưng cho từng thành phần: ablation gợi ý Isolation Forest bỏ nhóm `infra_ip` (tăng gần gấp đôi recall ATO), `gbm_attack_ip` bỏ `infra_ip`, `gbm_attacker_sim` chỉ dùng quan hệ với lịch sử. Hiện quy tắc của tôi là "141 ca ATO không bao giờ dùng để chọn"; đổi quy tắc cần bạn đồng ý.
2. **Thêm rule "nhà mạng cực hiếm toàn cục" ở MR9** (lý do độc lập với ATO: đăng nhập thành công từ mạng chưa hề hoặc rất ít xuất hiện là tín hiệu kinh điển của xác thực dựa trên rủi ro), kèm ghi chú rằng đánh giá trên ATO của RBA là vòng tròn.
3. **Rule/ngân sách xác thực lại riêng cho tài khoản mới và cách lâu > 30 ngày**: đây là vùng mô hình học yếu nhất.

## Tái lập

```bash
cd backend
venv\Scripts\python.exe -m ml.rba.holdout all --n-boot 200       # họ IP tấn công, biến thể đặc trưng, kiểu kẻ tấn công mô phỏng (~25 phút)
venv\Scripts\python.exe -m ml.rba.ablation all --n-boot 100      # ablation 3 mô hình (~35 phút); thêm `sim-extra` cho cấu hình bổ sung
venv\Scripts\python.exe -m ml.rba.errors                         # phân tích lỗi + giới hạn Targeted (~5 phút)
```
Kết quả JSON ở `backend/ml/artifacts/rba_mr7/` (không commit; sinh lại được). Mã: [`holdout.py`](../backend/ml/rba/holdout.py), [`ablation.py`](../backend/ml/rba/ablation.py), [`errors.py`](../backend/ml/rba/errors.py).
