# Tương quan chiến dịch (MR14)

Kiểm chứng thuật toán nối-theo-đồ-thị (`app/detection/campaign_correlation.py`) trên **141 ATO THẬT** của RBA (không phải kẻ tấn công mô phỏng — vẫn là dữ liệu tổng hợp theo Wiefling et al., xem project_rba_dataset.md). Mã nguồn báo cáo: [`ml/rba/campaign_correlation_eval.py`](../backend/ml/rba/campaign_correlation_eval.py).

## Mức trần: hạ tầng có được tái sử dụng qua nhiều nạn nhân không?

Trong 141 dòng ATO thật (141 biết ASN): **117 dòng (83.0%)** có CÙNG ASN với ít nhất một dòng ATO khác, tạo thành 22 ASN được tái sử dụng — nghĩa là phần lớn ATO thật KHÔNG phải tấn công đơn lẻ, đáng để tương quan thành chiến dịch. Số này CHƯA có ràng buộc thời gian (mức trần khả dĩ); các bảng dưới đây áp cửa sổ thời gian thật của thuật toán.

## Kết quả theo cửa sổ thời gian

| Cửa sổ | Số chiến dịch | Chiến dịch nhiều nạn nhân | Dòng ATO trong đó | % bao phủ | Chiến dịch lớn nhất |
|---|---|---|---|---|---|
| 1 ngày | 130 | 7 | 16 | 11.3% | 4 dòng / 4 TK / 0.0 ngày (ASN [3280]) |
| 7 ngày | 118 | 15 | 36 | 25.5% | 4 dòng / 4 TK / 0.0 ngày (ASN [3280]) |
| 30 ngày | 80 | 26 | 85 | 60.3% | 10 dòng / 10 TK / 76.6 ngày (ASN [197175]) |
| 90 ngày | 60 | 21 | 101 | 71.6% | 18 dòng / 17 TK / 282.1 ngày (ASN [206801]) |

## 3 chiến dịch lớn nhất ở cửa sổ 30 ngày (kiểm tra định tính)

- **10 dòng, 10 tài khoản khác nhau**, trải 76.6 ngày — ASN [197175], quốc gia ['CA', 'ID', 'RO']
- **7 dòng, 7 tài khoản khác nhau**, trải 89.3 ngày — ASN [206801], quốc gia ['RO']
- **6 dòng, 6 tài khoản khác nhau**, trải 50.9 ngày — ASN [206801], quốc gia ['RO']

## Diễn giải

- Cửa sổ CÀNG DÀI, số chiến dịch nhiều nạn nhân/độ bao phủ CÀNG TĂNG (gộp được nhiều đợt tái xuất hiện cách xa nhau hơn) nhưng cũng dễ gộp NHẦM hai đợt không liên quan tình cờ dùng chung ASN lớn — không có cửa sổ nào "đúng tuyệt đối", đây là đánh đổi có chủ đích, không phải thiếu sót.
- Vài chiến dịch lớn nhất (xem danh sách định tính ở trên) trải dài NHIỀU THÁNG với CHỤC tài khoản khác nhau bị nhắm — khớp trực giác về một hạ tầng bị lạm dụng lâu dài (proxy/hosting giá rẻ bị nhiều kẻ tấn công thuê lại), không phải một cụm ngẫu nhiên do trùng hợp ASN.
- **Cửa sổ dùng cho LUỒNG THẬT** (`app/detection/pipeline.py`) là **24 giờ**, KHÔNG PHẢI con số tốt nhất đo được ở bảng trên — hai câu hỏi khác nhau: RBA đo "hạ tầng có tái dùng qua NHIỀU THÁNG không" (dữ liệu 141 dòng rải cả năm, cần cửa sổ dài mới thấy), luồng thật cần "có nên gộp NGAY hôm nay không" để cảnh báo còn kịp hành động — cửa sổ dài ngày cho mục đích vận hành sẽ khiến chiến dịch "mở" hàng tháng trời, không thực tế cho một dashboard giám sát.

## Giới hạn

- RBA vẫn là dữ liệu TỔNG HỢP (Wiefling et al., CC BY 4.0) — 141 ATO là mô phỏng theo phân phối thật, không phải tấn công thật ngoài đời; số liệu ở đây chứng minh thuật toán HOẠT ĐỘNG ĐÚNG Ý ĐỊNH (phục hồi cụm hạ tầng dùng chung), không chứng minh hiệu quả trên tấn công thật.
- Nhiều giá trị IP trong RBA công khai có vẻ đã ẩn danh về dải riêng (10.x.x.x) — báo cáo dùng ASN làm tín hiệu chính vì lý do đó; luồng thật (IP không ẩn danh) có thêm tín hiệu IP đầy đủ nên có thể tương quan tốt hơn số đo ở đây.
- Chưa đo được tỉ lệ GỘP NHẦM (hai đợt tấn công độc lập bị coi là một chiến dịch chỉ vì trùng ASN lớn dùng chung bởi nhiều bên) một cách định lượng — chỉ kiểm tra định tính bằng mắt trên vài chiến dịch lớn nhất.
- Gán chiến dịch ở luồng thật là GIA TĂNG (một alert mới chỉ MỞ RỘNG chiến dịch đang có, không GỘP LẠI hai chiến dịch đã tách nếu có alert bắc cầu đến sau) — xem giới hạn chi tiết ở docstring `pipeline.py`.
