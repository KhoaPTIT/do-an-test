# So với công cụ thương mại và baseline học thuật (MR19)

Hai câu hỏi khác nhau, trả lời riêng: (1) hệ thống này **thiếu gì** so với sản phẩm thương mại trưởng thành (Okta,
Microsoft Entra ID Protection, Auth0) — đọc từ tài liệu công khai, không có quyền truy cập nội bộ, không đo được
hiệu năng thật của họ; (2) hệ thống **đo lường được gì** so với baseline học thuật (Freeman et al. 2016) — số đo
được trực tiếp trên cùng dữ liệu, cùng khung đánh giá.

## 1. So với công cụ thương mại (từ tài liệu công khai)

⚠️ **Giới hạn của việc so sánh này trước khi đọc bảng:** nguồn là tài liệu/blog công khai của nhà cung cấp (liệt kê ở
cuối mục), không phải benchmark độc lập. Không đo được recall/FPR thật của họ (họ không công bố số trên bộ dữ liệu
chung). So sánh chỉ ở mức **có/không có khả năng đó** và **cơ chế công bố**, không phải "ai chính xác hơn".

| Khả năng | Hệ thống này | Okta (Adaptive MFA + ThreatInsight) | Microsoft Entra ID Protection | Auth0 (Attack Protection) |
|---|---|---|---|---|
| Luật tần suất/nhịp (brute force, credential stuffing, password spray) | ✅ 19 luật, [`rule-catalog.md`](rule-catalog.md) | ✅ ThreatInsight (mạng lưới nhiều khách hàng) | ✅ (password spray là 1 loại risk detection) | ✅ Brute-force Protection, Suspicious IP Throttling |
| Chấm điểm rủi ro ML | ✅ `hybrid_cp2`: 2 mô hình có giám sát (LightGBM) + 1 không giám sát (Isolation Forest), tự huấn luyện, minh bạch kiến trúc | ✅ "data-driven risk engine" — không công bố kiến trúc | ✅ ML tính điểm tin cậy 3 mức (thấp/vừa/cao) — không công bố kiến trúc | ⚠️ tài liệu công khai không nói rõ ML hay luật cho Attack Protection |
| Mật khẩu rò rỉ (breached password) | ❌ chưa có | — (không thấy trong tài liệu Adaptive MFA) | ✅ Leaked Credentials (đối chiếu kho rò rỉ) | ✅ Breached Password Detection (theo kiểu HaveIBeenPwned) |
| Chặn bot/CAPTCHA | 🌓 `bot_user_agent`/`scripted_client` (chỉ dựa UA/chữ ký client, không CAPTCHA) | — | — | ✅ Bot Detection → thách thức CAPTCHA |
| Di chuyển bất khả thi | ✅ tầng 1 + rule engine + `impossible_travel_geo` (ML) | 🌓 "anomalous location" (không rõ có dùng khoảng cách/vận tốc) | ✅ "Atypical travel" | ✅ Adaptive MFA: Impossible Travel |
| Giải thích từng cảnh báo | ✅ tối đa 3 yếu tố/cảnh báo, SHAP/z-score, câu tiếng Việt "thường…→nay…" ([`ml-explanations.md`](ml-explanations.md)) | ✅ System Log `DebugContext`/`DebugData` (lý do dạng nhãn, vd "Anomalous device") | ✅ báo cáo Risky sign-ins có chi tiết loại phát hiện, có gắn nhãn "AI confirmed sign-in safe" khi tự sửa | ⚠️ không thấy giải thích per-alert công khai |
| Ngưỡng thích nghi theo user/nhóm | ✅ MR15: nới lỏng theo phản hồi "báo nhầm", không bao giờ tự siết dưới mức nhóm ([`feedback-loop.md`](feedback-loop.md)) | ✅ hồ sơ hành vi cập nhật dần theo mỗi lần đăng nhập thành công; tài khoản mới mặc định risk cao | 🌓 không thấy tài liệu công khai nói rõ mức cá nhân hoá | 🌓 không thấy tài liệu công khai nói rõ |
| Thời gian phát hiện | ✅ tất cả real-time (đồng bộ trong `/login`, p95 xem [`performance.md`](performance.md)) | ✅ real-time (ThreatInsight/Risk Engine đồng bộ) | ⚠️ CÓ CẢ hai: real-time (5-10 phút mới lên báo cáo) VÀ offline (tới 48 giờ) — một số phát hiện của Entra ID CHỦ Ý trễ để chính xác hơn | ✅ real-time |
| Phản ứng tự động | ✅ MR16: step-up OTP (mô phỏng), khoá tài khoản/IP có hạn, admin mở khoá | ✅ chặn/MFA theo policy cấu hình | ✅ Conditional Access: MFA, chặn tới khi SSPR, tự làm sạch nếu remediate | ✅ chặn theo luật, thách thức CAPTCHA |
| Tương quan nhiều tài khoản/chiến dịch | ✅ MR14: gom theo hạ tầng chung (IP/ASN/UA) | ✅ (mạng ThreatInsight liên-khách hàng, quy mô lớn hơn nhiều) | ✅ (Microsoft Threat Intelligence toàn cầu) | 🌓 không thấy tài liệu công khai chi tiết |
| Tín hiệu danh tiếng liên-khách hàng (nhiều tổ chức) | ❌ không có — chỉ thấy log của chính hệ thống này | ✅ ThreatInsight tổng hợp từ nhiều khách hàng Okta | ✅ Microsoft Threat Intelligence (quy mô hãng) | ✅ (mạng lưới Auth0/Okta) |
| Dữ liệu huấn luyện/kiểm chứng | RBA **tổng hợp** (1 bộ dữ liệu học thuật, xem giới hạn ở [`rba-data-card.md`](rba-data-card.md)) + simulator tự viết + log hệ thống tự dựng | log thật, quy mô nhiều triệu khách hàng doanh nghiệp | log thật, quy mô Microsoft 365/Azure AD toàn cầu | log thật, quy mô khách hàng Auth0/Okta CIC |
| Vận hành/hỗ trợ | dự án capstone, 2 người, 8 tuần | sản phẩm thương mại, SOC/SLA | sản phẩm thương mại, SOC/SLA, tuân thủ (SOC2, ISO...) | sản phẩm thương mại, SOC/SLA |

**Đọc bảng cho đúng:** hệ thống này có **hầu hết các LOẠI khả năng** cùng tên với ba sản phẩm trên (luật tần suất, ML
risk score, impossible travel, giải thích cảnh báo, phản ứng tự động, tương quan chiến dịch) — đây là điều đáng ghi
nhận cho một dự án 8 tuần. Nhưng khoảng cách thật nằm ở ba chỗ bảng trên không thể hiện hết:

1. **Tín hiệu danh tiếng liên-khách hàng là khác biệt lớn nhất, không thể thu hẹp bằng kỹ thuật.** ThreatInsight/Microsoft Threat Intelligence tổng hợp từ hàng triệu tổ chức; hệ thống này chỉ thấy log của chính nó. Đây là lý do `distributed_bruteforce` có trọng số 0,0 ([`behavior-coverage-matrix.md`](behavior-coverage-matrix.md) mục 2) — thiếu chính loại dữ liệu mà lợi thế thương mại lớn nhất nằm ở đó.
2. **Không công cụ thương mại nào công bố recall/FPR trên dữ liệu công khai** để so trực tiếp — mọi "✅" ở bảng trên là **có tính năng**, không phải **tính năng đó tốt bằng hoặc hơn**. Việc này KHÔNG đối xứng: hệ thống này công bố số cụ thể có khoảng tin cậy ở [`ml-evaluation-v2.md`](ml-evaluation-v2.md); ba công cụ kia thì không, nên không thể xác nhận hay bác bỏ tuyên bố tiếp thị của họ.
3. **Chưa qua kiểm chứng ngoài đời** trên bất kỳ quy mô nào gần với thương mại — mọi số của dự án này đến từ dữ liệu tổng hợp hoặc tự mô phỏng ([`rba-data-card.md`](rba-data-card.md), [`attack-scenarios-v2.md`](attack-scenarios-v2.md)).

**Nguồn (truy cập 28/09/2026):**
- Okta: [Risk scoring](https://help.okta.com/oie/en-us/content/topics/security/security_risk_scoring.htm), [Risk-Based Authentication](https://www.okta.com/identity-101/risk-based-authentication/), [ThreatInsight](https://www.okta.com/blog/2018/12/how-oktas-threatinsight-enhances-adaptive-mfa/)
- Microsoft Entra ID Protection: [Risk detection types and levels](https://learn.microsoft.com/en-us/entra/id-protection/concept-risk-detection-types), [Risk-based access policies](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies)
- Auth0: [Attack Protection](https://auth0.com/docs/secure/attack-protection), [Auth0 Launches Adaptive MFA](https://auth0.com/blog/auth0-launches-adaptive-mfa/)

## 2. So với baseline học thuật (Freeman et al. 2016)

Không cần nghiên cứu thêm — số đã đo trực tiếp trên **cùng bộ RBA, cùng bài kiểm tra, cùng khoảng tin cậy** ở
[`ml-evaluation-v2.md`](ml-evaluation-v2.md) (mô hình `freeman_all`/`freeman_no_ip`: cài lại đúng công thức log-tỉ-số
khả năng 7 thuộc tính của Freeman, Dell'Amico, Oorschot — NDSS 2016 — mà RBA được thiết kế để tái lập). Đây là so
sánh **công bằng nhất** trong tài liệu này vì cùng dữ liệu, cùng thước đo, không phải đọc quảng cáo.

**Recall @ FPR 1%, giai đoạn test, trọng số dân số:**

| Họ tấn công | Freeman et al. 2016 (`freeman_all`) | `hybrid_cp2` (hệ thống này) |
|---|---|---|
| ATO thật, tương lai (38 ca) | 15,8% [7–29] | **36,8%** [21–51] |
| IP tấn công (test) | 0,3% | **12,4%** |
| Kẻ tấn công Naive (mô phỏng) | 35,0% | 36,4% (tương đương — Freeman hơi thấp hơn) |
| Kẻ tấn công VPN (mô phỏng) | 26,5% | 27,0% (tương đương) |
| Kẻ tấn công Targeted (mô phỏng) | 1,5% | **8,4%** |

- **Hơn rõ rệt ở ATO thật và IP tấn công** — đúng như kỳ vọng: Freeman chỉ dùng log-tỉ-số của 7 thuộc tính đơn lẻ,
  không có tín hiệu hạ tầng (ASN/IP tần suất) hay nhịp độ mà `hybrid_cp2` có qua `gbm_attack_ip`/Isolation Forest.
- **Xấp xỉ nhau ở kẻ tấn công mô phỏng Naive/VPN** — hai phương pháp học/tính cùng loại tín hiệu (mới lạ so với hồ sơ
  user) nên hội tụ; khác biệt trong khoảng nhiễu.
- **Không phải "AI thắng tuyệt đối":** ở giai đoạn CP1 (trước khi sửa bộ mô phỏng, [`ml-evaluation-v2.md`](ml-evaluation-v2.md) mục "Đính chính"), Freeman từng vượt Isolation Forest ở Naive (ROC-AUC 0,93 so với 0,76) — baseline đơn giản vẫn cạnh tranh được ở một số bài, không nên coi là lỗi thời.
- Baseline **không hiệu chỉnh lại** cho `hybrid_cp2` (không có nhóm đặc trưng để bỏ/giữ) — so sánh này dùng nguyên bản Freeman cho cả hai cột, chỉ cột "hệ thống này" đổi.

**Kết luận so với học thuật:** hệ thống hơn baseline NDSS 2016 rõ rệt ở đúng hai chỗ có giá trị vận hành nhất (ATO
thật, IP tấn công hàng loạt) nhờ thêm tín hiệu hạ tầng/nhịp độ mà Freeman không có trong công thức gốc; ở kẻ tấn công
mô phỏng né tránh tốt (Targeted) cả hai đều yếu (8,4% và 1,5%) — xác nhận đây là giới hạn của **cách tiếp cận**
(chấm điểm theo thuộc tính đăng nhập), không phải của một mô hình cụ thể.
