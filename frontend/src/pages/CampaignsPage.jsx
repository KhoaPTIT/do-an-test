import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { apiClient } from "../services/api";
import "./CampaignsPage.css";

const PAGE_SIZE = 20;

// Danh sách chiến dịch (MR14) — nhiều tài khoản KHÁC NHAU bị tấn công từ CÙNG hạ tầng (IP/ASN) trong 24h, gán tự động
// bởi app/detection/pipeline.py (app/detection/campaign_correlation.py). Khác danh sách cảnh báo (từng lần đăng nhập
// riêng lẻ): mỗi dòng ở đây là MỘT ĐỢT TẤN CÔNG đã gộp nhiều alert lại.
// MR17 "Dashboard v2" — polish đã liệt kê từ MR14: bộ lọc trạng thái (backend đã hỗ trợ ?status= từ MR14, frontend
// trước đó chưa dùng) + phân trang (trước chỉ lấy CỐ ĐỊNH trang 1).
export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState(null);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [total, setTotal] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const params = { page, page_size: PAGE_SIZE };
    if (status) params.status = status;
    apiClient
      .get("/campaigns", { params })
      .then((res) => {
        if (!cancelled) {
          setCampaigns(res.data.items);
          setTotal(res.data.total);
        }
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được danh sách chiến dịch.");
      });
    return () => {
      cancelled = true;
    };
  }, [page, status]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <main className="campaigns-page">
      <h1>🕸️ Chiến dịch tấn công</h1>
      <p className="campaigns-page__hint">
        Nhiều tài khoản khác nhau bị nhắm từ cùng một IP hoặc nhà mạng (ASN) trong vòng 24 giờ được tự động gộp thành một chiến dịch.
      </p>

      <div className="campaigns-page__filters">
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
        >
          <option value="">Trạng thái: tất cả</option>
          <option value="open">Đang mở</option>
          <option value="closed">Đã đóng</option>
        </select>
      </div>

      {error && <p className="campaigns-page__placeholder">{error}</p>}
      {!error && campaigns === null && (
        <p className="campaigns-page__placeholder">
          <span className="spinner" />
          Đang tải...
        </p>
      )}
      {!error && campaigns !== null && campaigns.length === 0 && (
        <p className="campaigns-page__placeholder">Chưa phát hiện chiến dịch nào — mọi cảnh báo hiện tại đều là sự vụ đơn lẻ.</p>
      )}
      {!error && campaigns !== null && campaigns.length > 0 && (
        <>
          <table className="campaigns-table">
            <thead>
              <tr>
                <th>Chiến dịch</th>
                <th>Họ tấn công</th>
                <th>Số cảnh báo</th>
                <th>Số tài khoản bị nhắm</th>
                <th>Trạng thái</th>
                <th>Hoạt động gần nhất</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link to={`/dashboard/campaigns/${c.id}`}>{c.label}</Link>
                  </td>
                  <td>{c.attack_family ?? "—"}</td>
                  <td>{c.alert_count}</td>
                  <td>{c.targeted_accounts}</td>
                  <td>
                    <span className={`campaigns-status campaigns-status--${c.status}`}>{c.status === "open" ? "Đang mở" : "Đã đóng"}</span>
                  </td>
                  <td>{new Date(c.last_seen_at).toLocaleString("vi-VN")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="campaigns-page__pagination">
            <button type="button" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              ← Trước
            </button>
            <span>
              Trang {page}/{totalPages} ({total} chiến dịch)
            </span>
            <button type="button" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              Sau →
            </button>
          </div>
        </>
      )}
    </main>
  );
}
