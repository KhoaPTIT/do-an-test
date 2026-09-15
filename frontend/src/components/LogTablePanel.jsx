import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./LogTablePanel.css";

const PAGE_SIZE = 15;

// Tô màu dòng theo risk_score, đúng ngưỡng đã định nghĩa ở nhiệm vụ 4.2
// (< 40 bình thường, 40-70 trung bình, > 70 cao).
function riskClassName(riskScore) {
  if (riskScore === null || riskScore === undefined) return "";
  if (riskScore > 70) return "risk-row--high";
  if (riskScore >= 40) return "risk-row--medium";
  return "risk-row--low";
}

// Khu vực bảng log đăng nhập (nhiệm vụ 4.3) — nối GET /login-events thật,
// có phân trang.
export default function LogTablePanel() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    apiClient
      .get("/login-events", { params: { page, page_size: PAGE_SIZE } })
      .then((res) => {
        if (!cancelled) setData(res.data);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được log đăng nhập.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <section className="dashboard-panel" aria-label="Bảng log đăng nhập">
      <h2>Log đăng nhập</h2>
      <div className="dashboard-panel__body log-table">
        {loading && <p className="dashboard-panel__placeholder">Đang tải...</p>}
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!loading && !error && data && data.items.length === 0 && (
          <p className="dashboard-panel__placeholder">Chưa có dữ liệu đăng nhập.</p>
        )}
        {!loading && !error && data && data.items.length > 0 && (
          <>
            <table className="log-table__table">
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Username</th>
                  <th>Kết quả</th>
                  <th>Risk</th>
                  <th>Vị trí</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((event) => (
                  <tr key={event.id} className={riskClassName(event.risk_score)}>
                    <td>{new Date(event.created_at).toLocaleString("vi-VN")}</td>
                    <td>{event.attempted_username}</td>
                    <td>{event.success ? "✅" : "❌"}</td>
                    <td>{event.risk_score ?? "-"}</td>
                    <td>{event.city ? `${event.city}, ${event.country}` : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="log-table__pagination">
              <button type="button" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                ← Trước
              </button>
              <span>
                Trang {page}/{totalPages} ({data.total} bản ghi)
              </span>
              <button type="button" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Sau →
              </button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
