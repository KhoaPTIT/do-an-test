import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { apiClient } from "../services/api";
import "./LogTablePanel.css";
import "./AlertListPanel.css"; // dùng chung .ml-badge

const PAGE_SIZE = 15;

const EMPTY_FILTERS = { username: "", success: "", risk_level: "", is_synthetic: "" };

// Tô màu dòng theo risk_score, đúng ngưỡng đã định nghĩa ở nhiệm vụ 4.2
// (< 40 bình thường, 40-70 trung bình, > 70 cao).
function riskClassName(riskScore) {
  if (riskScore === null || riskScore === undefined) return "";
  if (riskScore > 70) return "risk-row--high";
  if (riskScore >= 40) return "risk-row--medium";
  return "risk-row--low";
}

// Phase 4.1: ô AI/ML — giá trị THẬT backend ghi lúc chấm (điểm, ngưỡng, kết luận) hoặc lý do không chấm.
function mlCell(event) {
  if (event.ml_anomaly_score != null && event.ml_threshold != null) {
    return (
      <span title={`model ${event.ml_model_version} — điểm ${event.ml_anomaly_score.toFixed(4)} / ngưỡng ${event.ml_threshold.toFixed(4)}`}>
        {event.ml_anomaly_score.toFixed(2)} {event.ml_is_anomaly ? <span className="ml-badge ml-badge--anomaly">Anomaly</span> : <span className="ml-badge ml-badge--normal">Normal</span>}
      </span>
    );
  }
  const reason = event.ml_details?.reason;
  if (reason === "model_not_loaded") return <span title="AI model: Not loaded">Not loaded</span>;
  if (reason === "out_of_scope") return <span title="Ngoài phạm vi chấm: lần thất bại, tài khoản mới hoặc hồ sơ chưa trưởng thành">ngoài phạm vi</span>;
  return "-";
}

// Chuyển filter UI (chuỗi rỗng = "tất cả") thành query param gửi backend.
function buildParams(page, filters) {
  const params = { page, page_size: PAGE_SIZE };
  if (filters.username.trim()) params.username = filters.username.trim();
  if (filters.success !== "") params.success = filters.success === "true";
  if (filters.risk_level !== "") params.risk_level = filters.risk_level;
  if (filters.is_synthetic !== "") params.is_synthetic = filters.is_synthetic === "true";
  return params;
}

// Khu vực bảng log đăng nhập (nhiệm vụ 4.3) — nối GET /login-events thật,
// có phân trang + BỘ LỌC (nâng cấp sau Tuần 7: log lên tới hàng nghìn dòng,
// cần lọc theo username/kết quả/mức rủi ro/dữ liệu thật-hay-giả-lập).
// `refreshKey` tăng lên mỗi khi có cảnh báo mới qua WebSocket (nhiệm vụ
// 5.3) để bảng tự làm mới mà không cần reload trang.
export default function LogTablePanel({ refreshKey = 0 }) {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [usernameInput, setUsernameInput] = useState(""); // gõ ngay, chỉ áp filter sau 1 nhịp nghỉ
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Debounce ô tìm username 350ms — tránh gọi API dồn dập mỗi ký tự gõ.
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => (prev.username === usernameInput ? prev : { ...prev, username: usernameInput }));
      setPage(1);
    }, 350);
    return () => clearTimeout(timer);
  }, [usernameInput]);

  useEffect(() => {
    let cancelled = false;
    // Chỉ hiện spinner toàn khung khi CHƯA có dữ liệu gì (lần đầu). Khi
    // refetch ngầm do có alert mới (refreshKey đổi) hoặc đổi bộ lọc, giữ
    // nguyên bảng cũ trên màn hình cho tới khi có dữ liệu mới — tránh giật
    // hình lúc demo.
    if (data === null) setLoading(true);
    setError(null);

    apiClient
      .get("/login-events", { params: buildParams(page, filters) })
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, refreshKey, filters]);

  function updateFilter(key, value) {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setPage(1); // đổi bộ lọc thì quay lại trang 1
  }

  const hasActiveFilters = usernameInput !== "" || Object.values(filters).some((v) => v !== "");
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <section className="dashboard-panel" aria-label="Bảng log đăng nhập">
      <h2>Log đăng nhập</h2>

      <div className="log-table__filters">
        <input
          type="text"
          placeholder="Tìm username..."
          value={usernameInput}
          onChange={(e) => setUsernameInput(e.target.value)}
        />
        <select value={filters.success} onChange={(e) => updateFilter("success", e.target.value)}>
          <option value="">Kết quả: tất cả</option>
          <option value="true">Thành công</option>
          <option value="false">Thất bại</option>
        </select>
        <select value={filters.risk_level} onChange={(e) => updateFilter("risk_level", e.target.value)}>
          <option value="">Risk: tất cả</option>
          <option value="low">Thấp (&lt;40)</option>
          <option value="medium">Trung bình (40-70)</option>
          <option value="high">Cao (&gt;70)</option>
        </select>
        <select value={filters.is_synthetic} onChange={(e) => updateFilter("is_synthetic", e.target.value)}>
          <option value="">Dữ liệu: tất cả</option>
          <option value="false">Chỉ dữ liệu thật</option>
          <option value="true">Chỉ dữ liệu giả lập</option>
        </select>
        {hasActiveFilters && (
          <button
            type="button"
            className="log-table__clear-filters"
            onClick={() => {
              setFilters(EMPTY_FILTERS);
              setUsernameInput("");
              setPage(1);
            }}
          >
            Xoá lọc
          </button>
        )}
      </div>

      <div className="dashboard-panel__body log-table">
        {loading && data === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && data && data.items.length === 0 && (
          <p className="dashboard-panel__placeholder">
            {hasActiveFilters ? "Không có bản ghi nào khớp bộ lọc." : "Chưa có dữ liệu đăng nhập."}
          </p>
        )}
        {!error && data && data.items.length > 0 && (
          <>
            <table className="log-table__table">
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Username</th>
                  <th>Kết quả</th>
                  <th>Risk</th>
                  <th title="Model bất thường Isolation Forest (Phase 4.1, docs/ml-anomaly-model.md): điểm / ngưỡng, chỉ chấm lần thành công của hồ sơ trưởng thành">
                    AI/ML
                  </th>
                  <th>Vị trí</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((event) => (
                  <tr key={event.id} className={riskClassName(event.risk_score)}>
                    <td>{new Date(event.created_at).toLocaleString("vi-VN")}</td>
                    <td>{event.user_id ? <Link to={`/dashboard/users/${event.user_id}`}>{event.attempted_username}</Link> : event.attempted_username}</td>
                    <td>{event.success ? "✅" : "❌"}</td>
                    <td>{event.risk_score ?? "-"}</td>
                    <td>{mlCell(event)}</td>
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
