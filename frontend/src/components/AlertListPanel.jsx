import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { apiClient } from "../services/api";
import "./AlertListPanel.css";

const PAGE_SIZE = 15;
const EMPTY_FILTERS = { attack_family: "", rule_id: "", campaign_id: "", status: "" };

function buildParams(filters) {
  const params = { page: 1, page_size: PAGE_SIZE };
  if (filters.attack_family) params.attack_family = filters.attack_family;
  if (filters.rule_id) params.rule_id = filters.rule_id;
  if (filters.campaign_id) params.campaign_id = filters.campaign_id;
  if (filters.status) params.status = filters.status;
  return params;
}

// Khu vực danh sách cảnh báo (nhiệm vụ 4.3) — nối GET /alerts thật, cập
// nhật tức thời khi có cảnh báo mới qua WebSocket (nhiệm vụ 5.3).
// MR15 "vòng phản hồi": nút "Đúng"/"Báo nhầm" gọi POST /alerts/{id}/feedback — chỉ GHI NHẬN phản hồi (Alert.status +
// nhật ký kiểm toán); ngưỡng thích nghi được tính lại ĐỊNH KỲ bởi backend/scripts/retrain_from_feedback.py, không
// phải ngay khi bấm.
// MR17 "Dashboard v2" — bộ lọc mở rộng (họ tấn công, rule, chiến dịch, phản hồi): có bộ lọc thì TẠM NGỪNG tự chèn
// alert mới qua WebSocket (latestAlert) — alert mới chưa chắc khớp bộ lọc đang xem, chèn bừa sẽ gây hiểu nhầm.
export default function AlertListPanel({ latestAlert }) {
  const [alerts, setAlerts] = useState(null);
  const [error, setError] = useState(null);
  const [submittingId, setSubmittingId] = useState(null);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const hasActiveFilters = Object.values(filters).some((v) => v !== "");

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get("/alerts", { params: buildParams(filters) })
      .then((res) => {
        if (!cancelled) setAlerts(res.data.items);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được cảnh báo.");
      });
    return () => {
      cancelled = true;
    };
  }, [filters]);

  useEffect(() => {
    if (!latestAlert || hasActiveFilters) return;
    setAlerts((prev) => [latestAlert, ...(prev ?? [])].slice(0, PAGE_SIZE));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [latestAlert]);

  function updateFilter(key, value) {
    setFilters((prev) => ({ ...prev, [key]: value }));
  }

  function submitFeedback(alertId, correct) {
    setSubmittingId(alertId);
    apiClient
      .post(`/alerts/${alertId}/feedback`, { correct })
      .then((res) => {
        setAlerts((prev) => (prev ?? []).map((a) => (a.id === alertId ? { ...a, status: res.data.status } : a)));
      })
      .catch(() => {
        setError("Không gửi được phản hồi, thử lại sau.");
      })
      .finally(() => setSubmittingId(null));
  }

  return (
    <section className="dashboard-panel" aria-label="Danh sách cảnh báo">
      <h2>Cảnh báo</h2>
      <div className="alert-list__filters">
        <input type="text" placeholder="Họ tấn công..." value={filters.attack_family} onChange={(e) => updateFilter("attack_family", e.target.value)} />
        <input type="text" placeholder="Mã rule..." value={filters.rule_id} onChange={(e) => updateFilter("rule_id", e.target.value)} />
        <input
          type="number"
          placeholder="ID chiến dịch..."
          value={filters.campaign_id}
          onChange={(e) => updateFilter("campaign_id", e.target.value)}
        />
        <select value={filters.status} onChange={(e) => updateFilter("status", e.target.value)}>
          <option value="">Trạng thái: tất cả</option>
          <option value="open">Chưa xử lý</option>
          <option value="resolved">Đã xác nhận đúng</option>
          <option value="false_positive">Báo nhầm</option>
        </select>
        {hasActiveFilters && (
          <button type="button" className="alert-list__clear-filters" onClick={() => setFilters(EMPTY_FILTERS)}>
            Xoá lọc
          </button>
        )}
      </div>
      <div className="dashboard-panel__body alert-list">
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && alerts === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {!error && alerts !== null && alerts.length === 0 && (
          <p className="dashboard-panel__placeholder">{hasActiveFilters ? "Không có cảnh báo nào khớp bộ lọc." : "Chưa có cảnh báo nào."}</p>
        )}
        {!error && alerts !== null && alerts.length > 0 && (
          <ul className="alert-list__items">
            {alerts.map((alert) => (
              <li key={alert.id} className={`alert-list__item alert-list__item--${alert.severity}`}>
                <strong>{alert.alert_type}</strong> ({alert.severity}, {alert.risk_score}đ)
                {alert.user_id ? <Link to={`/dashboard/users/${alert.user_id}`}> · hồ sơ</Link> : null}
                {alert.campaign_id ? <Link to={`/dashboard/campaigns/${alert.campaign_id}`}> · chiến dịch</Link> : null}
                <br />
                {alert.message}
                <div className="alert-list__feedback">
                  {alert.status === "open" ? (
                    <>
                      <button type="button" disabled={submittingId === alert.id} onClick={() => submitFeedback(alert.id, true)}>
                        👍 Đúng
                      </button>
                      <button type="button" disabled={submittingId === alert.id} onClick={() => submitFeedback(alert.id, false)}>
                        👎 Báo nhầm
                      </button>
                    </>
                  ) : (
                    <span className="alert-list__feedback-done">
                      {alert.status === "false_positive" ? "Đã xác nhận: báo nhầm" : alert.status === "resolved" ? "Đã xác nhận: đúng" : alert.status}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
