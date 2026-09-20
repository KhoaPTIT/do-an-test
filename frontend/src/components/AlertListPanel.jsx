import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./AlertListPanel.css";

const PAGE_SIZE = 15;

// Khu vực danh sách cảnh báo (nhiệm vụ 4.3) — nối GET /alerts thật, cập
// nhật tức thời khi có cảnh báo mới qua WebSocket (nhiệm vụ 5.3).
export default function AlertListPanel({ latestAlert }) {
  const [alerts, setAlerts] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get("/alerts", { params: { page: 1, page_size: PAGE_SIZE } })
      .then((res) => {
        if (!cancelled) setAlerts(res.data.items);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được cảnh báo.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!latestAlert) return;
    setAlerts((prev) => [latestAlert, ...(prev ?? [])].slice(0, PAGE_SIZE));
  }, [latestAlert]);

  return (
    <section className="dashboard-panel" aria-label="Danh sách cảnh báo">
      <h2>Cảnh báo</h2>
      <div className="dashboard-panel__body alert-list">
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && alerts === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {!error && alerts !== null && alerts.length === 0 && (
          <p className="dashboard-panel__placeholder">Chưa có cảnh báo nào.</p>
        )}
        {!error && alerts !== null && alerts.length > 0 && (
          <ul className="alert-list__items">
            {alerts.map((alert) => (
              <li key={alert.id} className={`alert-list__item alert-list__item--${alert.severity}`}>
                <strong>{alert.alert_type}</strong> ({alert.severity}, {alert.risk_score}đ)
                <br />
                {alert.message}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
