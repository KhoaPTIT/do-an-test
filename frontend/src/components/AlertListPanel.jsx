import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./AlertListPanel.css";

const PAGE_SIZE = 15;

// Khu vực danh sách cảnh báo (nhiệm vụ 4.3) — nối GET /alerts thật, cập
// nhật tức thời khi có cảnh báo mới qua WebSocket (nhiệm vụ 5.3).
// MR15 "vòng phản hồi": nút "Đúng"/"Báo nhầm" gọi POST /alerts/{id}/feedback — chỉ GHI NHẬN phản hồi (Alert.status +
// nhật ký kiểm toán); ngưỡng thích nghi được tính lại ĐỊNH KỲ bởi backend/scripts/retrain_from_feedback.py, không
// phải ngay khi bấm.
export default function AlertListPanel({ latestAlert }) {
  const [alerts, setAlerts] = useState(null);
  const [error, setError] = useState(null);
  const [submittingId, setSubmittingId] = useState(null);

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
