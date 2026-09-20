import "leaflet/dist/leaflet.css";
import "./DashboardPage.css";

import { useCallback, useEffect, useState } from "react";

import AlertListPanel from "../components/AlertListPanel";
import LogTablePanel from "../components/LogTablePanel";
import MapPanel from "../components/MapPanel";
import RiskChartPanel from "../components/RiskChartPanel";
import { useAlertsSocket } from "../services/useAlertsSocket";

const TOAST_DURATION_MS = 6000;

// Dashboard admin — bố cục 4 khu vực (nhiệm vụ 3.4), nối dữ liệu thật
// (nhiệm vụ 4.3) và cập nhật real-time qua WebSocket (nhiệm vụ 5.3): khi
// có cảnh báo mới, bảng log/biểu đồ tự làm mới + hiện popup, bản đồ vẽ
// đường nối nếu là impossible travel.
export default function DashboardPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const [latestAlert, setLatestAlert] = useState(null);
  const [toast, setToast] = useState(null);

  const handleAlert = useCallback((alert) => {
    setLatestAlert(alert);
    setRefreshKey((key) => key + 1);
    setToast(alert);
  }, []);

  const connected = useAlertsSocket(handleAlert);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(null), TOAST_DURATION_MS);
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <main>
      <div className="dashboard-page__header">
        <h1>📊 Dashboard giám sát</h1>
        <span className={connected ? "ws-status ws-status--connected" : "ws-status ws-status--disconnected"}>
          <span className="ws-status__dot" />
          {connected ? "Real-time" : "Mất kết nối, đang thử lại..."}
        </span>
      </div>

      {toast && (
        <div className="alert-toast" role="alert">
          🚨 <strong>{toast.alert_type}</strong> — {toast.message}
        </div>
      )}

      <div className="dashboard-grid">
        <MapPanel latestAlert={latestAlert} />
        <RiskChartPanel refreshKey={refreshKey} />
        <LogTablePanel refreshKey={refreshKey} />
        <AlertListPanel latestAlert={latestAlert} />
      </div>
    </main>
  );
}
