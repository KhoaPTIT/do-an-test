import "leaflet/dist/leaflet.css";
import "./DashboardPage.css";

import AlertListPanel from "../components/AlertListPanel";
import LogTablePanel from "../components/LogTablePanel";
import MapPanel from "../components/MapPanel";
import RiskChartPanel from "../components/RiskChartPanel";

// Dashboard admin — bố cục 4 khu vực (nhiệm vụ 3.4): bản đồ, biểu đồ, bảng
// log, danh sách cảnh báo. Dữ liệu thật + real-time nối ở Tuần 4-5.
export default function DashboardPage() {
  return (
    <main>
      <h1>Dashboard</h1>
      <div className="dashboard-grid">
        <MapPanel />
        <RiskChartPanel />
        <LogTablePanel />
        <AlertListPanel />
      </div>
    </main>
  );
}
