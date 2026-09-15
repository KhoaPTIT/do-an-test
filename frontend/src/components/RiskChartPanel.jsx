import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiClient } from "../services/api";

// Khu vực biểu đồ risk score theo thời gian (nhiệm vụ 4.3) — nối dữ liệu
// thật từ GET /login-events (lấy 100 bản ghi gần nhất, vẽ theo thời gian).
// `refreshKey` tăng lên khi có cảnh báo mới qua WebSocket (nhiệm vụ 5.3).
export default function RiskChartPanel({ refreshKey = 0 }) {
  const [points, setPoints] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    apiClient
      .get("/login-events", { params: { page: 1, page_size: 100 } })
      .then((res) => {
        if (cancelled) return;
        const items = [...res.data.items].reverse(); // đảo lại thành thứ tự thời gian tăng dần
        setPoints(
          items.map((event) => ({
            time: new Date(event.created_at).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" }),
            risk_score: event.risk_score ?? 0,
          }))
        );
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được dữ liệu biểu đồ.");
      });

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return (
    <section className="dashboard-panel" aria-label="Biểu đồ risk score">
      <h2>Biểu đồ risk score</h2>
      <div className="dashboard-panel__body">
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && points === null && <p className="dashboard-panel__placeholder">Đang tải...</p>}
        {!error && points !== null && points.length === 0 && (
          <p className="dashboard-panel__placeholder">Chưa có dữ liệu đăng nhập.</p>
        )}
        {!error && points !== null && points.length > 0 && (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={points} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" tick={{ fontSize: 10 }} minTickGap={20} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} />
              <Tooltip />
              {/* Ngưỡng phân loại risk score — nhiệm vụ 4.2 */}
              <ReferenceLine y={40} stroke="#e0a800" strokeDasharray="4 4" />
              <ReferenceLine y={70} stroke="#d9363e" strokeDasharray="4 4" />
              <Line type="monotone" dataKey="risk_score" stroke="#4C72B0" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}
