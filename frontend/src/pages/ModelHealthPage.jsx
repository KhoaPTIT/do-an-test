import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./ModelHealthPage.css";

function verdictClass(verdict) {
  if (verdict === "trôi đáng kể") return "model-health__verdict--bad";
  if (verdict === "trôi vừa") return "model-health__verdict--warn";
  if (verdict === "ổn định") return "model-health__verdict--good";
  return "";
}

// MR17 "Dashboard v2" — checklist "sức khoẻ model (drift, phiên bản)". Ghép model_registry (MR12, phiên bản mô hình
// đã đăng ký) + PSI drift (MR12, ml/rba/drift.py — trước đó chỉ chạy tay qua CLI) thành một trang xem nhanh.
export default function ModelHealthPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  function load(refresh = false) {
    if (refresh) setRefreshing(true);
    apiClient
      .get("/model-health", { params: refresh ? { refresh: true } : {} })
      .then((res) => setData(res.data))
      .catch(() => setError("Không tải được sức khoẻ mô hình (cần đăng nhập quản trị)."))
      .finally(() => setRefreshing(false));
  }

  useEffect(() => load(false), []);

  return (
    <main className="model-health-page">
      <h1>🩺 Sức khoẻ mô hình</h1>

      {error && <p className="model-health-page__placeholder">{error}</p>}
      {!error && data === null && (
        <p className="model-health-page__placeholder">
          <span className="spinner" />
          Đang tải (lần đầu có thể mất vài giây — quét lại toàn bộ log thật)...
        </p>
      )}

      {data && (
        <>
          <section className="model-health-panel">
            <h2>Phiên bản đã đăng ký</h2>
            {data.versions.length === 0 ? (
              <p className="model-health-page__placeholder">Chưa có phiên bản nào được đăng ký.</p>
            ) : (
              <table className="model-health-table">
                <thead>
                  <tr>
                    <th>Tên</th>
                    <th>Phiên bản</th>
                    <th>Đang dùng</th>
                    <th>Huấn luyện lúc</th>
                    <th>Chữ ký đặc trưng</th>
                  </tr>
                </thead>
                <tbody>
                  {data.versions.map((v) => (
                    <tr key={v.id}>
                      <td>{v.name}</td>
                      <td>{v.version}</td>
                      <td>{v.is_active ? "✅ Đang dùng" : "—"}</td>
                      <td>{v.trained_at ? new Date(v.trained_at).toLocaleString("vi-VN") : "—"}</td>
                      <td className="model-health-table__mono">{v.feature_signature ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="model-health-panel">
            <div className="model-health-panel__header">
              <h2>Trôi đặc trưng (PSI) so với dữ liệu train RBA</h2>
              <button type="button" disabled={refreshing} onClick={() => load(true)}>
                {refreshing ? "Đang tính..." : "🔄 Tính lại"}
              </button>
            </div>
            <p className="model-health-page__hint">
              Tính lúc {data.drift_computed_at ? new Date(data.drift_computed_at).toLocaleString("vi-VN") : "—"} — tham chiếu {data.drift_n_reference.toLocaleString("vi-VN")} dòng
              (train RBA), hiện tại {data.drift_n_current.toLocaleString("vi-VN")} dòng (đăng nhập thật).
              {data.drift_low_confidence && (
                <strong className="model-health-page__warning"> ⚠️ Quá ít dữ liệu hiện tại — số PSI dưới đây chỉ mang tính minh hoạ.</strong>
              )}
            </p>
            <table className="model-health-table">
              <thead>
                <tr>
                  <th>Đặc trưng</th>
                  <th>PSI</th>
                  <th>Kết luận</th>
                </tr>
              </thead>
              <tbody>
                {data.drift_top_features.map((f) => (
                  <tr key={f.feature}>
                    <td className="model-health-table__mono">{f.feature}</td>
                    <td>{f.psi === null ? "—" : f.psi.toFixed(3)}</td>
                    <td className={verdictClass(f.verdict)}>{f.verdict}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </main>
  );
}
