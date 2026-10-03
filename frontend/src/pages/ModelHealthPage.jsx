import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./ModelHealthPage.css";

function verdictClass(verdict) {
  if (verdict === "trôi đáng kể") return "model-health__verdict--bad";
  if (verdict === "trôi vừa") return "model-health__verdict--warn";
  if (verdict === "ổn định") return "model-health__verdict--good";
  return "";
}

function MlStatusPanel({ status, error }) {
  if (error) return <p className="model-health-page__placeholder">{error}</p>;
  if (status === null) return <p className="model-health-page__placeholder"><span className="spinner" />Đang tải trạng thái model...</p>;
  const files = status.artifact_files ?? {};
  return (
    <>
      <p className={status.ml_available ? "model-health__verdict--good" : "model-health__verdict--bad"}>
        <strong>{status.ml_available ? "✅ AI model: Loaded" : "⚠️ AI model: Not loaded"}</strong>
        {!status.ml_available && " — hệ thống đang chạy chỉ với 20 detector luật (ML không bao giờ chặn đăng nhập)."}
      </p>
      <table className="model-health-table">
        <tbody>
          <tr><th>Model</th><td>{status.model_name ?? "—"}</td></tr>
          <tr><th>Phiên bản</th><td className="model-health-table__mono">{status.model_version ?? "—"}</td></tr>
          <tr><th>Ngưỡng (threshold)</th><td>{status.threshold == null ? "—" : status.threshold.toFixed(4)}</td></tr>
          <tr>
            <th>Chữ ký đặc trưng (model / code)</th>
            <td className="model-health-table__mono">
              {status.feature_signature ?? "—"} / {status.code_feature_signature}
              {status.feature_signature && status.feature_signature !== status.code_feature_signature && " ⚠️ lệch"}
            </td>
          </tr>
          <tr><th>Phạm vi chấm</th><td>{status.scope ?? "—"}</td></tr>
          <tr><th>Trọng số trong risk engine</th><td>{status.risk_weight_when_anomalous} khi bất thường · được tự khoá: {status.can_lock ? "có" : "không"}</td></tr>
          <tr><th>Thư mục artifact</th><td className="model-health-table__mono">{status.artifact_dir ?? "—"}</td></tr>
          <tr>
            <th>File artifact</th>
            <td>{Object.entries(files).map(([name, ok]) => `${name} ${ok ? "✅" : "❌"}`).join(" · ") || "—"}</td>
          </tr>
          <tr><th>Huấn luyện lúc</th><td>{status.trained_at ? new Date(status.trained_at).toLocaleString("vi-VN") : "—"}</td></tr>
          <tr><th>Nạp lúc</th><td>{status.loaded_at ? new Date(status.loaded_at).toLocaleString("vi-VN") : "—"}</td></tr>
          <tr><th>Lỗi nạp gần nhất</th><td>{status.last_load_error ?? "—"}</td></tr>
        </tbody>
      </table>
    </>
  );
}

// MR17 "Dashboard v2" — checklist "sức khoẻ model (drift, phiên bản)". Phase 4.1: khối đầu là model bất thường ĐANG CHẠY
// (GET /ml/status — số thật từ backend, không dựng ở frontend); khối PSI bên dưới là phân tích cũ trên đặc trưng RBA
// (hybrid_cp2, không còn chạy ở runtime) — tải riêng để lỗi của nó không che trạng thái model.
export default function ModelHealthPage() {
  const [mlStatus, setMlStatus] = useState(null);
  const [mlError, setMlError] = useState(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  function load(refresh = false) {
    if (refresh) setRefreshing(true);
    apiClient
      .get("/model-health", { params: refresh ? { refresh: true } : {} })
      .then((res) => setData(res.data))
      .catch(() => setError("Không tải được phiên bản / trôi đặc trưng (cần đăng nhập quản trị, hoặc thiếu dữ liệu train RBA cũ)."))
      .finally(() => setRefreshing(false));
  }

  useEffect(() => {
    apiClient
      .get("/ml/status")
      .then((res) => setMlStatus(res.data))
      .catch(() => setMlError("Không tải được trạng thái model AI (cần đăng nhập quản trị)."));
    load(false);
  }, []);

  return (
    <main className="model-health-page">
      <h1>🩺 Sức khoẻ mô hình</h1>

      <section className="model-health-panel">
        <h2>Model AI đang chạy (Isolation Forest — tín hiệu bổ sung cho 20 detector luật)</h2>
        <MlStatusPanel status={mlStatus} error={mlError} />
      </section>

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
              <h2>Tham chiếu cũ: trôi đặc trưng RBA (hybrid_cp2 — không còn chạy ở runtime từ Phase 4.1)</h2>
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
