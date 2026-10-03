// Chi tiết MỘT cảnh báo (Phase 4.1): detector chính, tín hiệu phụ, điểm rủi ro, bằng chứng luật, và khối AI/ML.
// Mọi giá trị đọc THẲNG từ `alert.explanation` do backend ghi lúc chấm (GET /alerts hoặc WebSocket) — không suy diễn,
// không dựng dữ liệu giả ở frontend. Thiếu khối `ml` (cảnh báo cũ, trước Phase 4.1) thì ghi rõ là không có dữ liệu.

const ML_REASON_TEXT = {
  model_not_loaded: "AI model: Not loaded (chưa nạp model — hệ thống chỉ dùng 20 detector luật)",
  out_of_scope: "Ngoài phạm vi chấm (lần thất bại, tài khoản mới hoặc hồ sơ chưa đủ 10 lần / 7 ngày)",
  error: "Lỗi khi chấm — đã bỏ qua tín hiệu ML",
};

const DETECTOR_LABEL = { hybrid_ml: "AI/ML (Isolation Forest) — không luật nào khớp" };

function formatValue(value) {
  if (Array.isArray(value)) return value.join(", ");
  if (value !== null && typeof value === "object") return JSON.stringify(value);
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(3);
  return String(value);
}

export function MlBlock({ ml }) {
  if (!ml) {
    return <p className="alert-details__muted">Không có dữ liệu ML cho cảnh báo này (tạo trước khi tích hợp model).</p>;
  }
  if (!ml.available || ml.anomaly_score === null || ml.anomaly_score === undefined) {
    return (
      <dl className="alert-details__grid">
        <dt>Model</dt>
        <dd>{ml.model ? `${ml.model} (${ml.version})` : "—"}</dd>
        <dt>Kết quả</dt>
        <dd>{ML_REASON_TEXT[ml.reason] ?? ml.reason ?? "—"}</dd>
      </dl>
    );
  }
  return (
    <dl className="alert-details__grid">
      <dt>Model</dt>
      <dd>
        {ml.model === "isolation_forest" ? "Isolation Forest" : ml.model} <span className="alert-details__muted">({ml.version})</span>
      </dd>
      <dt>Anomaly score</dt>
      <dd>{ml.anomaly_score.toFixed(4)}</dd>
      <dt>Threshold</dt>
      <dd>{ml.threshold.toFixed(4)}</dd>
      <dt>Result</dt>
      <dd>
        <span className={ml.is_anomaly ? "ml-badge ml-badge--anomaly" : "ml-badge ml-badge--normal"}>{ml.is_anomaly ? "Anomaly" : "Normal"}</span>
      </dd>
      {ml.top_features && ml.top_features.length > 0 && (
        <>
          <dt>Đặc trưng lệch nhất</dt>
          <dd>
            {ml.top_features.map((f) => (
              <span key={f.feature} className="alert-details__chip" title={`${f.feature} = ${f.value} (z = ${f.z})`}>
                {f.label ?? f.feature} (z={f.z})
              </span>
            ))}
          </dd>
        </>
      )}
    </dl>
  );
}

export default function AlertDetails({ alert }) {
  const exp = alert.explanation ?? {};
  const evidence = exp.evidence ?? {};
  const secondary = exp.secondary_signals ?? [];
  return (
    <div className="alert-details">
      <dl className="alert-details__grid">
        <dt>Primary detector</dt>
        <dd>{DETECTOR_LABEL[exp.primary_detector] ?? exp.primary_detector ?? alert.rule_id ?? "—"}</dd>
        <dt>Hành vi</dt>
        <dd>{exp.behavior ?? "—"}</dd>
        <dt>Secondary signals</dt>
        <dd>{secondary.length ? secondary.map((s) => <span key={s} className="alert-details__chip">{s}</span>) : "—"}</dd>
        <dt>Risk score</dt>
        <dd>
          {exp.risk_score ?? alert.risk_score}/100 · hành động: {exp.action ?? "—"}
          {exp.ml_lock_suppressed ? " (ML không được tự khoá — đã hạ về step_up)" : ""}
        </dd>
        <dt>Lý do cảnh báo</dt>
        <dd>{exp.alert_reason ?? "—"}</dd>
      </dl>
      <h4>Rule evidence</h4>
      {Object.keys(evidence).length === 0 ? (
        <p className="alert-details__muted">Không có bằng chứng luật (cảnh báo chỉ do ML hoặc cảnh báo cũ).</p>
      ) : (
        <dl className="alert-details__grid">
          {Object.entries(evidence).map(([key, value]) => (
            <div key={key} className="alert-details__row">
              <dt>{key}</dt>
              <dd>{formatValue(value)}</dd>
            </div>
          ))}
        </dl>
      )}
      <h4>AI/ML</h4>
      <MlBlock ml={exp.ml} />
    </div>
  );
}
