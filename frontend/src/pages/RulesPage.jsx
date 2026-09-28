import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./RulesPage.css";

const MODE_LABELS = { enforce: "Bật (tạo cảnh báo)", shadow: "Theo dõi (không tạo cảnh báo)", off: "Tắt" };

function paramInput(param, value, onChange) {
  if (param.kind === "bool") {
    return <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />;
  }
  if (param.kind === "list") {
    return (
      <input
        type="text"
        value={Array.isArray(value) ? value.join(", ") : value}
        onChange={(e) => onChange(e.target.value.split(",").map((s) => s.trim()).filter(Boolean))}
      />
    );
  }
  return (
    <input
      type={param.kind === "int" || param.kind === "float" ? "number" : "text"}
      step={param.kind === "float" ? "any" : undefined}
      value={value}
      onChange={(e) => {
        const raw = e.target.value;
        if (param.kind === "int") onChange(raw === "" ? "" : parseInt(raw, 10));
        else if (param.kind === "float") onChange(raw === "" ? "" : parseFloat(raw));
        else onChange(raw);
      }}
    />
  );
}

// MR17 "Dashboard v2" — checklist "chỉnh ngưỡng và bật/tắt rule từ giao diện admin". Trước MR17, luật SỐNG (POST
// /login thật) luôn chấm bằng MẶC ĐỊNH của sổ đăng ký — không có đường nào ghi đè. Giờ GET/PUT/DELETE /rules đọc/ghi
// bảng rule_overrides (DB), áp dụng gần như ngay lập tức (cache 15s ở backend).
export default function RulesPage() {
  const [rules, setRules] = useState(null);
  const [error, setError] = useState(null);
  const [drafts, setDrafts] = useState({}); // { [ruleId]: { mode, params: {name: value} } } — chỉnh CHƯA lưu
  const [savingId, setSavingId] = useState(null);
  const [message, setMessage] = useState(null);

  function load() {
    apiClient
      .get("/rules")
      .then((res) => {
        setRules(res.data);
        setDrafts(Object.fromEntries(res.data.map((r) => [r.id, { mode: r.mode, params: Object.fromEntries(r.params.map((p) => [p.name, p.value])) }])));
      })
      .catch(() => setError("Không tải được danh sách luật (cần đăng nhập quản trị)."));
  }

  useEffect(load, []);

  function updateDraft(ruleId, patch) {
    setDrafts((prev) => ({ ...prev, [ruleId]: { ...prev[ruleId], ...patch } }));
  }

  function save(rule) {
    setSavingId(rule.id);
    setMessage(null);
    const draft = drafts[rule.id];
    apiClient
      .put(`/rules/${rule.id}`, { mode: draft.mode, params: draft.params })
      .then(() => {
        setMessage({ kind: "success", text: `Đã lưu "${rule.title}".` });
        load();
      })
      .catch((err) => setMessage({ kind: "error", text: err.response?.data?.detail || "Lưu thất bại." }))
      .finally(() => setSavingId(null));
  }

  function reset(rule) {
    setSavingId(rule.id);
    setMessage(null);
    apiClient
      .delete(`/rules/${rule.id}`)
      .then(() => {
        setMessage({ kind: "success", text: `Đã khôi phục mặc định cho "${rule.title}".` });
        load();
      })
      .catch(() => setMessage({ kind: "error", text: "Khôi phục thất bại." }))
      .finally(() => setSavingId(null));
  }

  const grouped = rules
    ? rules.reduce((acc, r) => {
        (acc[r.category] ??= []).push(r);
        return acc;
      }, {})
    : null;

  return (
    <main className="rules-page">
      <h1>⚙️ Cấu hình luật</h1>
      <p className="rules-page__hint">
        Bật/tắt từng luật và chỉnh tham số áp dụng cho lần đăng nhập TIẾP THEO (không hồi tố log cũ) — thay đổi có hiệu lực trong tối đa 15 giây.
      </p>

      {message && <p className={`rules-page__message rules-page__message--${message.kind}`}>{message.text}</p>}
      {error && <p className="rules-page__placeholder">{error}</p>}
      {!error && rules === null && (
        <p className="rules-page__placeholder">
          <span className="spinner" />
          Đang tải...
        </p>
      )}

      {grouped &&
        Object.entries(grouped).map(([category, categoryRules]) => (
          <section key={category} className="rules-page__category">
            <h2>{category}</h2>
            {categoryRules.map((rule) => {
              const draft = drafts[rule.id] ?? { mode: rule.mode, params: {} };
              return (
                <article key={rule.id} className="rule-card">
                  <div className="rule-card__header">
                    <h3>{rule.title}</h3>
                    <span className={`rule-card__severity rule-card__severity--${rule.severity}`}>{rule.severity}</span>
                    {rule.is_overridden && <span className="rule-card__overridden-badge">đã tuỳ chỉnh</span>}
                  </div>
                  <p className="rule-card__description">{rule.description}</p>

                  <div className="rule-card__field">
                    <label>Chế độ</label>
                    <select value={draft.mode ?? rule.default_mode} onChange={(e) => updateDraft(rule.id, { mode: e.target.value })}>
                      {Object.entries(MODE_LABELS).map(([mode, label]) => (
                        <option key={mode} value={mode}>
                          {label}
                          {mode === rule.default_mode ? " (mặc định)" : ""}
                        </option>
                      ))}
                    </select>
                  </div>

                  {rule.params.length > 0 && (
                    <div className="rule-card__params">
                      {rule.params.map((p) => (
                        <div key={p.name} className="rule-card__field" title={p.description}>
                          <label>
                            {p.name}
                            {p.unit ? ` (${p.unit})` : ""}
                          </label>
                          {paramInput(p, draft.params[p.name] ?? p.value, (value) => updateDraft(rule.id, { params: { ...draft.params, [p.name]: value } }))}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="rule-card__actions">
                    <button type="button" disabled={savingId === rule.id} onClick={() => save(rule)}>
                      Lưu
                    </button>
                    {rule.is_overridden && (
                      <button type="button" className="rule-card__reset" disabled={savingId === rule.id} onClick={() => reset(rule)}>
                        ↩ Khôi phục mặc định
                      </button>
                    )}
                  </div>
                  {rule.updated_by && (
                    <p className="rule-card__meta">
                      Sửa lần cuối bởi {rule.updated_by} lúc {new Date(rule.updated_at).toLocaleString("vi-VN")}
                    </p>
                  )}
                </article>
              );
            })}
          </section>
        ))}
    </main>
  );
}
