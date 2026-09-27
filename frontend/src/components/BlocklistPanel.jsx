import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./BlocklistPanel.css";

const PAGE_SIZE = 20;
const KIND_LABELS = { ip: "IP", cidr: "Dải CIDR", asn: "ASN", username: "Tài khoản" };

function formatExpiry(expiresAt) {
  if (!expiresAt) return "Vĩnh viễn";
  return new Date(expiresAt).toLocaleString("vi-VN");
}

// MR16 "phản ứng tự động (mô phỏng)" — "admin có nút mở khoá": danh sách khoá tạm/chặn đang hiệu lực (tự động khi
// hybrid risk engine đề xuất lock, HOẶC thủ công từ MR9) + nút gỡ trước hạn (DELETE /blocklist/{id}).
export default function BlocklistPanel() {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState(null);
  const [removingId, setRemovingId] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get("/blocklist", { params: { page: 1, page_size: PAGE_SIZE, active_only: true } })
      .then((res) => {
        if (!cancelled) setEntries(res.data.items);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được danh sách khoá (cần đăng nhập quản trị).");
      });
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  function unlock(entryId) {
    setRemovingId(entryId);
    apiClient
      .delete(`/blocklist/${entryId}`)
      .then(() => {
        setEntries((prev) => (prev ?? []).filter((e) => e.id !== entryId));
      })
      .catch(() => {
        setError("Không mở khoá được, thử lại sau.");
      })
      .finally(() => setRemovingId(null));
  }

  return (
    <section className="dashboard-panel blocklist-panel" aria-label="Khoá tạm / chặn">
      <h2>
        Khoá tạm &amp; chặn (MR16)
        <button type="button" className="blocklist-panel__refresh" onClick={() => setReloadKey((k) => k + 1)} title="Làm mới">
          🔄
        </button>
      </h2>
      <div className="dashboard-panel__body">
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && entries === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {!error && entries !== null && entries.length === 0 && (
          <p className="dashboard-panel__placeholder">Không có khoá/chặn nào đang hiệu lực.</p>
        )}
        {!error && entries !== null && entries.length > 0 && (
          <table className="blocklist-panel__table">
            <thead>
              <tr>
                <th>Loại</th>
                <th>Giá trị</th>
                <th>Lý do</th>
                <th>Hết hạn</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id}>
                  <td>{KIND_LABELS[entry.kind] ?? entry.kind}</td>
                  <td className="blocklist-panel__value">{entry.value}</td>
                  <td className="blocklist-panel__reason" title={entry.reason ?? ""}>
                    {entry.reason ?? "—"} <span className="blocklist-panel__added-by">({entry.added_by})</span>
                  </td>
                  <td>{formatExpiry(entry.expires_at)}</td>
                  <td>
                    <button type="button" disabled={removingId === entry.id} onClick={() => unlock(entry.id)}>
                      🔓 Mở khoá
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
