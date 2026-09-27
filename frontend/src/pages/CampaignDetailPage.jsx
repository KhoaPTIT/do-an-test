import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import CampaignGraphView from "../components/CampaignGraphView";
import { apiClient } from "../services/api";
import "./CampaignsPage.css";

// Chi tiết một chiến dịch (MR14): số tài khoản bị nhắm, timeline, trạng thái, đồ thị liên kết user-IP-ASN-thiết bị.
export default function CampaignDetailPage() {
  const { campaignId } = useParams();
  const [campaign, setCampaign] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setCampaign(null);
    setError(null);
    apiClient
      .get(`/campaigns/${campaignId}`)
      .then((res) => {
        if (!cancelled) setCampaign(res.data);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được chiến dịch (có thể không tồn tại).");
      });
    return () => {
      cancelled = true;
    };
  }, [campaignId]);

  if (error) {
    return (
      <main className="campaigns-page">
        <Link to="/dashboard/campaigns">← Danh sách chiến dịch</Link>
        <p className="campaigns-page__placeholder">{error}</p>
      </main>
    );
  }

  if (campaign === null) {
    return (
      <main className="campaigns-page">
        <p className="campaigns-page__placeholder">
          <span className="spinner" />
          Đang tải...
        </p>
      </main>
    );
  }

  return (
    <main className="campaigns-page">
      <Link to="/dashboard/campaigns">← Danh sách chiến dịch</Link>
      <h1>🕸️ {campaign.label}</h1>
      <div className="campaign-detail__summary">
        <span>
          Họ tấn công gợi ý: <strong>{campaign.attack_family ?? "—"}</strong>
        </span>
        <span>
          Trạng thái: <span className={`campaigns-status campaigns-status--${campaign.status}`}>{campaign.status === "open" ? "Đang mở" : "Đã đóng"}</span>
        </span>
        <span>
          {campaign.targeted_accounts} tài khoản bị nhắm · {campaign.alert_count} cảnh báo
        </span>
        <span>
          {new Date(campaign.first_seen_at).toLocaleString("vi-VN")} → {new Date(campaign.last_seen_at).toLocaleString("vi-VN")}
        </span>
      </div>

      <div className="campaign-detail__grid">
        <section className="campaign-detail__panel">
          <h2>Dòng thời gian</h2>
          <ul className="campaign-timeline">
            {campaign.timeline.map((item) => (
              <li key={item.alert_id} className={`campaign-timeline__item campaign-timeline__item--${item.severity}`}>
                <strong>{item.username ?? `? ${item.alert_type}`}</strong> — {item.message}
                <br />
                <small>
                  {new Date(item.created_at).toLocaleString("vi-VN")} · {item.risk_score}đ
                </small>
              </li>
            ))}
          </ul>
        </section>

        <section className="campaign-detail__panel">
          <h2>Tài khoản bị nhắm</h2>
          <ul className="campaign-accounts">
            {campaign.targeted_usernames.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </section>

        <section className="campaign-detail__panel campaign-detail__panel--graph">
          <h2>Đồ thị liên kết hạ tầng</h2>
          <CampaignGraphView graph={campaign.graph} />
        </section>
      </div>
    </main>
  );
}
