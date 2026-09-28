import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { apiClient } from "../services/api";
import "./UserProfilePage.css";

// MR17 "Dashboard v2" — checklist "hồ sơ rủi ro theo user (timeline, alert, thiết bị/quốc gia quen)". Gộp dữ liệu đã
// có sẵn rải rác (login_events, alerts, known_devices, known_locations, user_risk_profiles) thành MỘT trang xem nhanh
// cho admin — GET /users/{id}/profile (không phân trang, giới hạn cứng số dòng gần nhất, xem docstring router).
export default function UserProfilePage() {
  const { userId } = useParams();
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setProfile(null);
    setError(null);
    apiClient
      .get(`/users/${userId}/profile`)
      .then((res) => setProfile(res.data))
      .catch((err) => setError(err.response?.status === 404 ? "Không thấy tài khoản." : "Không tải được hồ sơ (cần đăng nhập quản trị)."));
  }, [userId]);

  if (error) return <main className="user-profile-page"><p className="user-profile-page__placeholder">{error}</p></main>;
  if (profile === null) {
    return (
      <main className="user-profile-page">
        <p className="user-profile-page__placeholder">
          <span className="spinner" />
          Đang tải...
        </p>
      </main>
    );
  }

  return (
    <main className="user-profile-page">
      <h1>👤 {profile.username}</h1>
      <p className="user-profile-page__hint">
        Tài khoản từ {new Date(profile.created_at).toLocaleDateString("vi-VN")} — mức độ quan trọng {profile.importance}
      </p>

      <section className="user-profile-panel">
        <h2>Ngưỡng rủi ro</h2>
        {profile.risk_profile ? (
          <p>
            Nới lỏng <strong>+{profile.risk_profile.threshold_delta}</strong> điểm so với ngưỡng nhóm — từ {profile.risk_profile.feedback_count} phản hồi
            (trong đó {profile.risk_profile.false_positive_count} báo nhầm).
          </p>
        ) : (
          <p className="user-profile-page__muted">Chưa đủ phản hồi — đang dùng ngưỡng NHÓM (mặc định toàn hệ thống).</p>
        )}
      </section>

      <div className="user-profile-grid">
        <section className="user-profile-panel">
          <h2>Thiết bị quen ({profile.known_devices.length})</h2>
          {profile.known_devices.length === 0 ? (
            <p className="user-profile-page__muted">Chưa có thiết bị nào được ghi nhận.</p>
          ) : (
            <ul className="user-profile-list">
              {profile.known_devices.map((d) => (
                <li key={d.device_fingerprint}>
                  <span className="user-profile-list__title">{d.user_agent ?? d.device_fingerprint}</span>
                  <span className="user-profile-list__meta">
                    Thấy lần đầu {new Date(d.first_seen_at).toLocaleDateString("vi-VN")} — gần nhất {new Date(d.last_seen_at).toLocaleDateString("vi-VN")}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="user-profile-panel">
          <h2>Quốc gia quen ({profile.known_locations.length})</h2>
          {profile.known_locations.length === 0 ? (
            <p className="user-profile-page__muted">Chưa có vị trí nào được ghi nhận.</p>
          ) : (
            <ul className="user-profile-list">
              {profile.known_locations.map((l) => (
                <li key={`${l.country}-${l.city}`}>
                  <span className="user-profile-list__title">{l.city ? `${l.city}, ${l.country}` : l.country ?? "Không rõ"}</span>
                  <span className="user-profile-list__meta">
                    Thấy lần đầu {new Date(l.first_seen_at).toLocaleDateString("vi-VN")} — gần nhất {new Date(l.last_seen_at).toLocaleDateString("vi-VN")}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="user-profile-panel">
        <h2>Cảnh báo gần đây ({profile.alerts.length})</h2>
        {profile.alerts.length === 0 ? (
          <p className="user-profile-page__muted">Chưa có cảnh báo nào.</p>
        ) : (
          <ul className="user-profile-list">
            {profile.alerts.map((a) => (
              <li key={a.id} className={`user-profile-list--severity-${a.severity}`}>
                <span className="user-profile-list__title">
                  {a.alert_type} ({a.severity}, {a.risk_score}đ)
                </span>
                <span className="user-profile-list__meta">{a.message}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="user-profile-panel">
        <h2>Lịch sử đăng nhập ({profile.timeline.length})</h2>
        {profile.timeline.length === 0 ? (
          <p className="user-profile-page__muted">Chưa có lần đăng nhập nào.</p>
        ) : (
          <table className="user-profile-table">
            <thead>
              <tr>
                <th>Thời gian</th>
                <th>Kết quả</th>
                <th>Risk</th>
                <th>Vị trí</th>
                <th>Thiết bị</th>
              </tr>
            </thead>
            <tbody>
              {profile.timeline.map((e) => (
                <tr key={e.id}>
                  <td>{new Date(e.created_at).toLocaleString("vi-VN")}</td>
                  <td>{e.success ? "✅" : "❌"}</td>
                  <td>{e.hybrid_risk_score ?? e.risk_score ?? "-"}</td>
                  <td>{e.city ? `${e.city}, ${e.country}` : e.country ?? "-"}</td>
                  <td>{e.device_type ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
