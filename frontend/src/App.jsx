import { Navigate, NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import "./App.css";
import CampaignDetailPage from "./pages/CampaignDetailPage";
import CampaignsPage from "./pages/CampaignsPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import ModelHealthPage from "./pages/ModelHealthPage";
import RulesPage from "./pages/RulesPage";
import UserProfilePage from "./pages/UserProfilePage";
import { clearAdminToken, getAdminToken } from "./services/auth";

// Route quản trị (nhiệm vụ 5.1) — chưa có token thì đá về trang đăng nhập chung /login.
// Không xác thực chữ ký JWT phía client (không cần thiết — backend luôn
// kiểm tra lại), chỉ chặn UI khi rõ ràng chưa đăng nhập.
function RequireAdmin({ children }) {
  const token = getAdminToken();
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function navLinkClass({ isActive }) {
  return isActive ? "active" : undefined;
}

// Trang đăng nhập chung (/login) dùng cho mọi tài khoản — backend tự phân quyền user/admin. Header riêng, tối giản,
// KHÔNG lẫn với nav quản trị (Dashboard/Luật/Mô hình...): nav quản trị chỉ hiện sau khi admin đã đăng nhập.
function SiteHeader() {
  return (
    <header className="site-header">
      <span className="site-header__brand">Anomaly Login Detection</span>
    </header>
  );
}

function AdminNav() {
  const navigate = useNavigate();

  function handleLogout() {
    clearAdminToken();
    navigate("/login", { replace: true });
  }

  return (
    <nav className="app-nav">
      <span className="app-nav__brand">🛡️ Anomaly Login Detection</span>
      <NavLink to="/dashboard" className={navLinkClass}>
        Dashboard
      </NavLink>
      <NavLink to="/dashboard/campaigns" className={navLinkClass}>
        Chiến dịch
      </NavLink>
      <NavLink to="/dashboard/rules" className={navLinkClass}>
        Luật
      </NavLink>
      <NavLink to="/dashboard/model-health" className={navLinkClass}>
        Mô hình
      </NavLink>
      <button type="button" className="app-nav__logout" onClick={handleLogout}>
        Đăng xuất
      </button>
    </nav>
  );
}

export default function App() {
  const { pathname } = useLocation();
  // Chưa vào khu quản trị (trang đăng nhập + các đường dẫn chỉ để chuyển hướng về đó) -> header tối giản.
  const isSiteRoute = ["/", "/login", "/admin/login"].includes(pathname);

  return (
    <div>
      {isSiteRoute ? <SiteHeader /> : <AdminNav />}
      <div className="app-main">
        <Routes>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<LoginPage />} />
          {/* Giữ đường dẫn cũ để bookmark/link cũ không bị gãy — nay dùng chung trang /login. */}
          <Route path="/admin/login" element={<Navigate to="/login" replace />} />
          <Route
            path="/dashboard"
            element={
              <RequireAdmin>
                <DashboardPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/dashboard/campaigns"
            element={
              <RequireAdmin>
                <CampaignsPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/dashboard/campaigns/:campaignId"
            element={
              <RequireAdmin>
                <CampaignDetailPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/dashboard/rules"
            element={
              <RequireAdmin>
                <RulesPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/dashboard/model-health"
            element={
              <RequireAdmin>
                <ModelHealthPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/dashboard/users/:userId"
            element={
              <RequireAdmin>
                <UserProfilePage />
              </RequireAdmin>
            }
          />
        </Routes>
      </div>
    </div>
  );
}
