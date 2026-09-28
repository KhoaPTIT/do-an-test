import { Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";

import "./App.css";
import AdminLoginPage from "./pages/AdminLoginPage";
import CampaignDetailPage from "./pages/CampaignDetailPage";
import CampaignsPage from "./pages/CampaignsPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import ModelHealthPage from "./pages/ModelHealthPage";
import RulesPage from "./pages/RulesPage";
import UserProfilePage from "./pages/UserProfilePage";
import { getAdminToken } from "./services/auth";

// Route quản trị (nhiệm vụ 5.1) — chưa có token thì đá về /admin/login.
// Không xác thực chữ ký JWT phía client (không cần thiết — backend luôn
// kiểm tra lại), chỉ chặn UI khi rõ ràng chưa đăng nhập.
function RequireAdmin({ children }) {
  const token = getAdminToken();
  if (!token) {
    return <Navigate to="/admin/login" replace />;
  }
  return children;
}

function navLinkClass({ isActive }) {
  return isActive ? "active" : undefined;
}

// Web app mẫu (nhiệm vụ 2.2) là MỤC TIÊU bị giám sát — người dùng cuối thật sự sẽ gặp trang này, không phải nhân
// viên quản trị. Header riêng, tối giản, KHÔNG lẫn với nav quản trị (Dashboard/Luật/Mô hình...) — giống một site
// thật: trang đăng nhập khách hàng không bao giờ trưng bảng điều hướng của công cụ giám sát nội bộ ra ngoài, chỉ có
// một lối nhỏ, kín đáo để nhân viên vào khu vực quản trị.
function SiteHeader() {
  return (
    <header className="site-header">
      <span className="site-header__brand">Anomaly Login Detection</span>
      <NavLink to="/admin/login" className="site-header__admin-link">
        Khu vực quản trị
      </NavLink>
    </header>
  );
}

function AdminNav() {
  return (
    <nav className="app-nav">
      <span className="app-nav__brand">🛡️ Anomaly Login Detection</span>
      <NavLink to="/admin/login" className={navLinkClass}>
        Đăng nhập quản trị
      </NavLink>
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
    </nav>
  );
}

export default function App() {
  const { pathname } = useLocation();
  const isSiteRoute = pathname === "/login";

  return (
    <div>
      {isSiteRoute ? <SiteHeader /> : <AdminNav />}
      <div className="app-main">
        <Routes>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/admin/login" element={<AdminLoginPage />} />
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
