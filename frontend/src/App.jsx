import { Navigate, NavLink, Route, Routes } from "react-router-dom";

import "./App.css";
import AdminLoginPage from "./pages/AdminLoginPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
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

export default function App() {
  return (
    <div>
      <nav>
        <NavLink to="/login">Login</NavLink> | <NavLink to="/admin/login">Admin</NavLink> |{" "}
        <NavLink to="/dashboard">Dashboard</NavLink>
      </nav>
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
      </Routes>
    </div>
  );
}
