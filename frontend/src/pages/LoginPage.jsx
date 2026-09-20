import { useState } from "react";

import { apiClient } from "../services/api";
import "./AuthForm.css";

// Form đăng nhập web app mẫu (nhiệm vụ 2.2). Gọi thật POST /login, xử lý
// cả 2 trường hợp thành công/thất bại theo docs/api-contract.md. Đây là
// "mục tiêu" bị giám sát — không có trang nào phía sau để điều hướng tới
// (khác /admin/login dẫn vào /dashboard), nên chỉ hiển thị trạng thái ngay
// tại chỗ thay vì chuyển trang.
export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      await apiClient.post("/login", { username, password });
      setSuccess(true);
    } catch (err) {
      if (err.response) {
        setError(err.response.data?.message || "Đăng nhập thất bại.");
      } else {
        setError("Không kết nối được tới máy chủ. Kiểm tra backend đã chạy chưa.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-card">
        <h1>Đăng nhập</h1>
        <form onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="username">Tên đăng nhập</label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </div>
          <div className="auth-field">
            <label htmlFor="password">Mật khẩu</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>

          {error && (
            <p className="auth-error" role="alert">
              {error}
            </p>
          )}
          {success && <p className="auth-success">✅ Đăng nhập thành công.</p>}

          <button type="submit" disabled={loading}>
            {loading ? "Đang đăng nhập..." : "Đăng nhập"}
          </button>
        </form>
        <p className="auth-hint">Web app mẫu — mục tiêu được giám sát, không phải trang quản trị.</p>
      </div>
    </main>
  );
}
