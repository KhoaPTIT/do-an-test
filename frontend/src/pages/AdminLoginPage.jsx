import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { apiClient } from "../services/api";
import { setAdminToken } from "../services/auth";

// Đăng nhập quản trị (nhiệm vụ 5.1) — TÁCH BIỆT hoàn toàn khỏi form đăng
// nhập web app mẫu ở /login. Token JWT lưu localStorage, dùng cho mọi
// route quản trị + WebSocket.
export default function AdminLoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await apiClient.post("/admin/login", { username, password });
      setAdminToken(response.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      if (err.response) {
        setError(err.response.data?.detail || "Đăng nhập quản trị thất bại.");
      } else {
        setError("Không kết nối được tới máy chủ.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <h1>Đăng nhập quản trị</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="admin-username">Tên đăng nhập admin</label>
          <br />
          <input
            id="admin-username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
          />
        </div>
        <div>
          <label htmlFor="admin-password">Mật khẩu</label>
          <br />
          <input
            id="admin-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </div>

        {error && (
          <p role="alert" style={{ color: "crimson" }}>
            {error}
          </p>
        )}

        <button type="submit" disabled={loading}>
          {loading ? "Đang đăng nhập..." : "Đăng nhập"}
        </button>
      </form>
    </main>
  );
}
