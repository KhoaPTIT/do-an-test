import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { apiClient } from "../services/api";

// Form đăng nhập web app mẫu (nhiệm vụ 2.2). Gọi thật POST /login,
// xử lý cả 2 trường hợp thành công/thất bại theo docs/api-contract.md.
export default function LoginPage() {
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
      await apiClient.post("/login", { username, password });
      navigate("/dashboard");
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
    <main>
      <h1>Đăng nhập</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="username">Tên đăng nhập</label>
          <br />
          <input
            id="username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
          />
        </div>
        <div>
          <label htmlFor="password">Mật khẩu</label>
          <br />
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
