import { useState } from "react";

import { apiClient } from "../services/api";
import "./AuthForm.css";

// Form đăng nhập web app mẫu (nhiệm vụ 2.2). Gọi thật POST /login, xử lý
// cả 2 trường hợp thành công/thất bại theo docs/api-contract.md. Đây là
// "mục tiêu" bị giám sát — không có trang nào phía sau để điều hướng tới
// (khác /admin/login dẫn vào /dashboard), nên chỉ hiển thị trạng thái ngay
// tại chỗ thay vì chuyển trang.
//
// MR16 "phản ứng tự động (mô phỏng)": rủi ro trung bình -> POST /login trả
// step_up_required=true (vẫn HTTP 200 — mật khẩu ĐÃ đúng, chỉ chưa đủ) thay
// vì đăng nhập xong ngay -> chuyển sang bước nhập OTP. Rủi ro cao/nguồn đã bị
// khoá -> POST /login trả HTTP 423, xử lý qua nhánh lỗi sẵn có bên dưới (message
// từ backend đã đủ rõ, không cần phân nhánh riêng).
export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  // Bước OTP giả lập — chỉ có giá trị khi step_up_required=true.
  const [challenge, setChallenge] = useState(null); // { id, demoCode }
  const [otpCode, setOtpCode] = useState("");
  const [otpError, setOtpError] = useState(null);
  const [otpLoading, setOtpLoading] = useState(false);

  function resetToCredentials() {
    setChallenge(null);
    setOtpCode("");
    setOtpError(null);
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const response = await apiClient.post("/login", { username, password });
      if (response.data.step_up_required) {
        setChallenge({ id: response.data.challenge_id, demoCode: response.data.demo_otp_code });
      } else if (response.data.success) {
        setSuccess(true);
      } else {
        setError(response.data.message || "Đăng nhập thất bại.");
      }
    } catch (err) {
      if (err.response) {
        // Bao gồm cả trường hợp bị khoá tạm (HTTP 423, MR16) — message từ backend đã đủ rõ để hiện thẳng.
        setError(err.response.data?.message || "Đăng nhập thất bại.");
      } else {
        setError("Không kết nối được tới máy chủ. Kiểm tra backend đã chạy chưa.");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOtp(event) {
    event.preventDefault();
    setOtpLoading(true);
    setOtpError(null);

    try {
      const response = await apiClient.post("/login/verify-otp", { challenge_id: challenge.id, code: otpCode });
      if (response.data.success) {
        setChallenge(null);
        setSuccess(true);
      } else {
        setOtpError(response.data.message || "Mã xác thực không đúng hoặc đã hết hạn.");
        setOtpCode("");
      }
    } catch (err) {
      setOtpError(err.response?.data?.message || "Không kết nối được tới máy chủ.");
    } finally {
      setOtpLoading(false);
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-card">
        <h1>Đăng nhập</h1>

        {challenge ? (
          <form onSubmit={handleVerifyOtp}>
            <p className="auth-otp-banner">
              ⚠️ <strong>OTP giả lập (demo)</strong> — hệ thống thật sẽ gửi mã qua SMS/email, không bao giờ hiện trực
              tiếp như thế này. Mã demo: <strong>{challenge.demoCode}</strong>
            </p>
            <div className="auth-field">
              <label htmlFor="otp">Mã xác thực (6 số)</label>
              <input
                id="otp"
                name="otp"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={12}
                value={otpCode}
                onChange={(event) => setOtpCode(event.target.value)}
                autoFocus
                required
              />
            </div>

            {otpError && (
              <p className="auth-error" role="alert">
                {otpError}
              </p>
            )}

            <button type="submit" disabled={otpLoading}>
              {otpLoading ? "Đang xác thực..." : "Xác thực"}
            </button>
            <button type="button" className="auth-secondary" onClick={resetToCredentials}>
              Huỷ, đăng nhập lại
            </button>
          </form>
        ) : (
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
        )}

        <p className="auth-hint">Web app mẫu — mục tiêu được giám sát, không phải trang quản trị.</p>
      </div>
    </main>
  );
}
