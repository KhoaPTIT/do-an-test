// Lưu JWT admin ở localStorage — riêng cho từng trình duyệt, không đồng bộ
// giữa các máy/tab khác domain. Bọc try/catch vì localStorage có thể bị
// chặn (private mode nghiêm ngặt, một số trình duyệt di động).
const TOKEN_KEY = "lad_admin_token";

export function getAdminToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setAdminToken(token) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // bỏ qua — không có nơi lưu thì phiên chỉ tồn tại trong bộ nhớ tab hiện tại
  }
}

export function clearAdminToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    // ignore
  }
}
