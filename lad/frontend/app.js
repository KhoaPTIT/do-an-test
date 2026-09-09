"use strict";

const API = "";                 // cùng gốc với backend
const POLL_MS = 8000;           // nhịp tự động tải lại

const $ = (id) => document.getElementById(id);
let charts = {};
let currentAlertId = null;

function apiKey() { return $("api-key").value.trim(); }

async function call(path, options = {}) {
  const res = await fetch(API + path, {
    ...options,
    headers: {
      "X-API-Key": apiKey(),
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (res.status === 401) throw new Error("API key không hợp lệ. Kiểm tra lại ô API key ở góc phải.");
  if (res.status === 429) throw new Error("Gọi API quá nhanh. Chờ một phút rồi thử lại.");
  if (!res.ok) throw new Error(`Máy chủ trả về lỗi ${res.status}`);
  return res.json();
}

function showBanner(msg) {
  const b = $("banner");
  if (!msg) { b.hidden = true; return; }
  b.textContent = msg;
  b.hidden = false;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("vi-VN", { day: "2-digit", month: "2-digit",
    hour: "2-digit", minute: "2-digit" });
}

const SEVERITY_VI = { critical: "Nghiêm trọng", high: "Cao", medium: "Trung bình", low: "Thấp" };
const STATUS_VI = { open: "Đang mở", investigating: "Đang điều tra",
                    resolved: "Đã xử lý", false_positive: "Báo động giả" };
const DECISION_VI = { allow: "Cho qua", challenge: "Bắt xác thực 2 lớp", block: "Chặn" };

function scoreClass(s) { return s >= 70 ? "high" : s >= 40 ? "mid" : ""; }

// --- Tải số liệu tổng quan ---
async function loadOverview() {
  const d = await call("/api/v1/stats/overview");
  $("m-events").textContent = d.events_24h.toLocaleString("vi-VN");
  $("m-blocked").textContent = d.blocked_24h.toLocaleString("vi-VN");
  $("m-challenge").textContent = d.challenged_24h.toLocaleString("vi-VN");
  $("m-open").textContent = d.open_alerts.toLocaleString("vi-VN");
  $("m-risk").textContent = d.avg_risk_24h.toFixed(1);
  $("m-model").textContent = d.model.loaded
    ? "Đã nạp, chạy chế độ lai"
    : "Chưa có, chỉ dùng luật";
}

// --- Biểu đồ ---
const CHART_BASE = {
  responsive: true,
  plugins: { legend: { labels: { color: "#93a1b0", boxWidth: 12, font: { size: 12 } } } },
  scales: {
    x: { ticks: { color: "#93a1b0", font: { size: 11 } }, grid: { color: "#2c3540" } },
    y: { ticks: { color: "#93a1b0", font: { size: 11 } }, grid: { color: "#2c3540" }, beginAtZero: true },
  },
};

async function loadTimeline() {
  const rows = await call("/api/v1/stats/timeline?days=14");
  const labels = rows.map(r => r.date.slice(5));
  const data = {
    labels,
    datasets: [
      { label: "Tổng sự kiện", data: rows.map(r => r.total),
        borderColor: "#4c9aff", backgroundColor: "transparent", tension: 0.3, pointRadius: 2 },
      { label: "Bắt xác thực 2 lớp", data: rows.map(r => r.challenge),
        borderColor: "#f0a742", backgroundColor: "transparent", tension: 0.3, pointRadius: 2 },
      { label: "Bị chặn", data: rows.map(r => r.block),
        borderColor: "#ff6b6b", backgroundColor: "transparent", tension: 0.3, pointRadius: 2 },
    ],
  };
  if (charts.timeline) { charts.timeline.data = data; charts.timeline.update(); }
  else charts.timeline = new Chart($("chart-timeline"), { type: "line", data, options: CHART_BASE });
}

async function loadRuleChart() {
  const rows = (await call("/api/v1/stats/rule-frequency")).slice(0, 8);
  const data = {
    labels: rows.map(r => r.code),
    datasets: [{ label: "Số lần kích hoạt", data: rows.map(r => r.count),
                 backgroundColor: "#4c9aff" }],
  };
  const options = {
    ...CHART_BASE,
    plugins: {
      legend: { display: false },
      tooltip: { callbacks: { title: (items) => rows[items[0].dataIndex].name,
        afterLabel: (item) => `Báo động giả: ${rows[item.dataIndex].fp_rate}%` } },
    },
  };
  if (charts.rules) { charts.rules.data = data; charts.rules.update(); }
  else charts.rules = new Chart($("chart-rules"), { type: "bar", data, options });
}

// --- Danh sách cảnh báo ---
async function loadAlerts() {
  const status = $("f-status").value;
  const severity = $("f-severity").value;
  const q = new URLSearchParams({ limit: "60" });
  if (status) q.set("status", status);
  if (severity) q.set("severity", severity);

  const rows = await call("/api/v1/alerts?" + q);
  const tbody = $("alerts-body");

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">Không có cảnh báo nào khớp bộ lọc. Đổi bộ lọc hoặc chạy script mô phỏng tấn công để tạo dữ liệu.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(a => `
    <tr tabindex="0" data-id="${a.id}">
      <td class="mono">${fmtTime(a.timestamp || a.created_at)}</td>
      <td>${a.username || "—"}</td>
      <td class="mono">${a.ip_address || "—"}</td>
      <td>${[a.city, a.country].filter(Boolean).join(", ") || "—"}</td>
      <td class="score ${scoreClass(a.risk_score || 0)}">${(a.risk_score ?? 0).toFixed(0)}</td>
      <td><span class="tag tag-${a.severity}">${SEVERITY_VI[a.severity] || a.severity}</span></td>
      <td><span class="tag tag-${a.status}">${STATUS_VI[a.status] || a.status}</span></td>
    </tr>`).join("");

  tbody.querySelectorAll("tr[data-id]").forEach(tr => {
    const open = () => openDrawer(Number(tr.dataset.id));
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", e => { if (e.key === "Enter") open(); });
  });
}

// --- Ngăn chi tiết ---
async function openDrawer(id) {
  currentAlertId = id;
  $("drawer").hidden = false;
  $("scrim").hidden = false;
  $("d-body").innerHTML = `<p style="color:var(--text-dim)">Đang tải…</p>`;

  const a = await call(`/api/v1/alerts/${id}`);
  $("d-title").textContent = a.title;

  const hits = (a.rule_hits || []).map(h => `
    <div class="rule-hit">
      <span class="pts">+${h.score}</span>
      <strong>${h.code} · ${h.name}</strong>
      <p>${h.detail}</p>
    </div>`).join("") ||
    `<p style="color:var(--text-dim);font-size:13px">Không có luật nào kích hoạt. Cảnh báo này do mô hình học máy sinh ra dựa trên độ lệch hành vi tổng thể.</p>`;

  $("d-body").innerHTML = `
    <dl class="kv">
      <dt>Tài khoản</dt><dd>${a.username || "—"}</dd>
      <dt>Thời gian</dt><dd>${fmtTime(a.timestamp)}</dd>
      <dt>Địa chỉ IP</dt><dd class="mono">${a.ip_address || "—"}</dd>
      <dt>Vị trí</dt><dd>${[a.city, a.country].filter(Boolean).join(", ") || "—"}</dd>
      <dt>Điểm rủi ro</dt><dd class="score ${scoreClass(a.risk_score || 0)}">${(a.risk_score ?? 0).toFixed(1)} / 100</dd>
      <dt>Quyết định</dt><dd>${DECISION_VI[a.decision] || a.decision || "—"}</dd>
      <dt>Trạng thái</dt><dd><span class="tag tag-${a.status}">${STATUS_VI[a.status]}</span></dd>
    </dl>

    <h3>Luật đã kích hoạt</h3>
    ${hits}

    <h3>Xử lý cảnh báo</h3>
    <textarea id="d-note" class="note-input" rows="2" placeholder="Ghi chú của người xử lý">${a.analyst_note || ""}</textarea>
    <div class="actions">
      <button class="btn btn-primary" data-act="resolved">Xác nhận là tấn công</button>
      <button class="btn" data-act="false_positive">Đánh dấu báo động giả</button>
      <button class="btn" data-act="investigating">Đang điều tra</button>
      <button class="btn btn-danger" data-act="block-ip">Chặn IP này</button>
    </div>

    <h3>Lịch sử đăng nhập gần đây của tài khoản</h3>
    <div id="d-history"><p style="color:var(--text-dim);font-size:13px">Đang tải…</p></div>
  `;

  $("d-body").querySelectorAll("button[data-act]").forEach(btn => {
    btn.addEventListener("click", () => handleAction(btn.dataset.act, a));
  });

  loadHistory(a.username);
}

async function loadHistory(username) {
  if (!username) return;
  const rows = await call(`/api/v1/users/${encodeURIComponent(username)}/history?limit=12`);
  $("d-history").innerHTML = rows.map(e => `
    <div class="history-row">
      <span>${fmtTime(e.timestamp)}</span>
      <span>${[e.city, e.country].filter(Boolean).join(", ") || "—"}</span>
      <span class="score ${scoreClass(e.risk_score || 0)}">${(e.risk_score ?? 0).toFixed(0)}</span>
    </div>`).join("") || `<p style="color:var(--text-dim);font-size:13px">Chưa có lịch sử.</p>`;
}

async function handleAction(act, alert) {
  try {
    if (act === "block-ip") {
      await call("/api/v1/blocked-ips", {
        method: "POST",
        body: JSON.stringify({ ip_address: alert.ip_address,
                               reason: `Chặn từ cảnh báo #${alert.id}` }),
      });
      showBanner(`Đã chặn ${alert.ip_address}. Các lần đăng nhập sau từ IP này sẽ bị từ chối.`);
      setTimeout(() => showBanner(null), 5000);
      return;
    }
    await call(`/api/v1/alerts/${alert.id}`, {
      method: "PATCH",
      body: JSON.stringify({ status: act, analyst_note: $("d-note").value }),
    });
    closeDrawer();
    await refreshAll();
  } catch (e) {
    showBanner(e.message);
  }
}

function closeDrawer() {
  $("drawer").hidden = true;
  $("scrim").hidden = true;
  currentAlertId = null;
}

// --- Vòng đời ---
async function refreshAll() {
  try {
    await Promise.all([loadOverview(), loadTimeline(), loadRuleChart(), loadAlerts()]);
    showBanner(null);
    $("live-dot").classList.remove("stale");
  } catch (e) {
    showBanner(e.message);
    $("live-dot").classList.add("stale");
  }
}

$("refresh").addEventListener("click", refreshAll);
$("f-status").addEventListener("change", loadAlerts);
$("f-severity").addEventListener("change", loadAlerts);
$("d-close").addEventListener("click", closeDrawer);
$("scrim").addEventListener("click", closeDrawer);
$("api-key").addEventListener("change", refreshAll);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

refreshAll();
setInterval(() => { if (!currentAlertId) refreshAll(); }, POLL_MS);
