import { useMemo } from "react";

import "./CampaignGraphView.css";

const SIZE = 480;
const CENTER = SIZE / 2;
const RADIUS = SIZE / 2 - 70;

const KIND_COLOR = {
  user: "var(--accent)",
  ip: "var(--warning)",
  asn: "var(--danger)",
  device: "var(--success)",
};

const KIND_ICON = { user: "👤", ip: "🌐", asn: "📡", device: "💻" };

// Đồ thị liên kết user–IP–ASN–thiết bị (MR14, checklist "Đồ thị liên kết ... để tìm hạ tầng dùng chung") — SVG tự vẽ,
// bố cục vòng tròn đơn giản (không dùng thư viện mô phỏng vật lý — số node của MỘT chiến dịch trên hệ thống demo nhỏ,
// vòng tròn đọc được ngay, không cần d3-force/cytoscape chỉ để vẽ vài chục node).
export default function CampaignGraphView({ graph }) {
  const positions = useMemo(() => {
    const map = {};
    const n = graph.nodes.length;
    graph.nodes.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
      map[node.id] = { x: CENTER + RADIUS * Math.cos(angle), y: CENTER + RADIUS * Math.sin(angle) };
    });
    return map;
  }, [graph.nodes]);

  if (graph.nodes.length === 0) {
    return <p className="campaign-graph__placeholder">Chưa có đủ dữ liệu để vẽ đồ thị liên kết.</p>;
  }

  return (
    <svg className="campaign-graph" viewBox={`0 0 ${SIZE} ${SIZE}`} role="img" aria-label="Đồ thị liên kết user, IP, ASN, thiết bị của chiến dịch">
      {graph.edges.map((edge) => {
        const a = positions[edge.source];
        const b = positions[edge.target];
        if (!a || !b) return null;
        return <line key={`${edge.source}->${edge.target}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="campaign-graph__edge" />;
      })}
      {graph.nodes.map((node) => {
        const p = positions[node.id];
        return (
          <g key={node.id} transform={`translate(${p.x}, ${p.y})`}>
            <circle r={22} fill={KIND_COLOR[node.kind] ?? "var(--text-muted)"} className="campaign-graph__node" />
            <text textAnchor="middle" dy="0.35em" className="campaign-graph__node-icon">
              {KIND_ICON[node.kind] ?? "•"}
            </text>
            <text textAnchor="middle" dy="2.6em" className="campaign-graph__node-label">
              {node.label.length > 16 ? `${node.label.slice(0, 15)}…` : node.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
