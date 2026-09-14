import { MapContainer, TileLayer } from "react-leaflet";

// Khu vực bản đồ (nhiệm vụ 3.4) — chỉ hiển thị nền bản đồ, marker/đường nối
// cảnh báo impossible travel sẽ thêm ở Tuần 5 (nhiệm vụ 5.3).
export default function MapPanel() {
  return (
    <section className="dashboard-panel" aria-label="Bản đồ đăng nhập">
      <h2>Bản đồ</h2>
      <div className="dashboard-panel__body">
        <MapContainer center={[16.0, 106.0]} zoom={5} style={{ height: "100%", width: "100%" }}>
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
        </MapContainer>
      </div>
    </section>
  );
}
