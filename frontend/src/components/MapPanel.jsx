import L from "leaflet";
import markerIcon2x from "leaflet/dist/images/marker-icon-2x.png";
import markerIcon from "leaflet/dist/images/marker-icon.png";
import markerShadow from "leaflet/dist/images/marker-shadow.png";
import { useEffect, useState } from "react";
import { MapContainer, Marker, Polyline, TileLayer } from "react-leaflet";

// Fix icon marker mặc định của Leaflet bị vỡ khi bundler (Vite) không tự
// resolve đúng đường dẫn ảnh — lỗi rất phổ biến với react-leaflet.
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

// Khu vực bản đồ (nhiệm vụ 3.4) — vẽ điểm + đường nối khi nhận cảnh báo
// impossible_travel qua WebSocket real-time (nhiệm vụ 5.3).
export default function MapPanel({ latestAlert }) {
  const [travelLine, setTravelLine] = useState(null);

  useEffect(() => {
    if (!latestAlert || latestAlert.alert_type !== "impossible_travel") return;
    const { previous_latitude, previous_longitude, latitude, longitude } = latestAlert;
    if (previous_latitude == null || previous_longitude == null || latitude == null || longitude == null) return;

    setTravelLine({
      from: [previous_latitude, previous_longitude],
      to: [latitude, longitude],
    });
  }, [latestAlert]);

  return (
    <section className="dashboard-panel" aria-label="Bản đồ đăng nhập">
      <h2>Bản đồ</h2>
      <div className="dashboard-panel__body">
        <MapContainer center={[16.0, 106.0]} zoom={5} style={{ height: "100%", width: "100%" }}>
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          {travelLine && (
            <>
              <Marker position={travelLine.from} />
              <Marker position={travelLine.to} />
              <Polyline positions={[travelLine.from, travelLine.to]} pathOptions={{ color: "red" }} />
            </>
          )}
        </MapContainer>
      </div>
    </section>
  );
}
