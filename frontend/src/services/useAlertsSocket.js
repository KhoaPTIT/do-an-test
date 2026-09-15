import { useEffect, useRef, useState } from "react";

import { getAdminToken } from "./auth";

const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL || "ws://localhost:8000";
const RECONNECT_DELAY_MS = 3000;

// WebSocket client cho /ws/alerts (nhiệm vụ 5.3) — tự reconnect khi mất
// kết nối mạng, xác thực bằng JWT admin qua query param.
export function useAlertsSocket(onAlert) {
  const [connected, setConnected] = useState(false);
  const onAlertRef = useRef(onAlert);
  onAlertRef.current = onAlert;

  useEffect(() => {
    let stopped = false;
    let socket = null;
    let reconnectTimer = null;

    function connect() {
      const token = getAdminToken();
      if (!token) return;

      socket = new WebSocket(`${WS_BASE_URL}/ws/alerts?token=${encodeURIComponent(token)}`);

      socket.onopen = () => setConnected(true);

      socket.onclose = () => {
        setConnected(false);
        if (!stopped) {
          reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS);
        }
      };

      socket.onerror = () => {
        socket?.close();
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "alert") {
            onAlertRef.current?.(payload.data);
          }
        } catch {
          // bỏ qua message không phải JSON hợp lệ
        }
      };
    }

    connect();

    return () => {
      stopped = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);

  return connected;
}
