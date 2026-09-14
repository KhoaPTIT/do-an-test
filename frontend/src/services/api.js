import axios from "axios";

// Địa chỉ backend — cấu hình qua biến môi trường VITE_API_BASE_URL (xem .env.example ở gốc repo).
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
});
