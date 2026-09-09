"""Cấu hình toàn hệ thống, đọc từ biến môi trường."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Mặc định dùng SQLite để chạy được ngay, không cần cài Postgres.
# Khi bảo vệ, đổi sang Postgres bằng cách đặt biến môi trường DATABASE_URL:
#   postgresql+psycopg2://lad:lad_password@localhost:5432/login_anomaly
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'lad.db'}")

# Khóa truy cập API. Trong môi trường thật phải sinh ngẫu nhiên và giữ bí mật.
API_KEY = os.getenv("LAD_API_KEY", "demo-api-key-doi-truoc-khi-nop")

# Đường dẫn mô hình đã huấn luyện
MODEL_PATH = BASE_DIR / "ml" / "models" / "detector.pkl"

# --- Tham số chấm điểm rủi ro ---
RULE_WEIGHT = float(os.getenv("RULE_WEIGHT", 0.6))
ML_WEIGHT = float(os.getenv("ML_WEIGHT", 0.4))

THRESHOLD_CHALLENGE = float(os.getenv("THRESHOLD_CHALLENGE", 40))
THRESHOLD_BLOCK = float(os.getenv("THRESHOLD_BLOCK", 70))

# Số lần đăng nhập thành công tối thiểu để mô hình ML được tin dùng.
# Dưới ngưỡng này coi là cold start, hệ thống chỉ dựa vào rule.
ML_MIN_HISTORY = int(os.getenv("ML_MIN_HISTORY", 5))

# Số ngày lịch sử dùng để xây dựng bối cảnh cho mỗi lần chấm điểm
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", 90))

# Giới hạn tần suất gọi API cho mỗi khóa (số request mỗi phút)
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", 600))
