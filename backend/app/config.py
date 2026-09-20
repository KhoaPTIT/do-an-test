from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Cấu hình backend, đọc từ biến môi trường / file .env ở gốc repo.

    Chỉ `database_url` là bắt buộc cho Tuần 1. Các trường còn lại đã có
    placeholder để không phải sửa lại cấu trúc khi triển khai các tuần sau
    (Redis ở Tuần 3, GeoIP ở Tuần 3, JWT ở Tuần 5).
    """

    model_config = SettingsConfigDict(env_file="../.env", extra="ignore")

    app_env: str = "development"
    database_url: str = "postgresql+psycopg2://lad_user:lad_password@localhost:5432/lad_db"
    frontend_origin: str = "http://localhost:5173"

    # Tuần 3+
    redis_url: str = "redis://localhost:6379/0"
    geoip_db_path: str = "./geoip/GeoLite2-City.mmdb"
    geoip_asn_db_path: str = "./geoip/GeoLite2-ASN.mmdb"

    # Tuần 5+
    jwt_secret_key: str = "change-me-to-a-random-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Tuần 6 — CHỈ bật khi demo cục bộ để script impossible_travel.py giả
    # lập IP nguồn qua header X-Forwarded-For. TUYỆT ĐỐI KHÔNG bật nếu
    # backend expose ra internet không qua reverse proxy đáng tin cậy —
    # bật sai chỗ cho phép BẤT KỲ ai tự khai IP nguồn tuỳ ý, né được toàn
    # bộ rule theo IP (brute force theo IP, credential stuffing, GeoIP).
    trust_forwarded_for: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
