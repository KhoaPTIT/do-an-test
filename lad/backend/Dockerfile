FROM python:3.12-slim

WORKDIR /app

# Cài thư viện trước, tách khỏi mã nguồn để tận dụng cache của Docker:
# sửa code không phải cài lại toàn bộ thư viện.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Chạy bằng tài khoản thường thay vì root. Nếu container bị chiếm quyền,
# kẻ tấn công không có sẵn quyền quản trị bên trong.
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
