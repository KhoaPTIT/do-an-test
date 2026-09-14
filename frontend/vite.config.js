import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Dùng chung file .env ở gốc repo (cùng file mà docker-compose/backend đọc)
  // thay vì tạo .env riêng trong frontend/.
  envDir: '../',
})
