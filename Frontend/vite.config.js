// vite.config.js
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5001', // backend port from app.py
        changeOrigin: true,
        secure: false
        // no rewrite needed because backend routes already start with /api
      }
    }
  }
});
