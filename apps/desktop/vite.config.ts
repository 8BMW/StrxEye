import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// During development the UI talks to `strxeye serve` through this proxy.
// The proxy adds the API token from STRXEYE_API_TOKEN so the token never
// has to be embedded in the frontend bundle.
const apiPort = process.env.STRXEYE_API_PORT ?? "8765";
const token = process.env.STRXEYE_API_TOKEN ?? "";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: `http://127.0.0.1:${apiPort}`,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      },
    },
  },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900 },
  test: { environment: "jsdom", globals: false },
});
