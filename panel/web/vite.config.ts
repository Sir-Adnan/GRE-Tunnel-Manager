import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { defineConfig } from "vite";

const panelOrigin = "http://127.0.0.1:8790";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  build: {
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
  // Development only: forwards the API to `gtm-panel demo` and presents the request as same-origin there,
  // so the panel's Origin/CSRF checks pass without being relaxed.
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: panelOrigin,
        changeOrigin: true,
        configure: (proxy) =>
          proxy.on("proxyReq", (request) =>
            request.setHeader("origin", panelOrigin),
          ),
      },
    },
  },
});
