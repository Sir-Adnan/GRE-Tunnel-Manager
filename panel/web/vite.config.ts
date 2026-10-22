import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  build: {
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
  server: { host: "127.0.0.1", proxy: { "/api": "http://127.0.0.1:8790" } },
});
