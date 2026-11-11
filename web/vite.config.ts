import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The console is a static SPA. It is built straight into the Python package so the
// API can serve it with no Node at runtime. `base: "./"` keeps asset URLs relative,
// so it works from the API root or any sub-path.
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../uniphish/server/static", // resolved against this directory (web/)
    emptyOutDir: true,
    sourcemap: false,
    target: "es2022",
  },
  server: {
    port: 5173,
    // `npm run dev` proxies the API so the console can be developed against a local server.
    proxy: { "/v1": "http://127.0.0.1:8080" },
  },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
