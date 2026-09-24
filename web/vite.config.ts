import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the dashboard runs on Vite's dev server and proxies the API
// and the event stream to a local agent. In production the agent serves the
// built assets itself, so these relative paths resolve to the same origin.
const agent = process.env.AEGIS_AGENT ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1/stream": { target: agent, ws: true, changeOrigin: true },
      "/v1": { target: agent, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
