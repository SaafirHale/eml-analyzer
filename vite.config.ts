import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "demo",
  base: "./",
  plugins: [react()],
  server: { port: 5178, strictPort: true, fs: { allow: [".."] } },
  build: { outDir: "../dist-demo", emptyOutDir: true },
});
