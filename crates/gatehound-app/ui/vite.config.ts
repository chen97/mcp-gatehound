import { defineConfig } from "vite";

// Tauri serves the built files from ui/dist; nothing is fetched from the network at runtime.
export default defineConfig({
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { target: "es2021", outDir: "dist", emptyOutDir: true },
});
