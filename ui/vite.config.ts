import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite build; production typically serves ui/dist behind the platform reverse proxy.
export default defineConfig({
  plugins: [react()],
});
