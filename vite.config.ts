/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig(({ command }) => ({
  // GitHub Pages serves a project site from /<repo-name>/, so a built bundle
  // must request its assets from there rather than the domain root. The dev
  // server stays at "/" so local testing is unaffected. Set BASE_PATH=/ when
  // hosting at a root domain instead.
  base: command === "build" ? (process.env.BASE_PATH ?? "/job-scam-checker/") : "/",
  plugins: [react()],
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
  },
}));
