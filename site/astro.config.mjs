import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://emdashcyber.com",
  base: "/dmarc-au",
  trailingSlash: "always",
  build: { assets: "assets" },
  // Keeps page scripts as files so the meta CSP can use script-src 'self'.
  vite: { build: { assetsInlineLimit: 0 } },
});
