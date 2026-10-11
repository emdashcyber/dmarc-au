import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://emdashcyber.com",
  base: "/dmarc-au",
  trailingSlash: "always",
  build: { assets: "assets" },
});
