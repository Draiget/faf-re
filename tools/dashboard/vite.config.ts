// Two pages: the dashboard (index.html: a server-host's control plane, its lobbies opened inside it) and the player's claim page for an
// open slot (claim.html, plan WP17.18). `npm run build` writes both to dist/.

import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // Vite 8's name for rollupOptions (that one still works, deprecated).
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        claim: fileURLToPath(new URL("./claim.html", import.meta.url)),
      },
    },
  },
});
