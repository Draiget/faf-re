// Two pages: the dashboard (index.html: a server-host's lobbies, queue, player hosting, logs and metrics) and the
// public request page players ask for a game on (request.html). `npm run build` writes both to dist/.

import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // Vite 8's name for rollupOptions (that one still works, deprecated).
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        request: fileURLToPath(new URL("./request.html", import.meta.url)),
      },
    },
  },
});
