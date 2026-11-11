# FAF server dashboard

A web page for one dedicated server (plan WP17.4), talking to its REST API (plan WP17.11, `server --rest`, see [docs/SWITCHES.md](../../docs/SWITCHES.md)): connect with the server's address and admin token, watch the lobby or game (phase, beat, each seat's state, ready, ping and slot), run the control ops (start the game, pause, resume, set options, eject, allow or disallow an address, end the game), and follow the event stream (joins, leaves, ready, launch, game start, results, stats; the server's console lines on request).

Plain TypeScript with Vite; no framework. The token stays in the tab's session storage. The whole setup (building the server, the admin token, starting both, a TLS proxy, troubleshooting) is in [docs/SERVER_DASHBOARD.md](../../docs/SERVER_DASHBOARD.md).

## Run it

```
npm ci
npm run dev          # http://localhost:5173
```

Start the server with the API and this page's origin allowed:

```
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > admin.token
server --match match.lua --out game --listen 0.0.0.0:27000 \
  --rest 127.0.0.1:27171 --rest-token-file admin.token --rest-cors-origin http://localhost:5173 ...
```

Then enter `http://127.0.0.1:27171` and the token. The API is plain HTTP: anything beyond the machine itself goes through a TLS proxy in front of it.

`npm run build` type-checks and writes the static page to `dist/`, to be served from the origin given to `--rest-cors-origin`.

## Check it

`npm run check` type-checks. `npm run smoke -- <rest url> <token file>` runs `src/api.ts` (the page's client) against a running server in its lobby: status, a refused op, a wrong token, then `force_start` with the event stream open, which must show `game_started`.
