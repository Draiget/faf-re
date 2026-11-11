# FAF server dashboard

A web page for one dedicated server (plan WP17.4), talking to its REST API (plan WP17.11, `server --rest`, see [docs/SWITCHES.md](../../docs/SWITCHES.md)): connect with the server's address and admin token, watch the lobby or game (phase, beat, each seat's state, ready, ping and slot), run the control ops (start the game, pause, resume, set options, eject, allow or disallow an address, end the game), and follow the event stream (joins, leaves, ready, launch, game start, results, stats; the server's console lines on request).

The page has a header with the connection and event-stream state, a phase panel (lobby or game, game clock, paused, the start-when-ready countdown), seat cards, a live game panel with one card per army grouped by team (score, mass and energy, units against the cap, ACU health and upgrades, result; from `GET /api/v1/armies`, polled only in the game and hidden when the server lacks it), grouped control ops (eject and end ask first; each answer shows as a toast), and an event timeline filtered by kind, with results and end-of-game stats as tables. Light and dark follow the system unless the theme button picks one.

## A machine's server-host

The page also drives `server-host` (plan WP17.13, `tools/cmd/server-host`), which runs one per machine, starts with no lobby, and runs each lobby as its own `server` pinned to chosen CPUs. The address field takes either: the page asks `GET /api/v1/host`, shows the host when it answers and the single-server page above when it answers 404. The host page shows the machine (CPU model, memory, load), a heatmap with one cell per logical CPU grouped by socket and core (hyperthread siblings together), coloured by the 10 s load and outlined in the colour of the lobbies pinned to it, and one card per lobby (map, state, seats, CPUs, phase, each human's join switches with a copy button; Open, Stop after a confirm, Forget once stopped or failed). "New lobby" opens the form: name, a searchable map list (size in km, players, FA or vault), seats up to the map's start spots (human with a name and an optional uid, or an AI personality; faction; team), FAF's usual game options, who starts the lobby (the first human from their game, or the organiser from here or once all are ready), start-when-ready seconds, how long the lobby stays open, and CPUs: Auto with a number of cores, or the cells clicked on the heatmap. Next to the CPUs it shows the host's cost hint for that many players on that map size (`GET /api/v1/hint`: mean, worst, suggested cores, and how it was measured) and warns when fewer cores are picked or a picked CPU is busy. Open shows that lobby with the single-server page through the host's proxy (`<host>/api/v1/lobbies/<id>`), under a bar that leads back to the host. The default address is the host's, `http://127.0.0.1:27180`.

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

`npm run check` type-checks. `npm run smoke -- <rest url> <token file>` runs `src/api.ts` (the page's client) against a running server in its lobby: status, a refused op, a wrong token, then `force_start` with the event stream open, which must show `game_started`. `npm run smoke-host -- <host url> <token file> [map id]` runs it against a running server-host: the machine, a wrong token, the maps, a hint, then a lobby on `auto` CPUs whose own status must answer through the host, stopped and forgotten.
