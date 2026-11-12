# FAF server dashboard

A web page for one dedicated server (plan WP17.4), talking to its REST API (plan WP17.11, `server --rest`, see [docs/SWITCHES.md](../../docs/SWITCHES.md)): connect with the server's address and admin token, watch the lobby or game (phase, beat, each seat's state, ready, ping and slot), run the control ops (start the game, pause, resume, set options, eject, allow or disallow an address, end the game), and follow the event stream (joins, leaves, ready, launch, game start, results, stats; the server's console lines on request).

The page has a header with the connection and event-stream state, a phase panel (lobby or game, game clock, paused, the start-when-ready countdown), seat cards, a live game panel with one card per army grouped by team (score, mass and energy, units against the cap, ACU health and upgrades, result; from `GET /api/v1/armies`, polled only in the game and hidden when the server lacks it), grouped control ops (eject and end ask first; each answer shows as a toast), and an event timeline filtered by kind, with results and end-of-game stats as tables. Light and dark follow the system unless the theme button picks one.

## A machine's server-host

The page also drives `server-host` (plan WP17.13-WP17.20, `tools/cmd/server-host`), which runs one per machine, starts with no lobby, and runs each lobby as its own `server` pinned to chosen CPUs. The address field takes either: the page asks `GET /api/v1/host`, shows the host's control plane when it answers and the single-server page above when it answers 404. The control plane is one page. Capacity: the machine by NUMA node, each node's CPUs as a heatmap of physical cores with their hyperthread siblings (coloured by the 10 s load), the node's memory, the network links with live traffic, and what is allocated: each lobby's CPUs outlined in its colour, each open slot's dashed, and a table of the allocations with their live CPU and memory use. Next to it the two kinds of capacity use: tournament lobbies (map, state, CPUs, node, placement warnings, use, each human's join line and each observer's watch line; Open, Stop after a confirm, Forget) and open slots for players who host themselves (state, claim code with copy, the player and lobby once claimed; Free or stop its game after a confirm). The configuration panel creates either: a lobby (map with search, size and players; seats with the catalog's AIs; observers; every game setting from `GET /api/v1/settings?map=`, grouped into rules, units, AI and other with the default shown and changed values marked, plus the map's own options for adaptive maps; lobby control; countdown; how long the lobby stays open) or slots (players per game, the map size they are planned for, how many, default settings). Placement is Auto or the cells clicked on the heatmap; every change asks `POST /api/v1/plan` and shows the estimate (cores, memory, upload, the minimum connection per player), the planned CPUs on the heatmap, and the warnings with their severity. An error-level warning keeps Create off until “Start anyway” is ticked (`force`). Create sends the planned CPUs, so what was shown is what starts. A host without `/api/v1/settings` or `/api/v1/slots` (404) gets the usual options and the host's AI list, and no slots. Open shows a lobby with the single-server page through the host's proxy (`<host>/api/v1/lobbies/<id>`), under a bar that leads back. The default address is the host's, `http://127.0.0.1:27180`.

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

`npm run check` type-checks. `npm run smoke -- <rest url> <token file>` runs `src/api.ts` (the page's client) against a running server in its lobby: status, a refused op, a wrong token, then `force_start` with the event stream open, which must show `game_started`. `npm run smoke-host -- <host url> <token file> [map id]` runs it against a running server-host: the machine, a wrong token, the maps, a hint, its NUMA nodes and links, the planner (auto, by hand across nodes, an unknown CPU), a lobby refused without `force`, then a lobby on `auto` CPUs with an observer and a referee, whose watch lines must come back as `/replay gpgnet://host:port/<32 hex>` on the lobby's observe port, and whose own status must answer through the host, its nodes, warnings and usage listed, stopped and forgotten; the settings catalog and open slots when the host has them (SKIP on 404): two slots on Auto on different CPUs held on the host, the claim view with the code alone (no token), a wrong code (404), a claim with a human and an AI seat (join line, the slot claimed with its lobby), a second claim (409), then both freed, which stops the claimed game.

## The claim page

`claim.html` is the page players use to host on an open slot (plan WP17.18). The control plane shows each open slot's claim link (`claim.html?host=<host url>&code=<code>`, next to this page); the address and code can also be typed in. The page shows the slot (players, the map size it was sized for, cores), then the player's game: their name, the map (with size and start spots, warning when a map has too few spots for the seats or is larger than the slot was sized for), the seats (seat 1 is the host; humans and AIs, faction, team), and the game settings starting from the slot's picks, with the map's own options for adaptive maps. Claiming starts the lobby; the page then shows every human seat's join line to copy and hand out, and follows the lobby every 3 s. It uses the claim API only (`/api/v1/claim/<code>`, no admin token), so it must be served from the origin the host allows (`--cors-origin`), usually next to the dashboard.
