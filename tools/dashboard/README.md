# FAF server dashboard

One web page for a machine's `server-host` (`tools/cmd/server-host`), which starts with no lobby and runs each lobby as its own dedicated `server` pinned to chosen CPUs. The page talks to server-host only: its own API, each lobby's API through the host's proxy (`<host>/api/v1/lobbies/<id>/api/v1/...`), and the players' claim API. A lone `server --rest` (see [docs/SWITCHES.md](../../docs/SWITCHES.md)) is not something this page connects to.

The page opens on the control plane at once, before anything is connected: the connection strip on top (server-host's address and admin token), and below it the plane's sections, empty until connected. Connected, they show:

- **Capacity**: the machine by NUMA node, each node's CPUs as a heatmap of physical cores with their hyperthread siblings (coloured by the 10 s load), the node's memory, the network links with live traffic, and what is allocated: each lobby's CPUs outlined in its colour, each open slot's dashed, and a table of the allocations with their live CPU and memory use.
- **Tournament lobbies** (map, state, CPUs, node, placement warnings, use, each human's join line and each observer's watch line; Open, Stop after a confirm, Forget) and **open slots** for players who host themselves (state, claim code and claim link with copy, the player and lobby once claimed; Open its game, Free or stop its game after a confirm), side by side.
- **Configure**: a tournament lobby (map with search, size and players; seats with the catalog's AIs; observers; every game setting from `GET /api/v1/settings?map=`, grouped into rules, units, teams, AI and other with the default shown and changed values marked, plus the map's own options for adaptive maps; lobby control; countdown; how long the lobby stays open) or open slots (players per game, the map size they are planned for, how many, default settings, reopen after a game). Placement is Auto or the cells clicked on the heatmap; every change asks `POST /api/v1/plan` and shows the estimate (cores, memory, upload, the minimum connection per player), the planned CPUs on the heatmap, and the warnings with their severity. An error-level warning keeps Create off until “Start anyway” is ticked (`force`). Create sends the planned CPUs, so what was shown is what starts. A host without `/api/v1/settings` or `/api/v1/slots` (404) gets the usual options and the host's AI list, and no slots.

**A lobby** (Open on its card, a claimed slot's Open, or a link `#/lobby/<id>`) opens inside the same page: a bar with the way back to the overview, the host's summary (CPUs and load, memory, lobbies running, slots open) and a switcher to the other running lobbies; then the lobby or game (phase, the start-when-ready countdown, the game clock, paused), the armies during the game (one card per army grouped by team: score, mass and energy, units against the cap, commander health and upgrades, result), the seats (joined, ready, ping, slot; click one to pick it for the player controls), the lobby's facts (map, control, CPUs, node, use, port, its open slot) with every join and watch line, and the event timeline filtered by kind (joins, leaves, ready, launch, game start, results and stats as tables; the console lines on request). The controls: start now; the lobby's game settings as the same settings form (the lobby's values as it started and as `options` events change them; changed ones marked “to apply”, sent with `set_options` as `Key=Value` pairs; game speed and team lock are the match file's and not offered; a player-hosted lobby's settings are the player's, so they are shown, not changed; a `Key=Value` text box only when the host has no settings catalog); pause, resume, end with results; eject, set player, substitute, extend timeouts; allow or disallow an address. Eject and end ask first; each answer shows as a toast. `#/lobby/<id>` links work after a reload: the page connects with what the tab has stored and opens the lobby.

Light and dark follow the system unless the theme button picks one. Plain TypeScript with Vite; no framework. The whole setup (building the server and server-host, the admin token, starting them, a TLS proxy, troubleshooting) is in [docs/SERVER_DASHBOARD.md](../../docs/SERVER_DASHBOARD.md).

## Run it

```
npm ci
npm run dev          # http://localhost:5173
```

server-host must allow the page's origin (`--cors-origin http://localhost:5173`). The page fills in the address `http://<the page's own host name>:27180` (server-host's port unless its `--listen` says otherwise); change it to the host's address if it runs elsewhere. The admin token is the content of the file server-host's `--token-file` names. The address is kept in the browser's local storage, the token in the tab's session storage only. With both at hand (stored, or the defaults below) the page connects on its own when it opens.

For development, defaults can come from a `.env.local` file next to `package.json` (git ignores it) or the environment of `npm run dev`:

```
VITE_HOST_URL=http://192.0.2.10:27180
VITE_HOST_TOKEN=<the admin token>
```

They are used only when the browser has nothing stored. `VITE_HOST_TOKEN` is read by the dev server only: `npm run build` never puts a token into `dist/`. `VITE_HOST_URL` does go into a build, as the address it starts with.

`npm run build` type-checks and writes the static pages to `dist/`, to be served from the origin given to `--cors-origin`.

## Check it

`npm run check` type-checks.

`npm run smoke-host -- <host url> <token file> [map id]` runs `src/api.ts` (the page's client) against a running server-host: the machine, a wrong token, the maps, a hint, its NUMA nodes and links, the planner (auto, by hand across nodes, an unknown CPU), a lobby refused without `force`, then a lobby on `auto` CPUs with an observer and a referee, whose watch lines must come back as `/replay gpgnet://host:port/<32 hex>` on the lobby's observe port, and whose own status must answer through the host, its nodes, warnings and usage listed, stopped and forgotten; the settings catalog and open slots when the host has them (SKIP on 404): two slots on Auto on different CPUs held on the host, the claim view with the code alone (no token), a wrong code (404), a claim with a human and an AI seat (join line, the slot claimed with its lobby), a second claim (409), then both freed, which stops the claimed game.

`npm run smoke -- <host url> <token file> <lobby id>` runs the lobby client against one lobby through the host's proxy, as a lobby's page reaches it: the lobby listed, its status, a refused op, a wrong token (401), then `force_start` with the event stream open, which must show `game_started`. The lobby must be one the organiser starts, still in its lobby: the check starts its game.

## The claim page

`claim.html` is the page players use to host on an open slot (plan WP17.18). The control plane shows each open slot's claim link (`claim.html?host=<host url>&code=<code>`, next to this page); the address and code can also be typed in. The page shows the slot (players, the map size it was sized for, cores), then the player's game: their name, the map (with size and start spots, warning when a map has too few spots for the seats or is larger than the slot was sized for), the seats (seat 1 is the host; humans and AIs, faction, team), and the game settings starting from the slot's picks, with the map's own options for adaptive maps. Claiming starts the lobby; the page then shows every human seat's join line to copy and hand out, and follows the lobby every 3 s. It uses the claim API only (`/api/v1/claim/<code>`, no admin token), so it must be served from the origin the host allows (`--cors-origin`), usually next to the dashboard.
