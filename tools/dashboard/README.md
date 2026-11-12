# FAF server dashboard

One web page for a machine's `server-host` (`tools/cmd/server-host`), which starts with no lobby and runs each lobby as its own dedicated `server` pinned to chosen CPUs, and the public page players ask for a server on (`request.html`). The dashboard talks to server-host only: its own API, each lobby's API through the host's proxy (`<host>/api/v1/lobbies/<id>/api/v1/...`), its logs and metrics. A lone `server --rest` (see [docs/SWITCHES.md](../../docs/SWITCHES.md)) is not something this page connects to.

The page uses the whole window: a top bar (the host, its CPU, memory and network with their last minutes, alerts, the connection) and the sections on the left (a strip on top on a phone), with the running lobbies under them. Until it is connected it asks for server-host's address and admin token.

- **Overview**: key numbers, the machine map (each NUMA node's CPUs by physical core, coloured by load, ringed in the colour of the lobby on them, hatched when they belong to the player-hosting pool; each node's memory), the network links, what needs attention, recent changes, the running lobbies and the queue.
- **Lobbies**: every lobby (map preview, kind, state, players, CPUs and node, live use, started), filtered by state and kind; Open, Stop, Remove.
- **Create lobby**: a full page in six steps with a live summary: kind (tournament: the organiser runs it; custom: the player on spot 1 hosts it), name and map from a gallery of previews with start spots; the slots, drawn on the map's large preview (each spot a named player, an open seat, an AI with its personality, or empty; team and faction); every setting with its default, changed ones marked, the map's own options; observers and start rules; placement (Auto or CPUs picked on the machine map, the planner's estimate and warnings as anything changes, one NUMA node kept) and whether to queue it when it doesn't fit; review, then Create.
- **Queue**: the player requests and the operator's queued lobbies, each with its place, map, seats, needs and what it waits for; move up, cancel.
- **Player hosting**: on or off; the pool's CPUs as whole cores on the machine map (or a whole node), games at once, the largest game, cores per game with the planner's hint of what fits, lobby time, the longest queue, access (anyone with the link, or an access code), the default settings, the request link, and the games running on the pool. Changes are a draft until Save.
- **Logs**: the host's own log and any lobby's server log, live, filtered by text and level.
- **Metrics**: charts over 5 minutes, 15 minutes or an hour: the machine's CPU, CPU by node, memory, free memory by node, each link, each lobby's CPU and memory. Drawn as SVG by the page itself.
- **A lobby's page** (`#/lobby/<id>`, `/log`, `/metrics`): the game (phase, countdown, clock, armies, seats, facts with join and watch lines, events, controls: start, settings, pause, end, player ops, the allowlist), its server log live, and its CPU and memory over time.

Light and dark follow the system unless the theme button picks one. Plain TypeScript with Vite; no framework, no chart library. The whole setup (building the server and server-host, the admin token, starting them, a TLS proxy, troubleshooting) is in [docs/SERVER_DASHBOARD.md](../../docs/SERVER_DASHBOARD.md).

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

`npm run smoke-host -- <host url> <token file> [map id]` runs `src/api.ts` (the pages' client) against a running server-host: the machine with its NUMA nodes and links, a wrong token (401), the maps with their start spots, a preview loaded without a token (and 404 for an unknown map), a hint, the planner (auto, by hand across nodes, an unknown CPU), a lobby refused without `force`, a lobby that doesn't fit queued with `queue: true` (202, listed in the queue, cancelled), then a tournament lobby with an observer and a referee: its kind and side, join and watch lines, its status through the host's proxy, its log (tail and stream), the metrics with its own series, the host's log (tail and stream), stopped, its log still there, and removed; the settings catalog. Then player hosting, with the pool saved first and put back at the end: a one-core pool for one game with open access, the planner on the pool's side and Auto keeping off it, the public pool, maps (with a preview) and settings, a request that becomes a lobby on the pool with a join line and the pool's and the request's options, a duplicate refused (409), a wrong key (404), two more requests queued behind it (listed with their requests, one moved up and cancelled, which the player sees), the first cancelled so the queue moves, and the pool turned off (public maps and requests refused with 403). It makes five requests, under the host's per-address limit.

`npm run smoke -- <host url> <token file> <lobby id>` runs the lobby client against one lobby through the host's proxy, as a lobby's page reaches it: the lobby listed, its status, a refused op, a wrong token (401), then `force_start` with the event stream open, which must show `game_started`. The lobby must be one the organiser starts, still in its lobby: the check starts its game.

## The request page

`request.html?host=<host url>` is the page players ask for a server on; Player hosting shows the link to hand out. It uses the public API only (`/api/v1/public/...`, no admin token), so it must be served from an origin the host allows (`--cors-origin`), usually next to the dashboard. It shows whether the server takes requests and how many game places are free, then the form: the player's name (they host: spot 1) and the access code when one is asked for; the map from a gallery of previews with start spots; who plays where on the map's large preview (friends as named players or open seats, AIs, empty spots; team and faction; up to the pool's largest game); the game settings starting at the server's defaults, marked “server”. After "Ask for a server" it follows the request every 3 s: its place in the queue, starting, the lobby with every human seat's join line to copy, the game, ended, or why it was refused, with Cancel while it waits or before the game. The request's id and key stay in the browser's local storage, so a reload follows it again.
