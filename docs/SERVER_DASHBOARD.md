# Running dedicated servers with the dashboard

How to run the dedicated server (`server`, Linux only) on a machine with the host agent (`server-host`) and drive it from the web dashboard (`tools/dashboard`): the host starts with no lobby; from the page you make tournament and custom lobbies (map with its preview and start spots, seats, AIs, every setting), choose the CPUs each runs on (by hand on the machine map, or the least loaded ones), queue the ones that don't fit yet, give players their join line, let players ask for a server of their own on a pool of CPUs you set aside, and watch every lobby and game with its log and metrics.

The dashboard is one page and talks to `server-host` only; every lobby, including a game a player asked for, opens inside it. A single `server` can also run without a host, from a match file you write yourself (section 6), but the dashboard doesn't connect to it.

## 1. Build

On Linux, with the pinned toolchain (see [README.md](../README.md)):

```
cmake --preset linux-clang-x64-release
cmake --build --preset linux-clang-x64-release --target server faf_server_probe
cd tools && go build -o ../build/server-host ./cmd/server-host
```

- `server` runs one lobby and its game; `faf_server_probe` is a test player that can sit in a seat without a game client.
- `server-host` starts a `server` per lobby. It needs Go (the version in `tools/go.mod`).
- The game data is a folder laid out as `--data` describes in [SWITCHES.md](SWITCHES.md): `fa/`, `faf/` (with `faf/bin/init_replay.lua`) and `vault/`.

Players need a game built with server mode (`cmake --preset clang-x64-release-server`, then `build.ps1`'s usual steps or `cmake --build --preset clang-x64-release-server`): only that build has the join switches (`/connectserver`). The FAF client's normal `main_x64.exe` doesn't.

## 2. Make an admin token

The REST APIs answer only requests that carry this token. Keep it in a file readable by the service's user only; it is never given on the command line, which every user of the machine can read.

```
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > admin.token
chmod 600 admin.token
```

## 3. Start the host

```
server-host --listen 127.0.0.1:27180 --token-file admin.token --cors-origin http://localhost:5173 \
  --server build/server --runs /var/lib/faf/lobbies \
  --maps fa=/data/fa/maps --maps vault=/data/vault/maps \
  --public-host 203.0.113.5 --ports 27200-27299 \
  --engine-args "/init /data/faf/bin/init_replay.lua /nobugreport /nosound"
```

| Option | What |
|---|---|
| `--listen` | where the host's REST API listens (`http://<ip:port>/api/v1`) |
| `--token-file` | the admin token (at least 16 characters) |
| `--cors-origin` | the one web origin whose pages may call the API: the dashboard's address |
| `--server` | the `server` binary each lobby runs |
| `--engine-args` | engine switches every lobby's server gets; `/init` names the init file of the game data |
| `--maps <label>=<folder>` | a folder of map folders (each with a `*_scenario.lua`); repeat it; the label shows as the map's source |
| `--runs` | where each lobby gets a folder: its match file, `server.log`, the replay and `result.json` |
| `--public-host` | the address players connect to, written into the join lines (default: this machine's outbound address) |
| `--game-ip` | the address each lobby's server listens on for players (default `0.0.0.0`) |
| `--ports` | the game ports lobbies take, one each (default `27200-27299`); open them for UDP and TCP |
| `--max-lobbies` | most lobbies at once (default 32) |

It says `server-host: REST API on http://127.0.0.1:27180/api/v1 (no lobby running; ...)` and runs no lobby until one is made. Stopping it (SIGTERM, Ctrl+C) stops every lobby's server first.

Each lobby's server is started on the CPUs chosen for it and keeps them (the server locks a CPU set it starts with, so FAF's init script can't move it; `--cpus` in [SWITCHES.md](SWITCHES.md)). A lobby on two or more CPUs also gets `/simworkers` (CPUs − 1).

## 4. Run the dashboard

```
cd tools/dashboard
npm ci
npm run dev
```

Open `http://localhost:5173` (exactly the `--cors-origin` origin: `http://127.0.0.1:5173` is another origin and the browser refuses it). Before it is connected the page asks for the host: the address starts as `http://<the page's own host name>:27180` (server-host's port unless `--listen` says otherwise); change it if the host runs on another machine, enter the admin token (the content of the `--token-file` file), and press Connect. The address stays in the browser, the token in the tab only; with both at hand the page connects by itself the next time it opens. If nothing answers, the page names the address it tried and says what to check (the port, that server-host runs, its `--cors-origin`). The host's name in the top bar leads back to this form.

For development, `tools/dashboard/.env.local` (ignored by git) may hold `VITE_HOST_URL=http://<host>:27180` and `VITE_HOST_TOKEN=<token>`: the page starts from them when the browser has nothing stored. The token is read by `npm run dev` only and never goes into a build.

The page uses the whole window. A top bar shows the host, its CPU, memory and network now with the last minutes as a small line, how many alerts there are, and the connection. On the left (a strip on top on a phone) are the sections, with the running lobbies under them:

- **Overview**: the key numbers (CPU, memory, network, lobbies running by kind, the queue, player hosting), the machine map, the network links, what needs attention (a failed lobby, a placement forced past an error or on the pool's CPUs, low memory, a busy machine or link, a long wait in the queue, a full queue), what changed while the page was open, the running lobbies and the queue.
- **Lobbies**: every lobby with its map, kind, state, players, CPUs and node, live use and when it started; filters for running, tournament, custom, player requests and ended; Open, Stop, and Remove once stopped.
- **Create lobby**: the steps below.
- **Queue**, **Player hosting**, **Logs**, **Metrics**: below.

The **machine map** shows the machine by NUMA node: each node's CPUs grouped by physical core (hyperthread siblings side by side in one box), each CPU coloured by its load of the last 10 s, ringed in the colour of the lobby running on it (click it to open that lobby), and hatched when it belongs to the player-hosting pool; each node's memory. When CPUs are picked (a lobby's placement, the pool) the same map takes the clicks.

### Creating a lobby

Create lobby is a full page in six steps, with a summary beside them (the map with its start spots and seats, the settings changed, observers, the countdown, the placement and its warnings) and Create available from any step once nothing is missing:

1. **Kind and map.** A tournament lobby is the organiser's: the map, every slot and every setting are set here, nobody hosts, and it starts from its page or by itself once every player is ready. A custom lobby is hosted by the player on spot 1 in their own game. Then the name and the map, from a gallery of the host's maps with their previews and start spots, searchable and filtered by size; maps with fewer spots than the seats asked for are marked.
2. **Slots.** The map's preview, large, with every start spot numbered and coloured by its team, and the seat's name or AI under it; next to it one row per spot: a player (with a name, or without one as an open seat that whoever gets its join line takes; the FAF uid is optional), an AI with its personality, or empty, and the team and faction. Clicking a spot on the map picks its row. Quick buttons split the spots into two teams (odd against even), clear the teams, or fill the empty spots with AIs. Each seat is sent with its start spot (`seat`), so a seat keeps the spot it was given on the map. Player colours follow the start spot.
3. **Settings.** Every setting, below.
4. **Observers and start.** The countdown once every player is ready (0: off), how long the lobby stays open without a game, and the observers (each with a watch line; referees watch live, the others with the delay).
5. **Placement.** Auto or CPUs picked on the machine map, below, with the planner's estimate and warnings as the map, seats and cores change; and what to do when it doesn't fit now: queue it (it waits in the operator queue and starts by itself when a lobby ends and it fits) or don't create it. With an error-level warning it can also be started anyway.
6. **Review.** Every part with a way back to its step; then Create. A lobby that starts opens its page; a queued one opens the queue.

### Game settings

The settings are read from the game's own files: the rules (victory, share, unit cap, fog, timeouts, prebuilt units, no-rush ...), the team options, the AI options, the AI personalities (mod AIs once mods are loaded), and for an adaptive map its own options (mexes, reclaim, and so on). Each shows its default, changed ones are marked with a way back to the default, a filter finds one by name, and only the ones changed are sent. On the test data: 32 options, 12 AIs, 19 maps with their own options (`adaptive_adrastea.v0004`: 11).

### Choosing CPUs

Pick CPUs on the machine map, or leave **Auto** on, with the suggested number of cores or a fixed one. Either way the host's planner (`POST /api/v1/plan`, the same as a lobby's creation uses) estimates the game and says where it goes; the create flow asks it for the operator's side, so Auto keeps off the player-hosting pool's CPUs, and Auto's pick shows dashed on the map:

- **Estimate**, from measurements on a two-socket test server (Xeon Gold 6144, one sim thread, normal speed): cores on average 0.07 with 1-2 players, 0.25 with 3-5, 0.22 with 6-8 and 0.38 with 9 or more, worst 30 s 0.14, 0.58, 0.40 and 0.67 (bigger maps scaled by an unmeasured ×1.15 at 20 km, ×1.3 at 40 km, ×1.5 at 81 km); memory from the measured peaks (190 MB at 4 players to 406 MB at 12) plus a quarter, 16 players estimated; the server's upload 205 KB/s for a 1v1, 2.3 MB/s for 8 players, 2.6 MB/s for 16.
- **Placement** (Auto): one NUMA node, the one with enough free physical cores (no lobby on any of their hyperthreads), then the most free memory, then the least load; one CPU per physical core, least loaded first; hyperthread siblings only when the node runs short. The lobby's memory is preferred on that node (`set_mempolicy`, inherited by its server): in a container this needs `CAP_SYS_NICE` (`docker run --cap-add SYS_NICE`), else the lobby starts with a `memory_policy` warning.
- **Warnings**: CPUs on two NUMA nodes (`spans_nodes`), fewer cores than the game's worst 30 s needs (`too_few_cores`) or far more than it needs (`too_many_cores`), a CPU another lobby runs on (`shared_cpu`) or busy outside the lobbies (`busy_cpu`), a CPU of the player-hosting pool (`pool_overlap`), both hyperthreads of one core (`both_siblings`), a sibling busy with another lobby (`sibling_busy`), a node short of whole cores (`node_short`), less free memory on the node than the game takes (`node_memory`), and the lobbies' upload over 80% of the links (`network`). An `error` (too little memory, no free CPU, links overrun, an unknown CPU) refuses the lobby unless it is queued or the request says `"force": true`.

### Who starts the game

- **Custom** (`control` `player`): the first human seat hosts the lobby in their game and presses Launch, as in a FAF lobby; they may change game options and eject.
- **Tournament** (`control` `organiser`): nobody hosts. Start it from the lobby's page (Start the game now), or set the countdown: once every player but the lobby's host is ready, a countdown of that many seconds runs, and the game starts at its end. Anyone leaving or standing down stops it.

A lobby left open longer than its lobby minutes starts as it is.

### Player hosting

Player hosting lets players ask for a server of their own on the request page. It is off until the operator turns it on, and while it is on it has a pool: the CPUs player games may use.

- **CPUs**: whole cores, picked on the machine map (a click takes or gives back a core with both of its hyperthreads) or a whole NUMA node at once. The page says how many cores go to player games and how many stay for operator lobbies; Auto doesn't pick the pool's CPUs for operator lobbies. A CPU given to the pool while an operator lobby still runs on it stays that lobby's until it ends (the answer warns `pool_overlap`).
- **Limits**: games at once, the largest game (seats, AIs included), cores per game (from the map and players, or always a fixed number), how long a lobby waits for its game, and the longest queue. Under them the planner's hint: what a typical game (4 players on a 10 km map) and the largest one (the most players on a 20 km map) need, and how many of each fit in the pool at once.
- **Who may ask**: anyone with the link (limited per address: a few requests a minute, one live request per player name), or only with an access code the operator hands out with the link.
- **The request link**: `request.html?host=<host>` next to the dashboard, with a copy button. A link to a loopback address is flagged: players elsewhere can't reach it, so connect the dashboard with the host's public address before handing it out.
- **Default settings** of player games: where a requested game starts; the player may change them.
- **Now on the pool**: the games running on it (with their player, map, seats and CPUs), how many wait, and the free cores.

Changes are kept as a draft, shown in a bar with Save and Discard, until saved (`PUT /api/v1/pool`). The on/off switch acts at once; turning it off asks first, refuses new requests, lets running games end, and with requests waiting refuses those too. The pool's settings stay across host restarts.

### Requests

A player opens the request link, types their name (and the access code if one is asked for), picks the map from the gallery, sets who plays where on the map's start spots (they are spot 1 and host the game; friends as players, with a name or as open seats; AIs), and the game settings, which start at the server's defaults (marked “server”). The page says how many game places are free and how many wait. "Ask for a server" sends it; the page then follows the request every few seconds: its place in the queue, starting, the lobby with every human seat's join line to copy and hand out, the game, or why it was refused. The request's key (its credential) stays in the browser, so a reload follows it again. The player can cancel while it waits or before the game. While player hosting is off, the page says the server isn't taking requests.

### The queue

Two queues, each first come first served: player requests wait for the pool, operator lobbies created with "Queue it" wait for the CPUs outside it. The Queue page lists both with each item's place, map, seats, what it needs (cores, memory) and what it waits for (a free game place, free cores, free memory, network room, a free port). The operator moves an item up one place or cancels it; a cancelled request shows as cancelled on the player's page. When a lobby ends, the host starts the first item of its side that fits.

### Joining

After a lobby is made, each human seat has a join line, for example `/connectserver 203.0.113.5:27200 /servertoken 0bc7…88 /serveruid 1001`. The player starts the server-mode game from FAF's `bin_x64` folder with it:

```
main_x64.exe /init init_faf.lua /windowed 1280 720 /connectserver 203.0.113.5:27200 /servertoken 0bc7…88 /serveruid 1001
```

The token is that seat's alone; hand each player only their own line.

### Watching

A lobby may list observers, each with a name and a token of their own, and a delay for them (`observer_delay_seconds`). An observer marked referee watches with no delay. Each gets a watch line, for example `/replay gpgnet://203.0.113.5:27201/9f3a…41`, which the game opens as a live replay of the lobby's game: `main_x64.exe /init init_faf.lua /replay gpgnet://203.0.113.5:27201/9f3a…41`. This is the game's own live-replay path, so it needn't be a server-mode build. The lobby then takes a second port from `--ports` for the watchers.

### A lobby's page

A lobby opens from the lists, the machine map or the navigation, through the host's proxy; `#/lobby/<id>` links to it directly. A bar on top names it with its kind, state, map, CPUs and node, and has three tabs:

- **Game**: the lobby or game (phase, the start-when-ready countdown, the game clock), during the game each army (score, mass and energy with stored, income per second and storage, units against the unit cap, the commander's health and upgrades, the result), the seats (joined, ready, ping), the lobby's facts (map, seats, who starts it, CPUs, node, live use, port, when it started and whether it was queued first, the request it came from) with every join and watch line and Stop, and the events with filters. The controls: start the game now; the lobby's game settings, as the same settings form (the lobby's current values, as it started and as `options` events change them; changes marked “to apply” and sent with `set_options`); pause, resume, end with results; eject, set a player's team, faction and colour, substitute, extend timeouts; allow or disallow an address. Settings change in the lobby only, and only in a tournament lobby: a custom lobby's settings are its host player's, so the page shows them without changing them. Game speed and team lock are fixed when the lobby starts and aren't offered. On a host without the settings catalog the settings are typed as `Key=Value,Key=Value` instead.
- **Server log** (`#/lobby/<id>/log`): its `server.log`, the last lines and then new ones as they come, also after the lobby ended; filtered by text or to warnings and errors; it follows the newest line until scrolled up.
- **Metrics** (`#/lobby/<id>/metrics`): its server's CPU (cores used, against the CPUs it was given) and memory over time.

### Logs and metrics

**Logs** lists the host's own log (lobbies starting and ending, the queue, the pool) and every lobby's log, running or ended; the one picked is shown live with the same filters. **Metrics** draws the host's history, a sample every 2 s kept for an hour, over the last 5 minutes, 15 minutes or hour: the machine's CPU, CPU by NUMA node, memory in use, free memory by node, each network link sending and receiving, and each lobby's CPU and memory. Hovering a chart reads every line at that moment. A host without the metrics endpoint gets the page's own samples since it connected.

## 5. Reaching it from another machine

The APIs are plain HTTP, so the token travels in the clear. Bind `--listen` to `127.0.0.1` and put a TLS proxy in front of it for anything reached over a network, for example Caddy:

```
dash.example.org {
    reverse_proxy /api/* 127.0.0.1:27180
    root * /srv/dashboard/dist
    file_server
}
```

with `npm run build`'s `tools/dashboard/dist/` copied to `/srv/dashboard/dist` and `--cors-origin https://dash.example.org`. On a trusted LAN, binding to the LAN address works without a proxy. The players' game ports (`--ports`) are separate from the API and must be reachable by the players.

## 6. One server without a host

A match file describes the game: map, options, the players' seats (`OwnerID` and `MatchTokens`) and any AIs; see the server section of [SWITCHES.md](SWITCHES.md). Then:

```
server --match match.lua --out game --data /path/to/data \
  --listen 0.0.0.0:27185 --join-seconds 600 --lobby-seconds 600 \
  --rest 127.0.0.1:27181 --rest-token-file admin.token
```

The server's own REST API (`--rest`, the lobby API below) is a feature of the server for scripts and other tools, for example `faf_server_control` or `curl`. The dashboard doesn't connect to it: it reaches games through `server-host`, which runs each lobby's server with `--rest` itself and proxies it. To drive a game from the dashboard, run it under `server-host`. To see a seat taken without a game client: `faf_server_probe --server 127.0.0.1:27185 --uid 1001 --token <its MatchTokens entry> --lobby-name Probe --no-decode --seconds 3600`.

## API

Every request carries `Authorization: Bearer <token>`; otherwise the answer is `401`. The exceptions are a map's preview image and the players' requests under `/api/v1/public/` (below). Answers are `200 {"ok": true, ...}`, or `{"ok": false, "error": "..."}` with `400` (refused, with the reason), `403` (player hosting is off, or a wrong access code), `404` (no such path, lobby, map or queued item), `409` (a conflict, e.g. no free port), `429` (too many requests from one address) or `502` (a lobby's server didn't answer).

The host (`server-host`):

| Request | Does |
|---|---|
| `GET /api/v1/host` | the machine: `name`, `cpu_model`, `memory_mb`, `cpus` (each `id`, `core`, `socket`, `load` over 1 s and `load10` over 10 s in %, the `lobbies` on it), the number of running `lobbies`, the `ai` personalities; `nodes` (each NUMA node's `id`, `cpus`, `memory_mb` total and free) and `links` (each physical network link's `name`, `speed_mbps`, `in_kbps`, `out_kbps`); each CPU also has its `node` |
| `GET /api/v1/maps` | the maps: `id`, `name`, `file`, `size`, `km`, `players` (start spots), `description`, `source`, `has_options`, `spawns` (each start spot `[x, z]` from the map's `_save.lua` markers, 0..1 over the map's size, in army order; `[]` when a marker is missing) and `preview` (the path of its preview image, when its `.scmap` has one) |
| `GET /api/v1/maps/<id>/preview.png` | the map's preview: the image its `.scmap` embeds, as PNG (256×256 on the game's and the vault's maps); `404` if it has none. No token needed, so an `<img>` can show it |
| `GET /api/v1/hint?players=<n>&km=<km>` | a game's cost: `mean_cores`, `worst_cores`, `suggested_cores`, `basis` |
| `POST /api/v1/plan` | `{"players": 8, "km": 20, "cores": 2}` or `{..., "cpus": [3, 11]}`, and `"side": "operator"` (default) or `"pool"`: the planner's answer without starting anything, on that side's CPUs (below): `side`, `plan` with `estimate` (cores mean, worst, suggested; `memory_mb`; `upload_kbps`; `basis`), `cores`, `cpus`, `nodes`, `fits` and `warnings` (each `code`, `severity`, `text`). On the pool side without `cores` or `cpus`, the pool's cores per game |
| `GET /api/v1/settings[?map=<id>]` | the game's settings as FAF's Lua defines them (the server binary reads them, `--describe-settings`): `options` (each `key`, `label`, `help`, `default`, `group` rules, teams or ai, and its `values`), `ai` (each `key`, `name`, `rating`) and, with a map that has its own `_options.lua` (adaptive maps; `has_options` in `/maps`), `map_options`. A lobby starts from every option's default and the request's `options` (game and map options together, values as strings or numbers as FAF has them) change them |
| `GET /api/v1/lobbies` | every lobby: `id`, `name`, `state`, `map`, `cpus`, `port`, `seats` (with each human's `join` line), `observers` (each `name`, `referee`, `watch` line), `observer_delay_seconds`, `observe_port`, `hint`, `nodes`, `warnings` (the placement's), `usage` (its server's `cpu_cores` and `rss_mb`, every 2 s), `kind` (`tournament` or `custom`), `side` (`operator`, or `pool` for a player's request), `request` (the request it came from, or null), `queued_at` (when it was queued, or null if it never waited), `started_at`, `phase`, `beat`, `exit` |
| `POST /api/v1/lobbies` | a new lobby: `{"map": "scmp_009", "seats": [{"kind": "human", "name": "Ann", "faction": 1, "team": 2}, {"kind": "ai", "ai": "adaptive", "faction": 2, "team": 3}], "options": {"Victory": "demoralization"}, "control": "player", "kind": "custom", "start_when_ready": 10, "lobby_minutes": 60, "observers": [{"name": "Caster"}, {"name": "Ref", "referee": true}], "observer_delay_seconds": 120, "cpus": "auto", "cores": 1, "queue": true}`; `cpus` may instead list CPU ids. Faction 1-4 (UEF, Aeon, Cybran, Seraphim) or 5 (random, chosen by the host); team 1 is no team, 2-9 teams 1-8. `kind` defaults from `control` (`organiser`: `tournament`, `player`: `custom`), and `control` from `kind` when only that is given. While player hosting runs, Auto picks CPUs outside the pool. When the lobby doesn't fit now (CPUs, memory, the host's lobby limit, ports), `"queue": true` answers `202 {"ok": true, "queued": <queued item>}` and the lobby waits in the operator queue; without it the answer is `409` |
| `DELETE /api/v1/lobbies/<id>` | stops the lobby's server (SIGTERM, a kill after 10 s); `?forget=1` then removes it from the list |
| `GET /api/v1/lobbies/<id>/log?lines=500` | the last lines of that lobby's `server.log` (default 500, at most 5000), also after it ended: `lines`, `size` (bytes), `state` |
| `GET /api/v1/lobbies/<id>/log/stream` | Server-Sent Events: each new line of its `server.log` as a `data:` event, from the moment the stream opens; when the lobby has ended and its log is read to the end, an `end` event, and the stream closes |
| `/api/v1/lobbies/<id>/api/v1/...` | that lobby's own API, below, with the host's token |
| `GET /api/v1/pool` | player hosting: `pool` (`enabled`, `cpus`, `nodes` (the NUMA nodes of its CPUs), `max_games`, `max_players`, `cores` (per game; 0 picks from the map size and players), `lobby_minutes`, `access` (`open` or `code`), `code`, `options` (a player's game's default settings), `max_queue`) and `usage` (`games` running from the pool, `queued` requests, `free_cores` (its physical cores no lobby runs on), `cpus_busy`) |
| `PUT /api/v1/pool` | changes any of the pool's fields, e.g. `{"enabled": true, "nodes": [1], "max_games": 4, "max_players": 8, "cores": 0, "lobby_minutes": 60, "access": "code", "max_queue": 10, "options": {"Victory": "demoralization"}}`; `nodes` without `cpus` means every CPU of those nodes; `access` `code` without a `code` makes one. Answers as GET, with `warnings`: `pool_overlap` for an operator's lobby running on the pool's CPUs (it keeps them until it ends). Turning it off refuses new requests; running games and queued requests drain, unless `"drop_queue": true` cancels the queued ones. The pool is kept in `pool.json` under `--runs` for the next start |
| `GET /api/v1/queue` | both queues in order: `queue`, each item `id`, `side` (`operator` or `pool`), `kind`, `name`, `player` (the requesting player, or null), `request` (or null), `map` (`id`, `name`, `km`, `players`), `seats`, `estimate` (as the planner's), `position` (1 is next, per side), `waiting_for` (`games`: the host's or the pool's game limit, `cores`, `memory`, `network`, `ports`; empty when it fits and starts next), `created` |
| `DELETE /api/v1/queue/<id>` | cancels a queued item (its request shows `cancelled`); answers the queue |
| `POST /api/v1/queue/<id>/up` | moves an item one place earlier in its side's queue; answers the queue |
| `GET /api/v1/metrics?seconds=600` | the host's history, sampled every 2 s and kept an hour (default 600 s, at most 3600): `interval_seconds`, `t` (Unix times), `cpu` (% over all CPUs), `mem_used_mb`, `net` (each link's `in_kbps` and `out_kbps`), `nodes` (each NUMA node's `cpu` % and `mem_free_mb`), `lobbies` (each running lobby's `cpu_cores` and `rss_mb`). Every series has one value per time; a link, node or lobby absent at a time has `null` there |
| `GET /api/v1/logs/host?lines=500` | the host's own last log lines: `lines` (it keeps 5000) |
| `GET /api/v1/logs/host/stream` | Server-Sent Events: each new host log line as a `data:` event |

The queue: a lobby that doesn't fit waits, first in first out per side (the operator's queue for lobbies made with `"queue": true`, the pool's for players' requests). Whenever a lobby ends, the pool changes, an item is cancelled or moved, and every 5 s, the host starts the first item of each side that fits, and again until none does. An item that can't start for another reason (its map is gone, the server didn't start) leaves the queue, and its request is refused with the reason.

The two sides: player games run on the pool's CPUs only, one CPU per free physical core as Auto picks, `cores` per game (or the planner's suggestion). While player hosting is on, or requests still wait, the operator's Auto picks outside the pool; CPUs picked by hand may be the pool's, with the warning `pool_overlap` (on the pool side, a CPU outside it warns `outside_pool`).

A lobby (`server --rest`, or through the host):

| Request | Does |
|---|---|
| `GET /api/v1/status` | the lobby or the game: phase, host, beat, paused, the countdown, and each seat (`uid`, `name`, `joined`, `loaded`, `lost`, `gone`, `away`, `ping_ms`, `ready`, `slot`) |
| `GET /api/v1/armies` | during the game: `beat` and each army's `name`, `team`, `faction`, `human`, `uid`, `type`, `score`, `mass` and `energy` (`stored`, `income` per second, `storage`), `units` (`count`, `cap`), `acu` (`alive`, `health`, `max_health`, `enhancements`), `defeated`, `result`. In the lobby: 400. Score and units come from FAF's score table, which the game sends every 2 s |
| `POST /api/v1/ops/<op>` | a control op with its fields as a JSON object: `force_start`, `pause`, `resume`, `eject` (`uid`, `reason`), `set_options` (`options`: `"Key=Value,..."`), `set_player` (`uid`, `options`), `allow` / `disallow` (`address`), `substitute` (`uid`, `token`, `name`), `extend_timeouts` (`uid`, `count`), `end` (`results`: `"1=victory,2=defeat"`, `reason`) |
| `GET /api/v1/events` | Server-Sent Events: `joined`, `left`, `away`, `back`, `host`, `ready`, `countdown`, `countdown_cancelled`, `launched`, `game_started`, `result`, `stats`, `game_ended`, `content`, and every console line as `log` |

The details of each op are in [SWITCHES.md](SWITCHES.md) under `--control` and `--rest`.

Players' requests (no `Authorization`; a request's `key` is its player's credential for following and cancelling it). Maps, settings and new requests answer only with player hosting on (`403` otherwise):

| Request | Does |
|---|---|
| `GET /api/v1/public/pool` | `enabled`, `access` (`open` or `code`), `max_players`, `lobby_minutes`, `options` (the defaults a request starts from), `queue` (`length`: requests waiting, `games` running, `max_games`) |
| `GET /api/v1/public/maps` | the maps, as `/api/v1/maps`, with `preview` under `/api/v1/public/maps/<id>/preview.png` |
| `GET /api/v1/public/maps/<id>/preview.png` | the map's preview, as `/api/v1/maps/<id>/preview.png` |
| `GET /api/v1/public/settings[?map=<id>]` | the settings, as `/api/v1/settings` |
| `POST /api/v1/public/requests` | asks for a game: `{"player": "Ann", "map": "adaptive_adrastea.v0004", "seats": [{"kind": "human"}, {"kind": "human", "name": "Bo"}, {"kind": "ai", "ai": "rush"}], "options": {"UnitCap": "500", "automex": 2}, "code": "<access code, with access code>"}`; seat 1 must be a human (the requesting player, named `player` unless the seat has a name); no seats means the player alone; at most `max_players` seats. The `options` go over the pool's. The game is a `custom` lobby (seat 1 hosts in their own lobby screen) on the pool. Answers `request`: `id`, `key`, `player`, `state` (`queued`, `starting`, `lobby`, `game`, `ended`, `refused`, `cancelled`), `position` (in the pool's queue, or null), `reason` (why it was refused, cancelled or failed, or null), `lobby` (once started: `id`, `name`, `state`, `phase`, `beat`, `map`, `seats` with each human's `join` line to hand out, `options`, `port`, `warnings`), `created`. It starts at once when it fits, else waits in the pool's queue; past `max_queue` waiting it is refused (`409`, with the refused `request`). Refused before that: a game larger than the whole pool (`400`), a wrong code (`403`), a second live request of the same player name from the same address (`409`), more than 6 requests a minute from one address (`429`; behind a proxy on the same machine, the last `X-Forwarded-For` address counts) |
| `GET /api/v1/public/requests/<id>?key=<key>` | the request, as POST answers it; `404` for a wrong key |
| `DELETE /api/v1/public/requests/<id>?key=<key>` | cancels it: out of the queue, or its lobby stopped before the game starts; `409` once the game runs or the request has ended |

Ended requests are kept 6 hours; the queue and the requests aren't kept when the host restarts.

## When it doesn't work

- **Token refused** (401) in the dashboard: the token differs from the `--token-file` file's (spaces and line ends at its end are dropped).
- **Not a host**: the address answered but has no `/api/v1/host`, for example a lone server's `--rest` port; the dashboard needs `server-host`'s address (port 27180 unless `--listen` says otherwise).
- **The page can't reach the API** (the browser's console shows a CORS error): the page's address isn't exactly the `--cors-origin` origin, scheme and port included.
- **No answer at all**: the address or port is wrong, server-host isn't running, the API is bound to `127.0.0.1` and the page runs on another machine, or a firewall closes the port.
- **A lobby is `failed`**: its card shows how the server ended; its `server.log` in the lobby's folder under `--runs` says why.
- **A lobby's CPUs**: the kernel's view is in `cpus_allowed` on the lobby (from `/proc/<pid>/status`); inside a container, CPUs outside the container's set can't be used.
- **A player can't join**: the game isn't a server-mode build, the join line is another seat's, or the lobby's port isn't reachable.
- **An op is refused**: the answer says why, for example `GameSpeed is set before the lobby opens; the match file has it`.
