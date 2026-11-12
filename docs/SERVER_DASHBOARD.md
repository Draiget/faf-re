# Running dedicated servers with the dashboard

How to run the dedicated server (`server`, Linux only) on a machine with the host agent (`server-host`) and drive it from the web dashboard (`tools/dashboard`): the host starts with no lobby; from the page you pick a map, seats, AIs and options, choose the CPUs a lobby runs on (by hand on a CPU heatmap, or the least loaded ones), start it, give players their join line, and watch the lobby and the game (each army's resources, units, commander health and upgrades).

A single `server` can also run without a host, from a match file you write yourself (section 6).

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

Open `http://localhost:5173` (exactly the `--cors-origin` origin: `http://127.0.0.1:5173` is another origin and the browser refuses it), enter the host's address (`http://<host>:27180`) and the token, and press Connect.

The host page shows:

- **The machine**: CPU model, memory, and a heatmap with one cell per logical CPU, grouped by socket and by core (hyperthread siblings together), coloured by the load of the last 10 s. CPUs that run a lobby are outlined in that lobby's colour.
- **The lobbies**: map, state (starting, lobby, game, ended, failed, stopped), seats, CPUs, game time; Open, Stop, and Forget once stopped.
- **New lobby**: the map (search by name; size and start spots shown), the seats (each a human with a name, or an AI with its personality; faction and team each), the game options, who starts it, the countdown, and the CPUs.

### Game settings

The configuration panel lists every setting FAF's lobby has, read from the game's own files: the rules (victory, share, unit cap, fog, timeouts, prebuilt units, no-rush ...), the team options, the AI options, the AI personalities (mod AIs once mods are loaded), and for an adaptive map its own options (mexes, reclaim, and so on). Each shows its default; only the ones you change are sent. On fw0's data: 32 options, 12 AIs, 19 maps with their own options (`adaptive_adrastea.v0004`: 11).

### Choosing CPUs

Pick cells on the heatmap, or leave **Auto** on with a number of cores. Either way the host's planner (`POST /api/v1/plan`, the same as a lobby's creation uses) estimates the game and says where it goes:

- **Estimate**, from measurements on fw0 (Xeon Gold 6144, one sim thread, normal speed): cores on average 0.07 with 1-2 players, 0.25 with 3-5, 0.22 with 6-8 and 0.38 with 9 or more, worst 30 s 0.14, 0.58, 0.40 and 0.67 (bigger maps scaled by an unmeasured ×1.15 at 20 km, ×1.3 at 40 km, ×1.5 at 81 km); memory from the measured peaks (190 MB at 4 players to 406 MB at 12) plus a quarter, 16 players estimated; the server's upload 205 KB/s for a 1v1, 2.3 MB/s for 8 players, 2.6 MB/s for 16.
- **Placement** (Auto): one NUMA node, the one with enough free physical cores (no lobby on any of their hyperthreads), then the most free memory, then the least load; one CPU per physical core, least loaded first; hyperthread siblings only when the node runs short. The lobby's memory is preferred on that node (`set_mempolicy`, inherited by its server): in a container this needs `CAP_SYS_NICE` (`docker run --cap-add SYS_NICE`), else the lobby starts with a `memory_policy` warning.
- **Warnings**: CPUs on two NUMA nodes (`spans_nodes`), fewer cores than the game's worst 30 s needs (`too_few_cores`) or far more than it needs (`too_many_cores`), a CPU another lobby runs on (`shared_cpu`) or busy outside the lobbies (`busy_cpu`), both hyperthreads of one core (`both_siblings`), a sibling busy with another lobby (`sibling_busy`), a node short of whole cores (`node_short`), less free memory on the node than the game takes (`node_memory`), and the lobbies' upload over 80% of the links (`network`). An `error` (too little memory, no free CPU, links overrun, an unknown CPU) refuses the lobby unless the request says `"force": true`.

### Who starts the game

- **A player hosts** (`player`): the first human seat hosts the lobby in their game and presses Launch, as in a FAF lobby; they may change game options and eject.
- **The organiser** (`organiser`): nobody hosts. Start it from the lobby's page (Start now), or set **start when ready**: once every player but the lobby's host is ready, a countdown of that many seconds runs, and the game starts at its end. Anyone leaving or standing down stops it.

A lobby left open longer than its lobby minutes starts as it is.

### Open slots

Next to the tournament lobbies, the same host can hold capacity for players who host their own game. An open slot has a name, the most players it takes, the map size it is sized for, its CPUs (Auto or picked, through the same planner and warnings as a lobby), the lobby minutes, default settings, and whether it opens again after each game. Making several at once with Auto places each with the ones before it holding their CPUs, so they get different cores. An open slot's CPUs count as taken: the heatmap shows them in the slot's colour, and the planner warns `shared_cpu` on them. Open slots count against `--max-lobbies` with the running lobbies.

Each slot has a claim code, and a claim link to the dashboard's claim page (`claim.html?host=<host>&code=<code>`), which the operator hands to a player. The player needs no admin token: on the claim page they pick the map, the seats (friends and AIs, up to the slot's players), the game options and the map's own options, starting from the slot's defaults. The slot then becomes a player-hosted lobby on the slot's CPUs (`control` `player`): seat 1 is the claiming player, who changes game options (not the map) in their own game's lobby screen and presses Launch; the page shows every human seat's join line for the host to hand to their friends. When the game ends the slot opens again with a new claim code, so the old one stops working; a slot made with `"reopen": false` ends instead. Freeing a slot from the operator's page stops a game running on it.

### Joining

After a lobby is made, each human seat has a join line, for example `/connectserver 203.0.113.5:27200 /servertoken 0bc7…88 /serveruid 1001`. The player starts the server-mode game from FAF's `bin_x64` folder with it:

```
main_x64.exe /init init_faf.lua /windowed 1280 720 /connectserver 203.0.113.5:27200 /servertoken 0bc7…88 /serveruid 1001
```

The token is that seat's alone; hand each player only their own line.

### Watching

A lobby may list observers, each with a name and a token of their own, and a delay for them (`observer_delay_seconds`). An observer marked referee watches with no delay. Each gets a watch line, for example `/replay gpgnet://203.0.113.5:27201/9f3a…41`, which the game opens as a live replay of the lobby's game: `main_x64.exe /init init_faf.lua /replay gpgnet://203.0.113.5:27201/9f3a…41`. This is the game's own live-replay path (plan WP13.1), so it needn't be a server-mode build. The lobby then takes a second port from `--ports` for the watchers.

### A lobby's page

Open shows the lobby through the host: its seats (joined, ready, ping), the countdown, the controls (start, pause, resume, end, eject, set options or a player's team, faction and colour), the events, and during the game each army: score, mass and energy (stored, income per second, storage), units against the unit cap, the commander's health and upgrades, and the result.

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
  --rest 127.0.0.1:27181 --rest-token-file admin.token --rest-cors-origin http://localhost:5173
```

The dashboard connects to `http://127.0.0.1:27181` the same way and shows the lobby's page directly. To see a seat taken without a game client: `faf_server_probe --server 127.0.0.1:27185 --uid 1001 --token <its MatchTokens entry> --lobby-name Probe --no-decode --seconds 3600`.

## API

Every request carries `Authorization: Bearer <token>`; otherwise the answer is `401`. Answers are `200 {"ok": true, ...}`, or `{"ok": false, "error": "..."}` with `400` (refused, with the reason), `404` (no such path, lobby or map), `409` (a conflict, e.g. no free port) or `502` (a lobby's server didn't answer).

The host (`server-host`):

| Request | Does |
|---|---|
| `GET /api/v1/host` | the machine: `name`, `cpu_model`, `memory_mb`, `cpus` (each `id`, `core`, `socket`, `load` over 1 s and `load10` over 10 s in %, the `lobbies` on it), the number of running `lobbies`, the `ai` personalities; `nodes` (each NUMA node's `id`, `cpus`, `memory_mb` total and free) and `links` (each physical network link's `name`, `speed_mbps`, `in_kbps`, `out_kbps`); each CPU also has its `node` |
| `GET /api/v1/maps` | the maps: `id`, `name`, `file`, `size`, `km`, `players` (start spots), `description`, `source` |
| `GET /api/v1/hint?players=<n>&km=<km>` | a game's cost: `mean_cores`, `worst_cores`, `suggested_cores`, `basis` |
| `POST /api/v1/plan` | `{"players": 8, "km": 20, "cores": 2}` or `{..., "cpus": [3, 11]}`: the planner's answer without starting anything: `estimate` (cores mean, worst, suggested; `memory_mb`; `upload_kbps`; `basis`), `cores`, `cpus`, `nodes`, `fits` and `warnings` (each `code`, `severity`, `text`) |
| `GET /api/v1/settings[?map=<id>]` | the game's settings as FAF's Lua defines them (the server binary reads them, `--describe-settings`): `options` (each `key`, `label`, `help`, `default`, `group` rules, teams or ai, and its `values`), `ai` (each `key`, `name`, `rating`) and, with a map that has its own `_options.lua` (adaptive maps; `has_options` in `/maps`), `map_options`. A lobby starts from every option's default and the request's `options` (game and map options together, values as strings or numbers as FAF has them) change them |
| `GET /api/v1/lobbies` | every lobby: `id`, `name`, `state`, `map`, `cpus`, `port`, `seats` (with each human's `join` line), `observers` (each `name`, `referee`, `watch` line), `observer_delay_seconds`, `observe_port`, `hint`, `nodes`, `warnings` (the placement's), `usage` (its server's `cpu_cores` and `rss_mb`, every 2 s), `phase`, `beat`, `exit` |
| `POST /api/v1/lobbies` | a new lobby: `{"map": "scmp_009", "seats": [{"kind": "human", "name": "Ann", "faction": 1, "team": 2}, {"kind": "ai", "ai": "adaptive", "faction": 2, "team": 3}], "options": {"Victory": "demoralization"}, "control": "player", "start_when_ready": 10, "lobby_minutes": 60, "observers": [{"name": "Caster"}, {"name": "Ref", "referee": true}], "observer_delay_seconds": 120, "cpus": "auto", "cores": 1}`; `cpus` may instead list CPU ids. Faction 1-4 (UEF, Aeon, Cybran, Seraphim) or 5 (random, chosen by the host); team 1 is no team, 2-9 teams 1-8 |
| `GET /api/v1/slots` | the open slots: `id`, `name`, `state` (`open`, `claimed` while its lobby's server starts, `lobby`, `game`, `ended`), `max_players`, `km`, `cpus`, `nodes`, `warnings`, `claim_code`, `lobby` (the lobby it became, or null), `host_player`, `lobby_minutes`, `options`, `reopen`, `games` (hosted so far), `created` |
| `POST /api/v1/slots` | new slots: `{"name": "Public 4v4", "max_players": 8, "km": 20, "cores": 2, "count": 3, "lobby_minutes": 60, "options": {"Victory": "demoralization"}, "reopen": true}`; `cpus` may list CPU ids instead of `cores`. A slot that doesn't fit is refused (`409`) unless `"force": true`, and then none of the batch is made |
| `DELETE /api/v1/slots/<id>` | frees the slot, and stops the game on it if it was claimed |
| `DELETE /api/v1/lobbies/<id>` | stops the lobby's server (SIGTERM, a kill after 10 s); `?forget=1` then removes it from the list |
| `/api/v1/lobbies/<id>/api/v1/...` | that lobby's own API, below, with the host's token |

A lobby (`server --rest`, or through the host):

| Request | Does |
|---|---|
| `GET /api/v1/status` | the lobby or the game: phase, host, beat, paused, the countdown, and each seat (`uid`, `name`, `joined`, `loaded`, `lost`, `gone`, `away`, `ping_ms`, `ready`, `slot`) |
| `GET /api/v1/armies` | during the game: `beat` and each army's `name`, `team`, `faction`, `human`, `uid`, `type`, `score`, `mass` and `energy` (`stored`, `income` per second, `storage`), `units` (`count`, `cap`), `acu` (`alive`, `health`, `max_health`, `enhancements`), `defeated`, `result`. In the lobby: 400. Score and units come from FAF's score table, which the game sends every 2 s |
| `POST /api/v1/ops/<op>` | a control op with its fields as a JSON object: `force_start`, `pause`, `resume`, `eject` (`uid`, `reason`), `set_options` (`options`: `"Key=Value,..."`), `set_player` (`uid`, `options`), `allow` / `disallow` (`address`), `substitute` (`uid`, `token`, `name`), `extend_timeouts` (`uid`, `count`), `end` (`results`: `"1=victory,2=defeat"`, `reason`) |
| `GET /api/v1/events` | Server-Sent Events: `joined`, `left`, `away`, `back`, `host`, `ready`, `countdown`, `countdown_cancelled`, `launched`, `game_started`, `result`, `stats`, `game_ended`, `content`, and every console line as `log` |

The details of each op are in [SWITCHES.md](SWITCHES.md) under `--control` and `--rest`.

A player's claim of an open slot (no `Authorization`: the claim code in the path is the credential; `404` for a code no slot has):

| Request | Does |
|---|---|
| `GET /api/v1/claim/<code>` | `claim`: the `slot` (`id`, `name`, `state`, `max_players`, `km`, `cores`, `lobby_minutes`, `options`) and, once claimed, the `lobby` (`id`, `name`, `state`, `phase`, `beat`, `map`, `seats` with each human's `join` line, `options`, `port`) |
| `GET /api/v1/claim/<code>/maps` | the maps, as `/api/v1/maps` |
| `GET /api/v1/claim/<code>/settings[?map=<id>]` | the settings, as `/api/v1/settings` |
| `POST /api/v1/claim/<code>` | claims the slot: `{"player": "Ann", "map": "adaptive_adrastea.v0004", "seats": [{"kind": "human"}, {"kind": "human", "name": "Bo"}, {"kind": "ai", "ai": "rush"}], "options": {"UnitCap": "500", "automex": 2}, "start_when_ready": 0}`; seat 1 must be a human (the claiming player); no seats means the host alone. The `options` go over the slot's. Answers as GET, with the lobby; `409` if the slot is already claimed |

## When it doesn't work

- **401** in the dashboard: the token differs from the file's (spaces and line ends at its end are dropped).
- **The page can't reach the API** (the browser's console shows a CORS error): the page's address isn't exactly the `--cors-origin` (or `--rest-cors-origin`) origin, scheme and port included.
- **No answer at all**: the API is bound to `127.0.0.1` and the page runs on another machine, or a firewall closes the port.
- **A lobby is `failed`**: its card shows how the server ended; its `server.log` in the lobby's folder under `--runs` says why.
- **A lobby's CPUs**: the kernel's view is in `cpus_allowed` on the lobby (from `/proc/<pid>/status`); inside a container, CPUs outside the container's set can't be used.
- **A player can't join**: the game isn't a server-mode build, the join line is another seat's, or the lobby's port isn't reachable.
- **An op is refused**: the answer says why, for example `GameSpeed is set before the lobby opens; the match file has it`.
