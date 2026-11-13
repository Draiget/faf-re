# Control service

`control-service` (`tools/cmd/control-service`, Go) is the web side of the dedicated servers. It signs users in with their FAF account, gives them roles, keeps the tournaments' allowlists, follows every server host (`server-host`, see [SERVER_DASHBOARD.md](SERVER_DASHBOARD.md)), makes organised lobbies on the host chosen or the least loaded one that fits, sends players' requests for games they host, and pushes the live state of every host and lobby to web clients as Server-Sent Events. The state is cached in Redis, or in memory when the service runs without Redis.

It is never in the game's path: players' games connect to the lobby servers the hosts run, and the service only talks to the hosts' REST APIs. When it stops, running lobbies and games go on.

```
web clients ──HTTPS── control-service ──HTTP + admin token── server-host (one per machine) ── server (one per lobby)
                          │                                                                      ▲
                       Redis (cache, events)                                    players' games ──┘
```

## Build and run

```
cd tools
go build -o ../build/control-service ./cmd/control-service
control-service --config control.yaml --redis 127.0.0.1:6379
```

| Option | What |
|---|---|
| `--config` | the configuration file (below); default `control.yaml` |
| `--listen` | where the API listens; default the configuration's `listen`, else `127.0.0.1:27190` |
| `--redis` | Redis (6.2 or newer) as `host:port`. Without it the cache and the event channel are in memory, with the same behaviour for one instance. With it, a Redis that doesn't answer stops the start |
| `--redis-password-file`, `--redis-db` | Redis' password (from a file) and database number |

`SIGHUP` reads the configuration again (roles, tournaments, hosts, sign-in settings); so does `POST /api/v1/admin/reload`. Run one instance: each instance follows every host itself.

The API is plain HTTP. For anything reached over a network, bind `listen` to `127.0.0.1` and put a TLS proxy in front, as for the host ([SERVER_DASHBOARD.md](SERVER_DASHBOARD.md) section 5); set `public_url` to the proxy's `https://` address so the session cookie is marked `Secure`. Redis holds sessions and every lobby's join lines: keep it on a loopback address or a private network.

## Configuration

```yaml
listen: 127.0.0.1:27190
public_url: https://control.example.org   # where browsers reach the service
cors_origin: http://localhost:5173        # a web UI on another origin (e.g. Vite's dev server); optional
admin_token_file: control-admin.token     # a bearer token with the admin role, for scripts; optional
session_hours: 12
poll_seconds: 2                           # how often each host is read
player_hosting: true                      # signed-in players may ask for a game they host
key_prefix: "faf-control:"                # Redis keys and channel

oidc:
  issuer: https://hydra.faforever.com/
  client_id: <the client id FAF registers>
  client_secret_file: oidc-client.secret  # leave out for a public client (PKCE alone)
  redirect_url: https://control.example.org/auth/callback   # default <public_url>/auth/callback
  scopes: [openid, public_profile]
  accept_access_tokens: true              # also take FAF access tokens as Authorization: Bearer
  required_scope: lobby                   # a scope those tokens must carry; optional

roles:
  admins: [1]            # FAF user ids
  organisers: [2, 3]     # may run organised lobbies of every tournament

tournaments:
  - id: spring-cup
    name: Spring Cup
    organisers: [4]      # run this tournament's lobbies only
    players: [10, 11, 12, 13]
    observers: [20]      # casters, referees

hosts:
  - name: eu-1
    url: http://203.0.113.5:27180
    token_file: eu-1.token   # the host's --token-file
    region: eu
```

Relative file names are read from the configuration file's folder. Token files hold at least 16 characters; spaces and line ends at their end are dropped. Unknown keys are refused.

## Sign-in

The service is an OpenID Connect client of FAF's provider (Hydra) and signs users in with the authorization-code flow and PKCE (S256):

1. The web UI sends the browser to `GET /auth/login?return=<path or URL>`. The service finds the provider's endpoints at `<issuer>/.well-known/openid-configuration`, keeps a state, a nonce and a PKCE verifier for 10 minutes, and redirects to the provider.
2. The provider sends the browser back to `GET /auth/callback?code=...&state=...`. The state is used once. The service trades the code (with the verifier, and the client secret when there is one) for tokens and checks the ID token: RS256 signature against the provider's JWKS (fetched again when a new key id shows up), issuer, audience (the client id), expiry and nonce.
3. The FAF user id is the token's `sub`. The name is the ID token's `preferred_username` (or `nickname`, `name`), else the provider's userinfo answer, else `FAF user <id>`.
4. The service sets an `HttpOnly`, `SameSite=Lax` session cookie (`Secure` with an `https` `public_url`) and redirects to `return`, which must be a path on the service or a URL on `cors_origin`.

`POST /auth/logout` ends the session. A change (`POST`, `PUT`, `DELETE`) made with the cookie must carry an `Origin` header of the service or of `cors_origin`; others are refused with `403`.

Scripts and other programs authenticate with `Authorization: Bearer`: the admin token, or (with `accept_access_tokens`) a FAF access token, checked as FAF's lobby server checks it (signature, issuer, expiry, and `required_scope` in its `scp`).

What FAF needs to provide: a registered OAuth client for the service (client id, a secret or a public client, the redirect URL `<public_url>/auth/callback`, the scopes `openid` and `public_profile`). Until then the service can be tried against `tools/cmd/oidc-mock`, a local stand-in that signs a configured user in without a password (never expose it).

## Roles

| Role | Who | May |
|---|---|---|
| admin | `roles.admins` | everything: every lobby on every host (also those made on a host's own dashboard), force a lobby past the planner's errors, reload the configuration |
| organiser | `roles.organisers` (every tournament, and lobbies outside tournaments), or a tournament's `organisers` (that tournament) | make organised lobbies, run and stop them (ops, armies), read hosts' maps, settings and planner |
| player | every signed-in FAF user | see the hosts and the lobbies, their own join or watch line, and ask for a game they host when `player_hosting` is on |

The one who made a lobby may also run it. Roles come from the configuration only and apply at once after a reload.

## Tournament allowlists

An organised lobby made for a tournament (`"tournament": "<id>"`) takes only the tournament's listed players in its human seats, each with their FAF id, and only listed observers or organisers as its observers, each once. AI seats are free. A lobby outside any tournament (admins and global organisers) has no list and may have open seats.

The host gets the seats with their FAF ids; the players' join lines are then their own credentials. A viewer of a lobby sees their own line under `you`; those who run the lobby see every line.

## Hosts and lobbies

Every `poll_seconds` the service reads each host's machine (`/api/v1/host`), player hosting (`/api/v1/pool`) and lobbies (`/api/v1/lobbies`), and each lobby's status (players joined, ready, ping) while it is open or in game. It also follows each running lobby's event stream through the host's proxy and relays it; an event other than a log line or the 2-second stats reads that lobby again at once. Everything goes into the cache (`host:<name>`, `lobby:<host>/<id>`), and each change goes out on the event channel. A host that stops answering is shown unreachable with its error, and its lobbies stay, marked `stale`.

A new organised lobby goes to the host named in the request, else to the least loaded host of the request's region that has the map and whose planner (`POST /api/v1/plan`) says it fits now. When a host refuses with a conflict (taken meanwhile), the next one is tried. The service never queues a lobby on a host; when nothing fits, the answer is `409` with each host's reason.

A player's request for a game they host goes to a host with player hosting on (the one named, else the shortest queue, then the fewest games, then the least load), through that host's public request API in the player's name, with the player in seat 1 and their FAF id. The service keeps the request's key and the pool's access code and never shows them.

## The web UI

The server dashboard (`tools/dashboard`, [SERVER_DASHBOARD.md](SERVER_DASHBOARD.md) section 4, "Through the control service") is the service's web UI as well as one host's: its connect form takes the service's address, signs in through `/auth/login` with the page as `return`, and then shows every host and lobby live from `/api/v1/events`, as the viewer's role allows. Serve it from `cors_origin` (or from `public_url` behind the same proxy), on the same site as the service: the session cookie is `SameSite=Lax`, so a page on another site doesn't get it. The preview images go through `/api/v1/hosts/<name>/maps/<id>/preview.png` with the cookie, so only organisers and admins see them.

`npm run smoke-control -- <service url> <admin token file> [--organiser <uid> --player <uid>] [--origin <web UI origin>]` (in `tools/dashboard`) runs the page's client against a running service: with the admin token, the health, a request without credentials, the hosts and the lobbies; with `--organiser` and `--player`, against `oidc-mock` only (its authorize step takes `login_as`), both sign in through `/auth/login`, the organiser reads a host's maps, settings, plan and a preview, makes an organised lobby with the player in it, and the checks follow it as each sees it (every line for the organiser; the player's own line, no ops, no armies, no other seat's line in their event stream), then stop it.

## API

Every request under `/api/v1/` needs a session cookie or a bearer token (above), except `GET /api/v1/health`; otherwise the answer is `401`. Answers are `200 {"ok": true, ...}`, or `{"ok": false, "error": "..."}` with `400` (refused, with the reason), `401` (not signed in), `403` (the roles don't allow it, or a cookie change from another origin), `404` (no such path, host, lobby or request), `409` (no host can take it now), `502` (a host didn't answer) or `503` (the cache didn't answer). A host's own refusal is passed on with its status and reason.

Lobbies are named `<host>/<id>` (`key`), for example `eu-1/l3`.

| Request | Does |
|---|---|
| `GET /api/v1/health` | `store` (`redis` or `memory`), `hosts`, `hosts_reachable`; no sign-in |
| `GET /auth/login?return=<where>` | starts the sign-in (above) |
| `GET /auth/callback` | the provider's redirect back |
| `POST /auth/logout` | ends the session |
| `GET /api/v1/me` | `user` (`uid`, `name`, `via`: `session`, `access_token` or `admin_token`), `roles`, `tournaments` (as below), `player_hosting` |
| `GET /api/v1/tournaments` | admins and global organisers: every tournament with its lists; others: the ones they are in, with `you` (`organiser`, `player`, `observer`), and the lists where they organise |
| `GET /api/v1/hosts` | each host. Organisers and admins: `name`, `region`, `reachable`, `error`, `machine`, `cpu_model`, `cpus`, `nodes`, `load` (mean CPU % over 10 s), `memory_total_mb`, `memory_available_mb`, `lobbies` (running), `player_hosting`, `pool_games`, `pool_queued`, `pool_max_games`, `checked`. Players: `name`, `region`, `reachable`, `lobbies`, `player_hosting` |
| `GET /api/v1/hosts/<name>` | one host (organisers, admins) |
| `GET /api/v1/hosts/<name>/maps`, `/settings[?map=<id>]`, `/hint?players=<n>&km=<km>`, `POST /api/v1/hosts/<name>/plan`, `GET /api/v1/hosts/<name>/maps/<id>/preview.png` | the host's own answers ([SERVER_DASHBOARD.md](SERVER_DASHBOARD.md)), for a lobby form (organisers, admins) |
| `GET /api/v1/lobbies[?host=<name>&tournament=<id>&running=1]` | every lobby, as its viewer may see it (below) |
| `POST /api/v1/lobbies` | an organised lobby (below); answers `lobby` |
| `GET /api/v1/lobbies/<host>/<id>` | one lobby |
| `DELETE /api/v1/lobbies/<host>/<id>` | stops it (its server gets SIGTERM): those who run it, and the player whose request made it |
| `POST /api/v1/lobbies/<host>/<id>/ops/<op>` | a control op with its fields as a JSON object, passed to the lobby server: `force_start`, `pause`, `resume`, `eject`, `set_options`, `set_player`, `allow`, `disallow`, `substitute`, `extend_timeouts`, `end`, `approve_observer`, `refuse_observer` (fields in [SWITCHES.md](SWITCHES.md) under `--control` and `--rest`). Those who run the lobby |
| `GET /api/v1/lobbies/<host>/<id>/armies` | during the game, each army's economy and units (the lobby server's `/api/v1/armies`). Those who run the lobby only: a player would see the enemy's |
| `POST /api/v1/requests` | a game the signed-in player hosts: `{"map": "scmp_007", "seats": [{"kind": "human"}, {"kind": "human", "name": "Bo"}, {"kind": "ai", "ai": "rush"}], "options": {"UnitCap": "500"}, "host": "", "region": ""}`; seat 1 is the player. Answers `request` as the host keeps it (`id`, `state`, `position`, `reason`, `lobby` with its join lines once it runs), with `ref` (`<host>/<id>`) and without its key. `403` with `player_hosting` off, `409` when no host takes players' games now |
| `GET /api/v1/requests` | the signed-in player's requests, each as the host has it now |
| `GET /api/v1/requests/<host>/<id>` | one of them |
| `DELETE /api/v1/requests/<host>/<id>` | cancels it (out of the queue, or its lobby stopped before the game) |
| `POST /api/v1/admin/reload` | reads the configuration again (admins) |
| `GET /api/v1/events[?lobby=<host>/<id>]` | Server-Sent Events, below |

### A new organised lobby

`POST /api/v1/lobbies` takes the host's lobby fields ([SERVER_DASHBOARD.md](SERVER_DASHBOARD.md), `POST /api/v1/lobbies`) and three of its own:

```json
{"tournament": "spring-cup", "host": "", "region": "eu",
 "name": "Spring Cup, semi-final 1", "map": "scmp_009",
 "seats": [{"kind": "human", "name": "Ann", "uid": 10, "team": 2, "faction": 1},
           {"kind": "human", "name": "Bo", "uid": 11, "team": 3, "faction": 3}],
 "observers": [{"uid": 20, "name": "Caster"}, {"uid": 4, "name": "Referee", "referee": true}],
 "options": {"Victory": "demoralization"}, "observer_delay_seconds": 120,
 "start_when_ready": 10, "lobby_minutes": 60, "cpus": "auto", "cores": 1}
```

- `tournament`: whose lists apply and who may run it; leave it out for a lobby outside tournaments.
- `host`: a host by name; leave it empty for the least loaded one that fits. CPUs picked by id (`"cpus": [3, 11]`) need a host.
- `region`: only hosts of this region when picking.
- Observers carry their FAF id here; the host gets their names.
- The lobby is always organised (`control` `organiser`, `kind` `tournament`): nobody hosts it, and it starts from the ops or by its countdown. `force` is for admins only; `queue` isn't taken.

### A lobby as its viewer sees it

`key`, `host`, `id`, `name`, `state` (`starting`, `lobby`, `game`, `ended`, `failed`, `stopped`), `phase`, `beat`, `kind`, `control`, `origin` (`organised` made through the service, `hosted` a player's request, `host` made on the host itself), `tournament`, `created_by` (`uid`, `name`), `map`, `options`, `seats` (`seat`, `kind`, `name`, `uid`, `ai`, `faction`, `team`), `observers` (`name`, `uid`, `referee`), `observer_delay_seconds`, `created`, `started_at`, `exit`, `status` (from the lobby server while it runs: `phase`, `host`, `beat`, `paused`, `started`, `countdown_seconds`, and each seat's `uid`, `name`, `joined`, `loaded`, `lost`, `gone`, `away`, `ping_ms`, `ready`, `slot`), `stale`, `updated`, `you` (the viewer's `seat` and `join` line, or `watch` line), `can_operate`, `can_stop`.

Those who run the lobby, and the player whose request made it, also get every seat's `join` and observer's `watch` line, the whole `status` (with each seat's mods, load and network figures) and `host_record`: the host's record as it came (CPUs, port, warnings, live use).

### Events

`GET /api/v1/events` is a Server-Sent Events stream (`EventSource` with credentials, or a bearer token from a script). Each event's `data` is one JSON object:

| Event | Data |
|---|---|
| `snapshot` | first, once: `hosts` and `lobbies` now, as the GETs give them |
| `host` | a host whose state changed (reachability, lobbies, player hosting, load by 5 points or more) |
| `host_removed` | `name`: a host taken out of the configuration |
| `lobby` | a lobby that changed, whole, as its viewer may see it |
| `lobby_removed` | `key`: a lobby the host no longer lists |
| `lobby_event` | to those who run the lobby (and the requesting player of a hosted one): `key`, `event` (the lobby server's: `joined`, `left`, `ready`, `countdown`, `launched`, `game_started`, `result`, `game_ended`, `observer_request`, `log`, ...) and its `data` |

With `?lobby=<host>/<id>` the stream carries that lobby only. A comment line every 15 s keeps proxies from closing it. A client that falls behind loses events; the next `lobby` event carries the whole lobby again, and reconnecting gives a fresh `snapshot`.

## The cache

| Key (after `key_prefix`) | Holds | Kept |
|---|---|---|
| `host:<name>` | a host's state | 2 minutes, written every poll |
| `lobby:<host>/<id>` | a lobby's state: the host's record, the lobby server's status, the service's record | 2 minutes, written every poll; removed when the host no longer lists it |
| `meta:<host>/<id>` | who made an organised lobby, for which tournament, its observers' FAF ids | 30 days |
| `request:<host>/<id>`, `myrequest:<uid>:<host>/<id>` | a player's request with its key | 7 days |
| `session:<sha-256 of the cookie>` | a signed-in user's id and name | `session_hours` |
| `login:<state>` | a sign-in in progress | 10 minutes, used once |

The channel `events` carries the changes. Roles, tournaments and hosts aren't in the cache: the configuration is their only source.

## Tests

`go test ./cmd/control-service` runs the sign-in against the mock provider (`tools/oidcmock`: public and confidential clients, a reused state, a wrong PKCE verifier, a wrong nonce, access tokens with a missing scope, another key, another issuer, expired), roles and allowlists, the host registry against fake hosts (polling, least loaded placement, a host that doesn't fit, a host that stops answering, views per viewer, ops, stopping, players' requests) and the event stream. With `CONTROL_TEST_REDIS=<host:port>` the same tests run on that Redis (each under its own key prefix, removed afterwards).
