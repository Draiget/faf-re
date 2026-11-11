# Running a dedicated server with the dashboard

How to run the dedicated server (`server`, Linux only) with its REST API, and the web dashboard (`tools/dashboard`) that drives it: watch the lobby or game, start it, pause it, eject, set options, follow the events.

## 1. Build the server

On Linux, with the pinned toolchain (see [README.md](../README.md)):

```
cmake --preset linux-clang-x64-release
cmake --build --preset linux-clang-x64-release --target server faf_server_probe
```

Both land in `build/linux-clang-x64-release/`: `server`, and `faf_server_probe`, a test player. The server reads the game data from a folder laid out as `--data` describes in [SWITCHES.md](SWITCHES.md).

## 2. Make an admin token

The REST API answers only requests that carry this token. Keep it in a file readable by the server's user only; it is never given on the command line, which every user of the machine can read.

```
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > admin.token
chmod 600 admin.token
```

## 3. Start the server

A match file describes the game: map, options, the players' seats (`OwnerID` and `MatchTokens`) and any AIs; see the server section of [SWITCHES.md](SWITCHES.md). Then:

```
server --match match.lua --out game --data /path/to/data \
  --listen 0.0.0.0:27185 --join-seconds 600 --lobby-seconds 600 \
  --rest 127.0.0.1:27181 --rest-token-file admin.token --rest-cors-origin http://localhost:5173
```

- `--listen` is where players' games connect (`/connectserver host:port` with `/serveruid` and `/servertoken`).
- `--lobby-seconds` keeps the lobby open that long, or until it is started.
- `--rest` serves the API at `http://<ip:port>/api/v1`; `--rest-cors-origin` names the one web origin whose pages may call it (the dashboard's address).

The console says `REST API on http://127.0.0.1:27181/api/v1 (admin token required; ...)`. Check it from the same machine:

```
curl -H "Authorization: Bearer $(cat admin.token)" http://127.0.0.1:27181/api/v1/status
```

To see a seat taken without a game client, sit a test player in it: `faf_server_probe --server 127.0.0.1:27185 --uid 1001 --token <its MatchTokens entry> --lobby-name Probe --no-decode --seconds 3600`.

## 4. Run the dashboard

```
cd tools/dashboard
npm ci
npm run dev
```

Open `http://localhost:5173` (the origin given to `--rest-cors-origin`, exactly: `http://127.0.0.1:5173` is another origin and the browser refuses it), enter the REST address and the token, and press Connect. The table shows each seat; the buttons send the control ops, and the answer (or the server's reason for refusing) appears under them; the event list shows what happens.

For a fixed page, `npm run build` writes it to `tools/dashboard/dist/`; serve that folder from the origin you give `--rest-cors-origin`.

## 5. Reaching it from another machine

The API is plain HTTP, so the token travels in the clear. Bind `--rest` to `127.0.0.1` and put a TLS proxy in front of it for anything reached over a network, for example Caddy:

```
dash.example.org {
    reverse_proxy /api/* 127.0.0.1:27181
    root * /srv/dashboard/dist
    file_server
}
```

with `--rest-cors-origin https://dash.example.org` (page and API from one origin need no CORS at all, but it does no harm). On a trusted LAN, binding `--rest` to the LAN address works without a proxy.

## API

| Request | Does |
|---|---|
| `GET /api/v1/status` | the lobby or the game: phase, host, beat, paused, and each seat (`uid`, `name`, `joined`, `loaded`, `lost`, `gone`, `away`, `ping_ms`, `ready`, `slot`) |
| `POST /api/v1/ops/<op>` | a control op with its fields as a JSON object: `force_start`, `pause`, `resume`, `eject` (`uid`, `reason`), `set_options` (`options`: `"Key=Value,..."`), `set_player` (`uid`, `options`), `allow` / `disallow` (`address`), `substitute` (`uid`, `token`, `name`), `extend_timeouts` (`uid`, `count`), `end` (`results`: `"1=victory,2=defeat"`, `reason`) |
| `GET /api/v1/events` | Server-Sent Events: `joined`, `left`, `away`, `back`, `host`, `ready`, `launched`, `game_started`, `result`, `stats`, `game_ended`, `content`, and every console line as `log` |

Every request carries `Authorization: Bearer <token>`. Answers are `200 {"ok": true, ...}`, or `400 {"ok": false, "error": "..."}` when the server refuses the op (with its reason), `401` for a missing or wrong token, `404` for an unknown path. The details of each op are in [SWITCHES.md](SWITCHES.md) under `--control` and `--rest`.

## When it doesn't work

- **401** in the dashboard: the token differs from the file's (spaces and line ends at its end are dropped).
- **The page can't reach the API** (the browser's console shows a CORS error): the page's address isn't exactly the `--rest-cors-origin` origin, scheme and port included.
- **No answer at all**: `--rest` is bound to `127.0.0.1` and the page runs on another machine, or a firewall closes the port.
- **An op is refused**: the answer says why, for example `GameSpeed is set before the lobby opens; the match file has it` (the match file pins it).
