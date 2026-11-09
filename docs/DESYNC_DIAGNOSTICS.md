# Desync diagnostics

A desync is a multiplayer game whose players' sims stop agreeing: every 50 beats by default (one beat is one 100 ms sim tick) each client hashes its game state and sends the hash to the others, and a hash that differs from a client's own is a desync. The engine has three aids for finding out why. The recorder is on by default in live multiplayer games; telemetry only with the player's consent (`/telemetry`, #337):

| Aid | What it does | Issue | Switches |
|---|---|---|---|
| Desync recorder | On by default in live multiplayer: keeps the state each beat hashes for the recent beats in memory, copied as bytes (`/nodesyncdump` turns it off). After a mismatch it writes `desync_<game id>_beat<N>_army<A>.zip` into the folder of the game's log file (`/log`; the working folder without it); the log names the folder at game start. `/desyncrecorder` records the full sync log instead, call trace included, at a sim-time cost | #216 | [Desync recorder](SWITCHES.md#desync-recorder) |
| `tools/cmd/desync-diff` | Compares two players' dumps and prints the first value that differs: beat, entity, field; also the desync server's dump receiver | #217 | [README](../tools/cmd/desync-diff/README.md) |
| Desync telemetry | Off unless the player agreed: `/telemetry` on the command line, which the FAF client passes (#337); `/notelemetry` turns it off and wins. With it, a live multiplayer game sends one small record per desync and one per game end to the faf-re desync server's OpenTelemetry collector, and uploads the dump as `.tar.gz` to its dump receiver; the switches point both at a server of your own | #218 | [Desync telemetry](SWITCHES.md#desync-telemetry) |

This page is the setup side: what reaches the servers, how to run them, and how to check it works. Every field and switch is listed in [SWITCHES.md](SWITCHES.md#desync-telemetry). A ready server with both parts, for Docker Compose or Kubernetes, is [tools/desync-server](../tools/desync-server/README.md).

## What the servers receive

Two servers, both optional:

- **OpenTelemetry collector** (records): OTLP/HTTP JSON log records, `POST <telemetry_Endpoint>/v1/logs`. No player names, FAF user ids, command line, file paths or dump contents.
- **Dump receiver** (files): one `POST <telemetry_DumpEndpoint>` per dump, body a `.tar.gz` with the same files as the local zip, header `X-FAF-Dump: desync_<game id>_beat<N>_army<A>.tar.gz`. A dump holds player names, the sync log and the command line, with the token shown as `<token>` and the user's folder in `\Users\<name>\` and `/home/<name>/` paths as `<user>`.

Both get `Authorization: Bearer <telemetry_Token>` when a token is set. The token ships with the game, so it only keeps casual junk out.

A `faf.desync` record from a test game (`tools/scenarios/2p-desync-dump-upload.yaml`, client 1 nudged one unit's health at beat 300), attributes only:

```json
{
  "faf.game.id": "424242", "faf.game.version": "3835", "faf.map": "faf_re_lockstep",
  "faf.game.mods_md5": "fba282cd5faca1f7619e4b7969a27f66", "faf.checksum_period": "50",
  "faf.players": "2", "faf.army.local": "0", "faf.sim.workers": "0", "faf.sse2": false,
  "faf.switches.hash": "4ac2958328f7dd61d7fedfc3d585d2ed", "faf.switches.changed": "sim_DesyncRecorder=1",
  "faf.desync.beat": "300", "faf.desync.last_agreed_beat": "250", "faf.desync.delay_beats": "4",
  "faf.hash.local": "9333968e601bd1ec605902120867e932", "faf.hash.remote": "6b5be1abbd4ac492166c7c9b23a1f247",
  "faf.army.remote": "1", "faf.desync.players_disagreeing": "1", "faf.desync.players_reported": "2",
  "faf.fpu.x87_control": "0x0000", "faf.fpu.mxcsr": "0x00001f80", "faf.orders_altered": false,
  "faf.dump.file": "desync_424242_beat300_army0.zip", "faf.dump.bytes": "1226486",
  "faf.dump.upload": "desync_424242_beat300_army0.tar.gz",
  "faf.dump.url": "https://dumps.example.org/dumps/424242/desync_424242_beat300_army0.tar.gz"
}
```

`faf.dump.url` is the dump endpoint plus `/<game id>/<file>`, where `desync-diff serve` serves the stored file (with the read token).

Every request also carries the process as the OTLP resource: `service.name` `faf-engine`, `service.version` (the commit), `faf.engine.version`, `faf.engine.dirty`, `host.arch`, `faf.arch`, `os.type`, `os.description`, `faf.cpu.logical_count`. A `faf.game.end` record follows at the end of every game, desync or not, with `faf.game.beats`, `faf.desync` and `faf.desync.later_records`. Records of one game pair up by `faf.game.id`; a record pairs with its uploaded dump by `faf.dump.upload`.

## Collector

Any OpenTelemetry Collector with an OTLP/HTTP receiver takes the records. The core distribution is enough; the local tests ran `otelcol` 0.164.0 for Windows from the [collector releases](https://github.com/open-telemetry/opentelemetry-collector-releases/releases) (`otelcol_<version>_windows_amd64.tar.gz`).

`collector.yaml` that prints every record and appends it to a file:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318        # 127.0.0.1:4318 for local tests only
        include_metadata: true        # keeps the Authorization header for the processor below

processors:
  attributes/token:                   # optional: record which token a request came with
    actions:
      - key: received.authorization
        from_context: metadata.authorization
        action: insert
  batch: {}

exporters:
  debug:
    verbosity: detailed               # each record on the collector's console
  file:
    path: ./received.jsonl            # one OTLP JSON request per line

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/token, batch]
      exporters: [debug, file]
```

Run it: `otelcol --config collector.yaml`. To keep the records somewhere searchable, add an exporter for your backend (for example `otlphttp` to Grafana Loki, or any OTLP-compatible log store) to the `logs` pipeline.

With Docker, the same file mounted as the image's config (not run in this repository's tests):

```sh
docker run -d --name faf-otel -p 4318:4318 \
  -v "$PWD/collector.yaml:/etc/otelcol/config.yaml" -v "$PWD/data:/data" \
  otel/opentelemetry-collector:0.164.0
```

with `path: /data/received.jsonl` in the `file` exporter, so the file lands in `./data` on the host.

The core collector does not check the token. To refuse requests without it, put the collector behind a reverse proxy that checks `Authorization`, or use the contrib distribution (`otel/opentelemetry-collector-contrib`) with its `bearertokenauth` extension on the receiver, as [tools/desync-server/collector.yaml](../tools/desync-server/collector.yaml) does: a request without the token or with a wrong one gets 401.

HTTPS: the Windows build posts `https://` URLs through WinHTTP; the Linux build posts plain `http://` only. A public collector normally sits behind a reverse proxy that terminates TLS and forwards to port 4318.

## Dump receiver

`desync-diff serve` ([tools/cmd/desync-diff](../tools/cmd/desync-diff/README.md), Go with the standard library only; `tools/build.ps1` builds it into `tools/bin`) is the receiver:

```sh
desync-diff serve --host 0.0.0.0 --port 4319 --prefix /dumps --out /srv/faf-dumps \
  --token <upload token> --read-token <read token> --max-mb 64
```

| Option | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Address to listen on |
| `--port` | `4319` | Port |
| `--prefix` | `/dumps` | Path the dumps are read under; uploads are taken at any path |
| `--out` | `received-dumps` | Storage folder; each dump goes to `<out>/<game id>/<name>.tar.gz` |
| `--token` | `FAF_UPLOAD_TOKEN` | Required `Authorization: Bearer` token for uploads; empty accepts any |
| `--read-token` | `FAF_READ_TOKEN` | Required token for reads (`Authorization: Bearer` or `?token=`); empty lets anyone read |
| `--max-mb` | 64 | Largest body accepted |

Uploads: 201 to a stored dump (with its path), 401 to a wrong token, 400 to a name that isn't a dump name or a body that isn't a dump (`header.json` missing from the archive), 413 to an empty or oversized body. Once a game has dumps from two armies, it compares them and writes `<out>/<game id>/report.txt`: the report `desync-diff compare A B` prints for dumps on disk. Reads: `GET <prefix>/` lists the games, `<prefix>/<game id>/` a game's dumps and report, `<prefix>/<game id>/<file>` downloads one; the upload token never reads, since it ships with the game. `GET /healthz` answers `ok` without a token. It has no TLS: for a public server, run it behind a reverse proxy that terminates TLS ([tools/desync-server](../tools/desync-server/README.md)). The engine posts to the URL as given; with `--prefix` equal to that URL's path, `faf.dump.url` points at the stored file.

The client deletes its `.tar.gz` once the receiver answers 2xx, after six failed attempts (when queued, with the game-end record, then at up to four later starts), or at once on a 4xx other than 408 and 429. The zip stays on the player's disk either way.

## Game side

Without `/telemetry` on its command line a game sends nothing: no records, no dump (#337). With it, a live multiplayer game sends its records to `https://fafre-metrics.draiget.dev/v1/logs` and its dump to `https://fafre-metrics.draiget.dev/dumps` (the Linux build posts plain `http://`: it has no TLS library), the faf-re desync server behind Cloudflare. `/notelemetry` sends nothing, even with `/telemetry`. To use a server of your own, add to the game's command line (or set the switches in the console):

```
/telemetryendpoint https://collector.example.org /telemetrytoken <token>
/telemetrydumpendpoint https://dumps.example.org/dumps
```

The token is this client's alone (#336): the launcher passes it, and no other player may see it. It never reaches the game log, the replay or the dump (whose copy of the command line shows `/telemetrytoken <token>`), and Lua never gets it: `GetCommandLineArg('/telemetrytoken', n)` answers `false`, and the values of an option given before it end before it.

The first line moves the records. The second moves the dump the recorder writes (an empty URL uploads none); the recorder is on by default in live multiplayer, and with `/nodesyncdump` there is no dump to upload. `/v1/logs` is appended to the collector URL unless it already ends with it. Records and dumps are only sent from live multiplayer games, never from replays.

The game log shows it working:

```
Telemetry: on, endpoint https://collector.example.org
Telemetry: dumps go to https://dumps.example.org/dumps
Desync recorder: wrote ...\desync_424242_beat300_army0.zip (1226486 bytes)
Desync recorder: wrote ...\desync_424242_beat300_army0.tar.gz (766498 bytes) for upload
Telemetry: dump desync_424242_beat300_army0.tar.gz (766498 bytes) posted, HTTP status 201
Telemetry: 2 record(s) sent, 0 dropped, 0 kept for a retry (last HTTP status 201)
```

What isn't sent yet waits in `faf_telemetry_outbox_<pid>.txt` next to the game log and goes out with the next record or at the next start.

## Checking a setup locally

Two scenarios run a real two-player desync against local servers (`tools/mpemu`, see [tools/README.md](../tools/README.md)): start the collector on `127.0.0.1:4318` and, for the second, `desync-diff serve --port 4319 --token test-token`, then

```bat
tools\bin\mpemu.exe run tools\scenarios\2p-desync-telemetry.yaml
tools\bin\mpemu.exe run tools\scenarios\2p-desync-dump-upload.yaml
```

Both expect the build staged as `bin_x64\desync_test.exe`. The first checks the records; the second also checks that both clients post their `.tar.gz` with HTTP 201, after which the receiver holds both dumps of game 424242 and a `report.txt` naming the nudged field (`beat 300 ... field: health`).
