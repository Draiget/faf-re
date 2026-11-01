# Desync test server

Collects the desync reports faf-re clients send ([docs/DESYNC_DIAGNOSTICS.md](../../docs/DESYNC_DIAGNOSTICS.md)): an OpenTelemetry Collector for the small records (`faf.desync`, `faf.game.end`) and the dump receiver ([`tools/desync-diff/receive.py`](../desync-diff/receive.py)) for the dump files, which it stores per game, compares once two players' dumps are in, and serves back for download. A dashboard ([`dashboard.py`](dashboard.py)) shows both. Nothing here names a host: the server's name is set when it is deployed.

| Path | Service | What |
|---|---|---|
| `/v1/logs` (port 4318) | collector | OTLP/HTTP log records; `Authorization: Bearer <upload token>` required; appended to `received.jsonl` (rotated at 100 MB, 20 files) |
| `POST /dumps` (port 4319) | dump receiver | one `.tar.gz` dump per request (`X-FAF-Dump: <name>`, upload token); answers 201 |
| `GET /dumps/`, `/dumps/<game id>/`, `/dumps/<game id>/<file>` | dump receiver | games, a game's files (dumps and `report.txt`, the comparison), one file; read token required (`Authorization: Bearer` or `?token=`) |
| `GET /healthz` (4319, 4320), `:13133/` | all three | health checks, no token |
| port 4320, on a name of its own | dashboard | the records and dumps in a browser (below); read token required |

Two tokens:
- **Upload token** (`FAF_UPLOAD_TOKEN`): ships with the game (`/telemetrytoken`). It only keeps casual junk out, and it can't read anything.
- **Read token** (`FAF_READ_TOKEN`): private, for the people who look at dumps and the dashboard. A dump holds player names, the beat logs and the command line (with the token and user folder names masked).

## Game side

```
/telemetry /telemetryendpoint https://<host> /telemetrytoken <upload token>
/telemetrydumpendpoint https://<host>/dumps
```

The collector URL gets `/v1/logs` appended. Each `faf.desync` record carries `faf.dump.url`, the dump's address on the receiver (`https://<host>/dumps/<game id>/<file>`; add `?token=<read token>` to open it in a browser). The Windows build posts `https://`; the Linux build posts plain `http://` only.

## Dashboard

`dashboard.py` reads what the other two wrote and never changes it: the collector's `received*.jsonl` files (the rotated ones too) and the receiver's game folders. Python 3, standard library only.

| Page | Shows |
|---|---|
| `/` | counts; per build (engine version, arch, OS): desync records, games with a desync, game ends, how many of the ended games desynced; the latest 300 records, filtered by kind, build or a search over the attributes |
| `/games` | every game in a record or a dump folder: map, record counts, dumps, whether a report exists |
| `/game/<id>` | the game's records; the switches that differ between its players (from `faf.switches`, or `faf.switches.changed` for older builds); its dumps and the comparison report; every attribute of every record |
| `/files/<id>/<dump>/` | the entries of a dump (`header.json`, `hashes.csv`, `beats/*.log`, `state.txt`, ...); one entry opens as text (the first 1 MB, `?raw=1` for all of it) |
| `/api/records` | all records as JSON |

Every page except `/healthz` asks for the read token: a login form (kept in a cookie for 30 days), `?token=<read token>` once, or `Authorization: Bearer <read token>`. The upload token doesn't open it. Attributes whose name contains `authorization` or `token` show as `<hidden>`. Run it on a name of its own, best one only reachable inside your network.

Locally, without a server: `python dashboard.py --otel <folder with received.jsonl> --dumps <receiver --out folder>`, then open `http://127.0.0.1:4320`.

## One machine: Docker Compose

```sh
cd tools/desync-server
cp .env.example .env        # set FAF_UPLOAD_TOKEN and FAF_READ_TOKEN
docker compose up -d
docker compose logs -f
```

`compose.yaml` mounts `../desync-diff/receive.py`, `desync_diff.py` and `dashboard.py` into a stock `python:3.12-slim` image and runs the contrib collector image (`otel/opentelemetry-collector-contrib:0.164.0`, for its `bearertokenauth` extension). Data stays in `data/otel` and `data/dumps`. The dashboard listens on `127.0.0.1:4320` only. Each container is capped at 1 CPU and 512 MB. The ports are plain HTTP: for players on the internet, put a TLS proxy in front (Caddy, nginx, a cloud load balancer) that forwards `/v1/logs` to 4318 and `/dumps` to 4319 and allows request bodies of 64 MB.

`docker compose down` stops it; `data/` keeps what arrived.

## Kubernetes

`k8s/desync-server.yaml` has a namespace `faf-desync`, one 10 Gi volume (all three services, by subPath; the dashboard mounts it read-only), the three Deployments with their Services, one Ingress for the two upload paths and one for the dashboard's own name. Before applying it:

```sh
kubectl apply -f k8s/desync-server.yaml --dry-run=client   # check it parses
kubectl create namespace faf-desync
kubectl -n faf-desync create secret generic faf-desync-tokens \
  --from-literal=FAF_UPLOAD_TOKEN=<upload token> --from-literal=FAF_READ_TOKEN=<read token>
kubectl -n faf-desync create configmap faf-desync-tools \
  --from-file=../desync-diff/receive.py --from-file=../desync-diff/desync_diff.py --from-file=dashboard.py
kubectl -n faf-desync create configmap faf-desync-collector --from-file=collector.yaml
sed -e 's/DASHBOARD_NAME/<dashboard host>/g' -e 's/HOST/<host>/g' k8s/desync-server.yaml | kubectl apply -f -
```

In both Ingresses, set `ingressClassName`, a cert-manager issuer (or a TLS secret) and, with external-dns, its annotations. The PersistentVolumeClaim uses the cluster's default storage class unless `storageClassName` is set. To update the receiver after a change to `receive.py`, recreate the `faf-desync-tools` ConfigMap (`--dry-run=client -o yaml | kubectl apply -f -`) and `kubectl -n faf-desync rollout restart deployment/dumps` (or `deployment/dashboard` after a change to `dashboard.py`).

## Checking a deployment

```sh
curl -X POST -H 'Content-Type: application/json' -d '{"resourceLogs":[]}' \
  -H 'Authorization: Bearer <upload token>' https://<host>/v1/logs     # 200; without the token 401
curl -H 'Authorization: Bearer <read token>' https://<host>/dumps/    # the games list
curl -H 'Authorization: Bearer <read token>' https://<dashboard host>/api/records   # the records as JSON
```

Then a real desync: `tools/scenarios/2p-desync-state.yaml` with the game-side switches above added to both players' `args`. Both clients log `Telemetry: dump desync_<id>_beat300_army<A>.tar.gz (<bytes> bytes) posted, HTTP status 201`, and `https://<host>/dumps/<id>/report.txt` names the nudged health value.
