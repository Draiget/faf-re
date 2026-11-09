# Desync test server

Collects the desync reports faf-re clients send ([docs/DESYNC_DIAGNOSTICS.md](../../docs/DESYNC_DIAGNOSTICS.md)): an OpenTelemetry Collector for the small records (`faf.desync`, `faf.game.end`) and the dump receiver (`desync-diff serve`, [`tools/cmd/desync-diff`](../cmd/desync-diff/README.md), Go with the standard library only) for the dump files, which it stores per game, compares once two players' dumps are in, and serves back for download. Nothing here names a host: the server's name is set when it is deployed.

| Path | Service | What |
|---|---|---|
| `/v1/logs` (port 4318) | collector | OTLP/HTTP log records; `Authorization: Bearer <upload token>` required; appended to `received.jsonl` (rotated at 100 MB, 20 files) |
| `POST /dumps` (port 4319) | dump receiver | one `.tar.gz` dump per request (`X-FAF-Dump: <name>`, upload token); answers 201 |
| `GET /dumps/`, `/dumps/<game id>/`, `/dumps/<game id>/<file>` | dump receiver | games, a game's files (dumps and `report.txt`, the comparison), one file; read token required (`Authorization: Bearer` or `?token=`) |
| `GET /healthz` (4319), `:13133/` | both | health checks, no token |

Two tokens:
- **Upload token** (`FAF_UPLOAD_TOKEN`): ships with the game (`/telemetrytoken`). It only keeps casual junk out, and it can't read anything.
- **Read token** (`FAF_READ_TOKEN`): private, for the people who look at dumps. A dump holds player names, the beat logs and the command line (with the token and user folder names masked).

## Game side

```
/telemetryendpoint https://<host> /telemetrytoken <upload token>
/telemetrydumpendpoint https://<host>/dumps
```

The collector URL gets `/v1/logs` appended. Each `faf.desync` record carries `faf.dump.url`, the dump's address on the receiver (`https://<host>/dumps/<game id>/<file>`; add `?token=<read token>` to open it in a browser). The Windows build posts `https://`; the Linux build posts plain `http://` only.

## One machine: Docker Compose

```sh
cd tools/desync-server
cp .env.example .env        # set FAF_UPLOAD_TOKEN and FAF_READ_TOKEN
docker compose up -d
docker compose logs -f
```

`compose.yaml` mounts `../cmd/desync-diff` into a stock `golang:1.25.5-alpine` image, which builds the receiver at start (the build cache stays in `data/gocache`), and runs the contrib collector image (`otel/opentelemetry-collector-contrib:0.164.0`, for its `bearertokenauth` extension). Data stays in `data/otel` and `data/dumps`. Each container is capped at 1 CPU and 512 MB. The ports are plain HTTP: for players on the internet, put a TLS proxy in front (Caddy, nginx, a cloud load balancer) that forwards `/v1/logs` to 4318 and `/dumps` to 4319 and allows request bodies of 64 MB.

`docker compose down` stops it; `data/` keeps what arrived.

## Kubernetes

`k8s/desync-server.yaml` has a namespace `faf-desync`, one 10 Gi volume (both services, by subPath), the two Deployments with their Services, and one Ingress for both paths. The receiver's pod builds it from its Go sources in a ConfigMap (an init container with `golang:1.25.5-alpine`) and runs it in `alpine:3.22.2`, so no image has to be built or pushed. Before applying it:

```sh
kubectl apply -f k8s/desync-server.yaml --dry-run=client   # check it parses
kubectl create namespace faf-desync
kubectl -n faf-desync create secret generic faf-desync-tokens \
  --from-literal=FAF_UPLOAD_TOKEN=<upload token> --from-literal=FAF_READ_TOKEN=<read token>
kubectl -n faf-desync create configmap faf-desync-diff --from-file=../cmd/desync-diff/
kubectl -n faf-desync create configmap faf-desync-collector --from-file=collector.yaml
sed 's/HOST/<host>/g' k8s/desync-server.yaml | kubectl apply -f -
```

In the Ingress, set `ingressClassName`, a cert-manager issuer (or a TLS secret) and, with external-dns, its annotations. The PersistentVolumeClaim uses the cluster's default storage class unless `storageClassName` is set. To update the receiver after a change to its sources, recreate the `faf-desync-diff` ConfigMap (`--dry-run=client -o yaml | kubectl apply -f -`) and `kubectl -n faf-desync rollout restart deployment/dumps`.

## Checking a deployment

```sh
curl -X POST -H 'Content-Type: application/json' -d '{"resourceLogs":[]}' \
  -H 'Authorization: Bearer <upload token>' https://<host>/v1/logs     # 200; without the token 401
curl -H 'Authorization: Bearer <read token>' https://<host>/dumps/    # the games list
```

Then a real desync: `tools/scenarios/2p-desync-state.yaml` with the game-side switches above added to both players' `args`. Both clients log `Telemetry: dump desync_<id>_beat300_army<A>.tar.gz (<bytes> bytes) posted, HTTP status 201`, and `https://<host>/dumps/<id>/report.txt` names the nudged health value.
