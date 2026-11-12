// The dashboard's host client against a running server-host: node scripts/smoke-host.ts <host url> <token file> [map id]
// The machine with its NUMA nodes and links, a wrong token, the maps (start spots, previews without a token), a hint,
// the planner on both sides (auto, by hand across nodes, an unknown CPU), a lobby refused without force, a lobby that
// doesn't fit queued and cancelled, then a tournament lobby with an observer and a referee: its kind and side, its own
// status through the proxy, its log (tail and stream), metrics with its series, the host's log, stopped and removed.
// Then player hosting: the pool saved and restored around the checks, a one-core pool with room for one more game and open access, the public
// pool, maps and settings, a player's request (started, with a join line), a second one queued behind it (listed in
// the queue with its request, moved, cancelled), a duplicate refused, a wrong key, the first cancelled, and the pool
// turned off (public maps refused). Exit 0 when every check passed. Leaves the pool as it found it.

import { readFileSync } from "node:fs";
import { ApiError, HostApi, RequestApi, type GameRequest, type Lobby, type PlacementWarning, type Plan, type Pool, type PoolUpdate } from "../src/api.ts";

const [url, tokenFile, mapArg] = process.argv.slice(2);
if (!url || !tokenFile) {
  console.error("usage: node scripts/smoke-host.ts <host url> <token file> [map id]");
  process.exit(2);
}
const host = new HostApi(url, readFileSync(tokenFile, "utf8").trim());
const pub = new RequestApi(url);
let failed = 0;
function check(name: string, ok: boolean, detail: string): void {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail.slice(0, 260)}`);
  failed += ok ? 0 : 1;
}
function skip(name: string, detail: string): void {
  console.log(`SKIP ${name}: ${detail}`);
}
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const isNum = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
const SEVERITIES = new Set(["info", "warn", "error"]);
const wellFormed = (warnings: PlacementWarning[]): boolean => warnings.every((warning) => typeof warning.code === "string" && SEVERITIES.has(warning.severity) && typeof warning.text === "string" && warning.text !== "");
async function status(promise: Promise<unknown>): Promise<number> {
  try {
    await promise;
    return 200;
  } catch (error) {
    return error instanceof ApiError ? error.status : -1;
  }
}
async function until<T>(read: () => Promise<T>, done: (value: T) => boolean, ms: number): Promise<T> {
  const deadline = Date.now() + ms;
  let value = await read();
  while (!done(value) && Date.now() < deadline) {
    await sleep(500);
    value = await read();
  }
  return value;
}

// ---------------------------------------------------------------- the machine
const info = await host.host();
check("host", info.cpus.length > 0, `${info.name}, ${info.cpu_model}, ${info.cpus.length} CPUs, ${info.lobbies ?? "?"} lobbies`);
const nodes = info.nodes ?? [];
const listed = nodes.flatMap((node) => node.cpus);
const nodeOf = new Map(nodes.flatMap((node) => node.cpus.map((cpu): [number, number] => [cpu, node.id])));
check("nodes", nodes.length > 0 && listed.length === info.cpus.length && new Set(listed).size === listed.length && info.cpus.every((cpu) => isNum(cpu.node) && nodeOf.get(cpu.id) === cpu.node), nodes.map((node) => `node ${node.id}: ${node.cpus.length} CPUs`).join("; "));
check("links", Array.isArray(info.links) && (info.links ?? []).every((link) => typeof link.name === "string" && isNum(link.in_kbps) && isNum(link.out_kbps)), JSON.stringify(info.links));
check("wrong token", (await status(new HostApi(url, "wrong-token-wrong-token").host())) === 401, "401 expected");

// ---------------------------------------------------------------- maps and previews
const maps = await host.maps();
const map = maps.find((candidate) => candidate.id === mapArg) ?? maps.find((candidate) => (candidate.players ?? 0) >= 2) ?? maps[0];
check("maps", maps.length > 0 && map !== undefined, `${maps.length} maps; using ${map?.id} (${map?.km} km, ${map?.players} players)`);
if (map === undefined) process.exit(1);
const km = map.km ?? 10;
const spawnsOk = maps.filter((candidate) => Array.isArray(candidate.spawns) && candidate.spawns.length > 0);
check(
  "maps: start spots",
  spawnsOk.length > 0 && spawnsOk.every((candidate) => (candidate.spawns ?? []).every((spot) => spot.length === 2 && spot.every((value) => isNum(value) && value >= 0 && value <= 1))),
  `${spawnsOk.length} of ${maps.length} maps with spots; ${map.id}: ${JSON.stringify(map.spawns)}`,
);
const withPreview = maps.find((candidate) => typeof candidate.preview === "string" && candidate.preview !== "");
if (withPreview !== undefined) {
  const address = host.previewUrl(withPreview) ?? "";
  const response = await fetch(address); // no token: an <img> loads it as is
  const bytes = new Uint8Array(await response.arrayBuffer());
  check("preview without a token", response.ok && (response.headers.get("content-type") ?? "").includes("png") && bytes[0] === 0x89 && bytes[1] === 0x50, `${address}: HTTP ${response.status}, ${bytes.length} bytes`);
  const none = await fetch(`${url}/api/v1/maps/no-such-map-here/preview.png`);
  check("preview of an unknown map", none.status === 404, `HTTP ${none.status}`);
} else {
  skip("preview", "no map with a preview");
}

const hint = await host.hint(2, km);
check("hint", isNum(hint.suggested_cores) && hint.suggested_cores >= 1, JSON.stringify(hint));

// ---------------------------------------------------------------- the planner
const planText = (plan: Plan): string => `cpus ${plan.cpus.join(",")} nodes ${plan.nodes.join(",")} fits ${plan.fits} warnings ${plan.warnings.map((warning) => `${warning.severity}:${warning.code}`).join(",") || "none"}`;
const auto = await host.plan({ players: 2, km });
check("plan auto", isNum(auto.estimate.suggested_cores) && isNum(auto.estimate.memory_mb) && auto.cores >= 1 && auto.nodes.length >= 1 && auto.cpus.every((cpu) => auto.nodes.includes(nodeOf.get(cpu) ?? -1)) && wellFormed(auto.warnings), planText(auto));
const [nodeA, nodeB] = nodes;
if (nodeA !== undefined && nodeB !== undefined && nodeA.cpus.length > 0 && nodeB.cpus.length > 0) {
  const across = await host.plan({ players: 2, km, cpus: [nodeA.cpus[0] ?? 0, nodeB.cpus[0] ?? 0] });
  check("plan by hand across nodes", across.nodes.length === 2 && across.warnings.some((warning) => warning.code === "spans_nodes"), planText(across));
} else {
  skip("plan by hand across nodes", "one NUMA node");
}
const unknown = await host.plan({ players: 2, km, cpus: [99999] });
check("plan with an unknown CPU", !unknown.fits && unknown.warnings.some((warning) => warning.severity === "error"), planText(unknown));

const seats = [{ kind: "human" as const, name: "Smoke", faction: 1, team: 2, seat: 1 }];
check("an unknown CPU is refused", (await status(host.createLobby({ name: "dashboard smoke (refused)", map: map.id, options: {}, seats, control: "organiser", start_when_ready: 0, lobby_minutes: 5, cpus: [99999] }))) === 400, "400 expected: a CPU the machine lacks is a bad request, which force cannot override");

// ---------------------------------------------------------------- the operator queue: a lobby that can't fit now
try {
  const queued = await host.createLobby({ name: "dashboard smoke (queued)", map: map.id, kind: "tournament", options: {}, seats, control: "organiser", start_when_ready: 0, lobby_minutes: 5, cpus: "auto", cores: info.cpus.length * 4, queue: true });
  const item = queued.queued;
  check("queued when it doesn't fit", queued.lobby === null && item !== null && item.side === "operator" && isNum(item.position) && item.position >= 1 && typeof item.waiting_for === "string", JSON.stringify(item));
  if (item !== null) {
    const listedQueue = await host.queue();
    check("queue lists it", listedQueue.some((other) => other.id === item.id && other.side === "operator"), `${listedQueue.length} queued`);
    await host.cancelQueued(item.id);
    check("queue cancel", !(await host.queue()).some((other) => other.id === item.id), "gone");
  } else if (queued.lobby !== null) {
    await host.stopLobby(queued.lobby.id).catch(() => undefined);
    await host.forgetLobby(queued.lobby.id).catch(() => undefined);
  }
} catch (error) {
  check("queued when it doesn't fit", false, String(error));
}

// ---------------------------------------------------------------- a tournament lobby: kind, proxy, log, metrics
const created = await host.createLobby({
  name: "dashboard smoke",
  map: map.id,
  kind: "tournament",
  options: { Victory: "demoralization", UnitCap: "1000" },
  seats: [
    { kind: "human", name: "Smoke", faction: 1, team: 2, seat: 1 },
    { kind: "ai", ai: "adaptive", faction: 2, team: 3, seat: 2 },
  ],
  control: "organiser",
  start_when_ready: 0,
  lobby_minutes: 5,
  cpus: "auto",
  cores: 1,
  observers: [{ name: "Caster" }, { name: "Ref", referee: true }],
  observer_delay_seconds: 30,
});
let lobby: Lobby | null = created.lobby;
check("create", lobby !== null && (lobby.cpus ?? []).length > 0, `${lobby?.id} ${lobby?.state} on CPU ${(lobby?.cpus ?? []).join(",")}`);
if (lobby !== null) {
  const id = lobby.id;
  check("kind and side", lobby.kind === "tournament" && (lobby.side === undefined || lobby.side === "operator") && (lobby.request ?? null) === null, `kind ${lobby.kind}, side ${lobby.side}, request ${lobby.request}`);
  check("join line", (lobby.seats ?? []).some((seat) => seat.kind === "human" && (seat.join ?? "").includes("/connectserver")), JSON.stringify(lobby.seats?.map((seat) => seat.join)));
  check("watch lines", (lobby.observers ?? []).length === 2 && (lobby.observers ?? []).every((observer) => /^\/replay gpgnet:\/\//.test(observer.watch ?? "")), JSON.stringify(lobby.observers));
  let phase = "";
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      phase = (await host.lobbyApi(id).status()).phase;
      break;
    } catch {
      await sleep(500);
    }
  }
  check("lobby status through the host", phase === "lobby", `phase "${phase}"`);
  lobby = (await until(() => host.lobbies(), (list) => list.find((item) => item.id === id)?.state === "lobby", 6000)).find((item) => item.id === id) ?? lobby;
  check("listed", lobby.state === "lobby" && typeof lobby.started_at === "string", `state ${lobby.state}, started ${lobby.started_at}`);

  const lines = await host.lobbyLog(id, 200);
  check("lobby log", lines.length > 0 && lines.every((line) => typeof line.text === "string"), `${lines.length} lines; last: ${lines.at(-1)?.text ?? ""}`);
  {
    const controller = new AbortController();
    let opened = false;
    const stream = host.lobbyLogStream(id, () => undefined, controller.signal, () => (opened = true)).catch(() => undefined);
    await sleep(1500);
    controller.abort();
    await stream;
    check("lobby log stream opens", opened, opened ? "open" : "didn't open");
  }
  await sleep(2500); // a metrics sample every 2 s
  const metrics = await host.metrics(120);
  const n = metrics.t.length;
  check(
    "metrics",
    n > 0 && metrics.cpu.length === n && metrics.mem_used_mb.length === n && Object.keys(metrics.nodes).length === nodes.length && Object.values(metrics.net).every((link) => link.in_kbps.length === n),
    `${n} samples, ${Object.keys(metrics.net).length} links, ${Object.keys(metrics.nodes).length} nodes, lobbies ${Object.keys(metrics.lobbies).join(",")}`,
  );
  check("metrics: the lobby's series", (metrics.lobbies[id]?.cpu_cores ?? []).some((value) => value !== null), JSON.stringify(metrics.lobbies[id]?.cpu_cores.slice(-3)));
  const hostLines = await host.hostLog(100);
  check("host log", hostLines.length > 0 && hostLines.some((line) => line.text.includes(id)), `${hostLines.length} lines; mentions ${id}: ${hostLines.some((line) => line.text.includes(id))}`);
  {
    const controller = new AbortController();
    let opened = false;
    const stream = host.hostLogStream(() => undefined, controller.signal, () => (opened = true)).catch(() => undefined);
    await sleep(1000);
    controller.abort();
    await stream;
    check("host log stream opens", opened, opened ? "open" : "didn't open");
  }
  lobby = await host.stopLobby(id);
  check("stop", lobby.state === "stopped", `state ${lobby.state}`);
  check("log after it ended", (await host.lobbyLog(id, 50)).length > 0, "still there");
  await host.forgetLobby(id);
  check("forget", !(await host.lobbies()).some((item) => item.id === id), "gone");
}

// ---------------------------------------------------------------- settings
const settings = await host.settings();
check("settings", settings.options.length > 0 && settings.ai.length > 0 && settings.options.every((option) => option.values.some((value) => String(value.key) === String(option.default))), `${settings.options.length} options, ${settings.ai.length} AIs`);

// ---------------------------------------------------------------- player hosting: pool, public API, requests, queue
let original: Pool | null = null;
let runningGames = 0;
let queuedRequests = 0;
try {
  const view = await host.pool();
  original = view.pool;
  // Games already on the pool and requests already waiting count against its limits: room is made for one more game.
  runningGames = view.usage.games;
  queuedRequests = view.usage.queued;
  check("pool", Array.isArray(view.pool.cpus) && isNum(view.usage.games) && isNum(view.usage.free_cores), JSON.stringify(view));
} catch (error) {
  check("pool", false, String(error));
}
if (original !== null) {
  const made: GameRequest[] = [];
  try {
    // One whole core of the least busy node as the pool, one game at once, open access.
    const node = nodes[nodes.length - 1] ?? nodes[0];
    const core = info.cpus.find((cpu) => cpu.id === node?.cpus[node.cpus.length - 1]);
    const coreCpus = info.cpus.filter((cpu) => cpu.core === core?.core && cpu.node === core?.node).map((cpu) => cpu.id);
    const maxGames = runningGames + 1;
    const set = await host.setPool({ enabled: true, cpus: coreCpus, max_games: maxGames, max_players: 4, cores: 1, access: "open", max_queue: queuedRequests + 5, lobby_minutes: 5, options: { UnitCap: "1500" } });
    check("pool save", set.pool.enabled && set.pool.cpus.length === coreCpus.length && set.pool.max_games === maxGames && String(set.pool.options.UnitCap) === "1500", `${JSON.stringify(set.pool)} warnings ${JSON.stringify(set.warnings)}`);
    const poolPlan = await host.plan({ players: 2, km, side: "pool" });
    check("plan on the pool's side", poolPlan.cpus.every((cpu) => coreCpus.includes(cpu)), planText(poolPlan));
    const operatorPlan = await host.plan({ players: 2, km, side: "operator" });
    check("Auto keeps off the pool", !operatorPlan.cpus.some((cpu) => coreCpus.includes(cpu)), planText(operatorPlan));

    const publicPool = await pub.pool();
    check("public pool", publicPool.enabled && publicPool.access === "open" && publicPool.max_players === 4 && publicPool.queue.max_games === maxGames, JSON.stringify(publicPool));
    const publicMaps = await pub.maps();
    const small = publicMaps.find((candidate) => (candidate.players ?? 0) >= 2 && (candidate.km ?? 99) <= 10) ?? publicMaps.find((candidate) => (candidate.players ?? 0) >= 2);
    check("public maps", publicMaps.length === maps.length && small !== undefined, `${publicMaps.length} maps; using ${small?.id}`);
    const publicPreview = publicMaps.find((candidate) => candidate.preview);
    if (publicPreview !== undefined) {
      const response = await fetch(pub.previewUrl(publicPreview) ?? "");
      check("public preview", response.ok, `HTTP ${response.status}`);
    }
    check("public settings", (await pub.settings(small?.id)).options.length > 0, "listed");
    if (small !== undefined) {
      const first = await pub.create({ player: "Smoke A", map: small.id, seats: [{ kind: "human", seat: 1 }, { kind: "ai", ai: "adaptive", seat: 2, team: 3 }], options: { Victory: "sandbox" } });
      made.push(first);
      check("request", typeof first.key === "string" && first.key !== "" && ["queued", "starting", "lobby"].includes(first.state), JSON.stringify({ ...first, key: first.key ? "(set)" : first.key }));
      const key = first.key ?? "";
      const followed = await until(() => pub.get(first.id, key), (request) => request.state === "lobby" || request.state === "refused", 30000);
      check("request becomes a lobby", followed.state === "lobby" && (followed.lobby?.seats ?? []).some((seat) => seat.kind === "human" && (seat.join ?? "").includes("/connectserver")), `${followed.state}, lobby ${followed.lobby?.id}`);
      const asLobby = (await host.lobbies()).find((item) => item.id === followed.lobby?.id);
      check("the lobby is on the pool", asLobby !== undefined && asLobby.request === first.id && (asLobby.side === undefined || asLobby.side === "pool") && (asLobby.cpus ?? []).every((cpu) => coreCpus.includes(cpu)), `request ${asLobby?.request}, side ${asLobby?.side}, cpus ${(asLobby?.cpus ?? []).join(",")}`);
      check("the pool's own options", String(asLobby?.options?.UnitCap) === "1500" && String(asLobby?.options?.Victory) === "sandbox", JSON.stringify(asLobby?.options));
      check("duplicate refused", (await status(pub.create({ player: "Smoke A", map: small.id, seats: [{ kind: "human", seat: 1 }] }))) === 409, "409 expected");
      check("wrong key", (await status(pub.get(first.id, "wrong-key"))) === 404, "404 expected");

      const second = await pub.create({ player: "Smoke B", map: small.id, seats: [{ kind: "human", seat: 1 }] });
      made.push(second);
      check("second request queued", second.state === "queued" && second.position === queuedRequests + 1, JSON.stringify({ state: second.state, position: second.position }));
      const third = await pub.create({ player: "Smoke C", map: small.id, seats: [{ kind: "human", seat: 1 }] });
      made.push(third);
      const queue = await host.queue();
      const items = queue.filter((item) => item.side === "pool");
      const itemOf = (request: GameRequest) => items.find((item) => item.request === request.id || item.player === (request.player ?? ""));
      check("queue lists the requests", itemOf(second)?.position === queuedRequests + 1 && itemOf(third)?.position === queuedRequests + 2 && typeof itemOf(second)?.waiting_for === "string", JSON.stringify(items.map((item) => ({ id: item.id, request: item.request, position: item.position, waiting_for: item.waiting_for }))));
      const thirdItem = itemOf(third);
      if (thirdItem !== undefined) {
        await host.moveUp(thirdItem.id);
        const moved = (await host.queue()).find((item) => item.id === thirdItem.id);
        check("move up", moved?.position === queuedRequests + 1, `position ${moved?.position}`);
        await host.cancelQueued(thirdItem.id);
        const after = await pub.get(third.id, third.key ?? "");
        check("operator cancel reaches the player", after.state === "cancelled" || after.state === "refused", `${after.state}: ${after.reason}`);
      }
      const cancelled = await pub.cancel(first.id, key);
      check("player cancel", cancelled.state === "cancelled" || cancelled.state === "ended", cancelled.state);
      // With the first gone, the second starts on the pool (once nothing queued before it fits first).
      const next = await until(() => pub.get(second.id, second.key ?? ""), (request) => request.state !== "queued", 30000);
      check("the queue moves", next.state === "starting" || next.state === "lobby", `${next.state}`);
      await pub.cancel(second.id, second.key ?? "").catch(() => undefined);
    } else {
      skip("requests", "no public map with 2 or more spots");
    }
    const off = await host.setPool({ enabled: false, drop_queue: true });
    check("pool off", !off.pool.enabled, JSON.stringify(off.usage));
    check("public maps refused while off", (await status(pub.maps())) === 403, "403 expected");
    check("requests refused while off", (await status(pub.create({ player: "Smoke D", map: map.id, seats: [{ kind: "human", seat: 1 }] }))) === 403, "403 expected");
  } catch (error) {
    check("player hosting", false, String(error));
  } finally {
    for (const request of made) await pub.cancel(request.id, request.key ?? "").catch(() => undefined);
    const restore: PoolUpdate = { enabled: original.enabled, cpus: original.cpus, max_games: original.max_games, max_players: original.max_players, cores: original.cores, lobby_minutes: original.lobby_minutes, access: original.access, code: original.code, options: original.options, max_queue: original.max_queue };
    try {
      const back = await host.setPool(restore);
      check("pool restored", back.pool.enabled === original.enabled && JSON.stringify([...back.pool.cpus].sort()) === JSON.stringify([...original.cpus].sort()), JSON.stringify(back.pool));
    } catch (error) {
      check("pool restored", false, String(error));
    }
  }
}

console.log(failed === 0 ? "HOST SMOKE PASSED" : `HOST SMOKE FAILED (${failed})`);
process.exit(failed === 0 ? 0 : 1);
