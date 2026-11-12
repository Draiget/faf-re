// The dashboard's host client against a running server-host (plan WP17.13, WP17.16-WP17.20):
// node scripts/smoke-host.ts <host url> <token file> [map id]
// The machine with its NUMA nodes and links, a wrong token, the maps, a cost hint, the planner (auto, by hand across
// nodes, an unknown CPU), a lobby refused without force, then a lobby with an observer and a referee: started on "auto"
// CPUs, each watcher's watch line back, its own status through the host's proxy, its nodes, warnings and usage listed,
// stopped and forgotten. The settings catalog and open slots are checked when the host has them (SKIP on 404): two
// slots on Auto on different CPUs held on the host, a claim view with the code alone (no token), a wrong code (404), a
// claim with a human and an AI (join line, slot claimed with its lobby), a second claim (409), then both freed, which
// stops the claimed game and makes the code answer 404.
// Exit 0 when every check passed.

import { readFileSync } from "node:fs";
import { ApiError, ClaimApi, HostApi, type Lobby, type PlacementWarning, type Plan, type Slot } from "../src/api.ts";

const [url, tokenFile, mapArg] = process.argv.slice(2);
if (!url || !tokenFile) {
  console.error("usage: node scripts/smoke-host.ts <host url> <token file> [map id]");
  process.exit(2);
}
const host = new HostApi(url, readFileSync(tokenFile, "utf8").trim());
let failed = 0;
function check(name: string, ok: boolean, detail: string): void {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail.slice(0, 240)}`);
  failed += ok ? 0 : 1;
}
function skip(name: string, detail: string): void {
  console.log(`SKIP ${name}: ${detail}`);
}
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const isNum = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
const SEVERITIES = new Set(["info", "warn", "error"]);
const wellFormed = (warnings: PlacementWarning[]): boolean => warnings.every((warning) => typeof warning.code === "string" && SEVERITIES.has(warning.severity) && typeof warning.text === "string" && warning.text !== "");

const info = await host.host();
check("host", info.cpus.length > 0, `${info.name}, ${info.cpu_model}, ${info.cpus.length} CPUs, ${info.lobbies ?? "?"} lobbies, ai ${info.ai?.length ?? 0}`);

// Topology (WP17.16): every CPU in exactly one node, and its own `node` says the same.
const nodes = info.nodes ?? [];
const listed = nodes.flatMap((node) => node.cpus);
const nodeOf = new Map(nodes.flatMap((node) => node.cpus.map((cpu): [number, number] => [cpu, node.id])));
check(
  "nodes",
  nodes.length > 0 && listed.length === info.cpus.length && new Set(listed).size === listed.length && info.cpus.every((cpu) => isNum(cpu.node) && nodeOf.get(cpu.id) === cpu.node),
  nodes.map((node) => `node ${node.id}: ${node.cpus.length} CPUs, ${node.memory_mb?.free ?? "?"}/${node.memory_mb?.total ?? "?"} MB free`).join("; "),
);
check("node memory", nodes.every((node) => isNum(node.memory_mb?.total) && (node.memory_mb?.total ?? 0) > 0 && isNum(node.memory_mb?.free)), JSON.stringify(nodes.map((node) => node.memory_mb)));
const links = info.links ?? [];
check("links", Array.isArray(info.links) && links.every((link) => typeof link.name === "string" && isNum(link.in_kbps) && isNum(link.out_kbps)), JSON.stringify(links));

try {
  await new HostApi(url, "wrong-token-wrong-token").host();
  check("wrong token", false, "no error");
} catch (error) {
  check("wrong token", error instanceof ApiError && error.status === 401, String(error));
}

const maps = await host.maps();
const map = maps.find((candidate) => candidate.id === mapArg) ?? maps.find((candidate) => (candidate.players ?? 0) >= 2) ?? maps[0];
check("maps", maps.length > 0 && map !== undefined, `${maps.length} maps; using ${map?.id} (${map?.km} km, ${map?.players} players)`);
if (map === undefined) process.exit(1);
const km = map.km ?? 10;

const hint = await host.hint(2, km);
check("hint", typeof hint.suggested_cores === "number" && hint.suggested_cores >= 1, JSON.stringify(hint));

// The planner (WP17.17): nothing is started.
const planText = (plan: Plan): string => `cpus ${plan.cpus.join(",")} nodes ${plan.nodes.join(",")} fits ${plan.fits} warnings ${plan.warnings.map((warning) => `${warning.severity}:${warning.code}`).join(",") || "none"}`;
const auto = await host.plan({ players: 2, km });
const est = auto.estimate;
check(
  "plan auto",
  isNum(est.suggested_cores) && est.suggested_cores >= 1 && isNum(est.memory_mb) && isNum(est.upload_kbps) && isNum(est.min_connection_kbps) && auto.cpus.length === auto.cores && auto.cores >= 1 && auto.nodes.length >= 1 && wellFormed(auto.warnings),
  `${planText(auto)}; estimate ${JSON.stringify({ ...est, basis: undefined })}`,
);
check("plan auto stays on its CPUs' nodes", auto.cpus.every((cpu) => auto.nodes.includes(nodeOf.get(cpu) ?? -1)), planText(auto));
const [nodeA, nodeB] = nodes;
if (nodeA !== undefined && nodeB !== undefined && nodeA.cpus.length > 0 && nodeB.cpus.length > 0) {
  const across = await host.plan({ players: 2, km, cpus: [nodeA.cpus[0] ?? 0, nodeB.cpus[0] ?? 0] });
  check("plan by hand across nodes", across.cpus.length === 2 && across.nodes.length === 2 && across.warnings.some((warning) => warning.code === "spans_nodes"), planText(across));
} else {
  skip("plan by hand across nodes", "one NUMA node");
}
const unknown = await host.plan({ players: 2, km, cpus: [99999] });
check("plan with an unknown CPU", !unknown.fits && unknown.warnings.some((warning) => warning.severity === "error"), planText(unknown));

// An error-level placement is refused without force (409, with the reasons).
const refusedBody = {
  name: "dashboard smoke (refused)",
  map: map.id,
  options: {},
  seats: [{ kind: "human" as const, name: "Smoke", faction: 1, team: 2 }],
  control: "organiser" as const,
  start_when_ready: 0,
  lobby_minutes: 5,
  cpus: [99999],
};
try {
  const made = await host.createLobby(refusedBody);
  check("refused without force", false, `made ${made.id}`);
  await host.stopLobby(made.id).catch(() => undefined);
  await host.forgetLobby(made.id).catch(() => undefined);
} catch (error) {
  check("refused without force", error instanceof ApiError && (error.status === 409 || error.status === 400), String(error));
}

let lobby: Lobby = await host.createLobby({
  name: "dashboard smoke",
  map: map.id,
  options: { Victory: "demoralization", Share: "FullShare", UnitCap: "1000", FogOfWar: "explored", GameSpeed: "normal", CheatsEnabled: "false" },
  seats: [
    { kind: "human", name: "Smoke", faction: 1, team: 2 },
    { kind: "ai", ai: "adaptive", faction: 2, team: 3 },
  ],
  control: "organiser",
  start_when_ready: 0,
  lobby_minutes: 5,
  cpus: "auto",
  cores: 1,
  observers: [{ name: "Caster" }, { name: "Ref", referee: true }],
  observer_delay_seconds: 30,
});
const join = lobby.seats?.find((seat) => seat.kind === "human")?.join ?? "";
check("create", typeof lobby.id === "string" && (lobby.cpus ?? []).length > 0, `${lobby.id} ${lobby.state} on CPU ${(lobby.cpus ?? []).join(",")}, join "${join}"`);
check("join command", join.includes("/connectserver"), join);

/** The observer and the referee came back with their names, roles and a watch line each: `/replay gpgnet://host:port/<32 hex>`. */
function checkObservers(name: string, item: Lobby): void {
  const watchLine = /^\/replay gpgnet:\/\/[^\s/:]+:(\d+)\/[0-9a-f]{32}$/;
  const list = item.observers ?? [];
  const caster = list.find((observer) => observer.name === "Caster");
  const referee = list.find((observer) => observer.name === "Ref");
  const ports = new Set(list.map((observer) => watchLine.exec(observer.watch ?? "")?.[1]));
  const ok =
    list.length === 2 &&
    caster !== undefined &&
    caster.referee !== true &&
    referee?.referee === true &&
    list.every((observer) => watchLine.test(observer.watch ?? "")) &&
    typeof item.observe_port === "number" &&
    ports.size === 1 &&
    ports.has(String(item.observe_port)) &&
    item.observer_delay_seconds === 30;
  check(name, ok, `observe_port ${item.observe_port}, delay ${item.observer_delay_seconds}, ${JSON.stringify(list)}`);
}
checkObservers("observers on create", lobby);

const deadline = Date.now() + 30000;
let phase = "";
while (Date.now() < deadline) {
  try {
    phase = (await host.lobbyApi(lobby.id).status()).phase;
    break;
  } catch {
    await sleep(500); // the lobby's server is still starting
  }
}
check("lobby status through the host", phase === "lobby", `phase "${phase}"`);
// The host reads each lobby's own status every 0.5 s while it starts, so its list may lag the proxy a little.
for (let tries = 0; tries < 12; tries++) {
  lobby = (await host.lobbies()).find((item) => item.id === lobby.id) ?? lobby;
  if (lobby.state === "lobby") break;
  await new Promise((resolve) => setTimeout(resolve, 250));
}
check("listed", lobby.state === "lobby", `state ${lobby.state}`);
checkObservers("observers listed", lobby);
const lobbyNodes = lobby.nodes ?? [];
check(
  "lobby placement",
  lobbyNodes.length >= 1 && (lobby.cpus ?? []).every((cpu) => lobbyNodes.includes(nodeOf.get(cpu) ?? -1)) && Array.isArray(lobby.warnings) && wellFormed(lobby.warnings ?? []),
  `cpus ${(lobby.cpus ?? []).join(",")} nodes ${lobbyNodes.join(",")} warnings ${JSON.stringify(lobby.warnings)}`,
);
// Usage is sampled every 2 s: give it one round.
await sleep(2500);
lobby = (await host.lobbies()).find((item) => item.id === lobby.id) ?? lobby;
check("lobby usage", isNum(lobby.usage?.cpu_cores) && isNum(lobby.usage?.rss_mb) && (lobby.usage?.rss_mb ?? 0) > 0, JSON.stringify(lobby.usage));

lobby = await host.stopLobby(lobby.id);
check("stop", lobby.state === "stopped", `state ${lobby.state}`);
await host.forgetLobby(lobby.id);
const after = await host.lobbies();
check("forget", !after.some((item) => item.id === lobby.id), `${after.length} lobbies left`);

// The settings catalog (WP17.20), once the host has it.
try {
  const settings = await host.settings();
  const options = settings.options;
  check(
    "settings",
    options.length > 0 &&
      options.every((option) => typeof option.key === "string" && option.values.length > 0 && option.values.some((value) => String(value.key) === String(option.default)) && typeof option.group === "string" && option.group !== "") &&
      settings.ai.length > 0 &&
      settings.map_options.length === 0,
    `${options.length} options (${[...new Set(options.map((option) => option.group))].map((group) => `${group} ${options.filter((option) => option.group === group).length}`).join(", ")}), ${settings.ai.length} AIs`,
  );
  const adaptive = maps.find((candidate) => /adaptive/i.test(candidate.id));
  if (adaptive !== undefined) {
    const own = await host.settings(adaptive.id);
    check("map options", own.map_options.length > 0 && own.map_options.every((option) => option.values.some((value) => String(value.key) === String(option.default))), `${adaptive.id}: ${own.map_options.map((option) => option.key).join(", ")}`);
  } else {
    skip("map options", "no adaptive map on this host");
  }
} catch (error) {
  if (error instanceof ApiError && error.status === 404) skip("settings", "the host has no /api/v1/settings yet");
  else check("settings", false, String(error));
}

// Open slots (WP17.18), once the host has them: two slots on Auto, a player's claim of one with the claim code alone
// (no token), then both freed, which stops the claimed one's game.
let slotsSupported = true;
try {
  await host.slots();
} catch (error) {
  if (error instanceof ApiError && error.status === 404) {
    slotsSupported = false;
    skip("slots", "the host has no /api/v1/slots yet");
  } else {
    check("slots", false, String(error));
  }
}
if (slotsSupported) {
  const made: Slot[] = [];
  let claimedLobby = "";
  try {
    const before = await host.slots();
    made.push(...(await host.createSlots({ name: "dashboard smoke slot", max_players: 2, km: 10, lobby_minutes: 5, count: 2 })));
    check(
      "slots create",
      made.length === 2 && made.every((slot) => slot.state === "open" && typeof slot.claim_code === "string" && slot.claim_code !== "" && (slot.cpus ?? []).length >= 1 && (slot.nodes ?? []).length >= 1 && slot.km === 10 && slot.max_players === 2 && slot.reopen === true && slot.games === 0),
      JSON.stringify(made.map((slot) => ({ id: slot.id, state: slot.state, cpus: slot.cpus, nodes: slot.nodes, km: slot.km, reopen: slot.reopen, games: slot.games, claim: slot.claim_code }))),
    );
    const [first, second] = made;
    const firstCpus = first?.cpus ?? [];
    const secondCpus = second?.cpus ?? [];
    check("slots on different CPUs", firstCpus.length > 0 && secondCpus.length > 0 && !firstCpus.some((cpu) => secondCpus.includes(cpu)), `${firstCpus.join(",")} / ${secondCpus.join(",")}`);
    const machine = await host.host();
    const heldOn = (slot: Slot): boolean => (slot.cpus ?? []).every((cpu) => machine.cpus.find((item) => item.id === cpu)?.lobbies?.includes(slot.id) === true);
    check("slots held on the host's CPUs", made.every(heldOn), made.map((slot) => `${slot.id}: ${(slot.cpus ?? []).map((cpu) => `${cpu}=[${(machine.cpus.find((item) => item.id === cpu)?.lobbies ?? []).join(",")}]`).join(" ")}`).join("; "));
    const held = await host.plan({ players: 2, km, cpus: firstCpus });
    check("planner counts a slot's CPUs as taken", held.warnings.some((warning) => warning.code === "shared_cpu"), planText(held));
    const listedSlots = await host.slots();
    check("slots listed", made.every((slot) => listedSlots.some((item) => item.id === slot.id)) && listedSlots.length === before.length + 2, `${listedSlots.length} slots`);

    // The claim API takes the code as its credential: ClaimApi sends no Authorization header.
    const claimApi = new ClaimApi(url, first?.claim_code ?? "");
    const openView = await claimApi.view();
    check("claim view without a token", openView.slot.id === first?.id && openView.slot.state === "open" && openView.lobby === null && openView.slot.max_players === 2 && openView.slot.km === 10, JSON.stringify(openView));
    try {
      await new ClaimApi(url, "0123456789abcdef").view();
      check("claim with a wrong code", false, "no error");
    } catch (error) {
      check("claim with a wrong code", error instanceof ApiError && error.status === 404, String(error));
    }
    const claimMaps = await claimApi.maps();
    const claimMap = claimMaps.find((candidate) => candidate.id === mapArg && (candidate.players ?? 0) >= 2) ?? claimMaps.find((candidate) => (candidate.players ?? 0) >= 2);
    check("claim maps", claimMap !== undefined && claimMaps.length === maps.length, `${claimMaps.length} maps; using ${claimMap?.id} (${claimMap?.km} km, ${claimMap?.players} spots)`);
    if (claimMap !== undefined) {
      const claimed = await claimApi.claim({ player: "Smoke", map: claimMap.id, seats: [{ kind: "human" }, { kind: "ai", ai: "rush" }], options: { Victory: "sandbox" } });
      const claimedSeats = claimed.lobby?.seats ?? [];
      const hostSeat = claimedSeats.find((seat) => seat.seat === 1);
      claimedLobby = claimed.lobby?.id ?? "";
      check(
        "claim",
        claimed.lobby !== null && claimedSeats.length === 2 && hostSeat?.kind === "human" && hostSeat.name === "Smoke" && (hostSeat.join ?? "").includes("/connectserver") && claimedSeats.some((seat) => seat.kind === "ai" && seat.ai === "rush") && String(claimed.lobby.options?.Victory) === "sandbox",
        `lobby ${claimed.lobby?.id} ${claimed.lobby?.state} on ${claimed.lobby?.map?.id}, seats ${JSON.stringify(claimedSeats.map((seat) => ({ seat: seat.seat, kind: seat.kind, name: seat.name, ai: seat.ai, join: seat.join })))}, Victory ${String(claimed.lobby?.options?.Victory)}`,
      );
      const afterClaim = (await host.slots()).find((slot) => slot.id === first?.id);
      check("slot listed as claimed", afterClaim !== undefined && (afterClaim.state === "claimed" || afterClaim.state === "lobby") && afterClaim.lobby === claimedLobby && claimedLobby !== "" && afterClaim.host_player === "Smoke" && afterClaim.games === 1, JSON.stringify(afterClaim));
      const claimedListed = (await host.lobbies()).find((item) => item.id === claimedLobby);
      check("claimed lobby listed with its slot", claimedListed?.slot === first?.id && claimedListed?.control === "player", `slot ${claimedListed?.slot}, control ${claimedListed?.control}`);
      try {
        await claimApi.claim({ player: "Smoke again", map: claimMap.id });
        check("second claim refused", false, "no error");
      } catch (error) {
        check("second claim refused", error instanceof ApiError && error.status === 409, String(error));
      }
      const again = await claimApi.view();
      check("claim view shows the lobby", again.lobby?.id === claimedLobby && (again.lobby?.seats ?? []).length === 2, `${again.slot.state}, lobby ${again.lobby?.id} ${again.lobby?.state}`);
    } else {
      skip("claim", "no map with 2 or more start spots");
    }

    for (const slot of made) await host.deleteSlot(slot.id);
    let stoppedState = claimedLobby === "" ? "none" : "";
    if (claimedLobby !== "") {
      const stopDeadline = Date.now() + 15000;
      while (Date.now() < stopDeadline) {
        stoppedState = (await host.lobbies()).find((item) => item.id === claimedLobby)?.state ?? "gone";
        if (stoppedState === "stopped" || stoppedState === "ended" || stoppedState === "gone") break;
        await sleep(500);
      }
      check("freeing a claimed slot stops its game", stoppedState === "stopped" || stoppedState === "ended", `lobby ${claimedLobby} ${stoppedState}`);
      await host.forgetLobby(claimedLobby).catch(() => undefined);
    }
    const left = await host.slots();
    check("slots freed", !made.some((slot) => left.some((item) => item.id === slot.id)), `${left.length} slots left`);
    try {
      await claimApi.view();
      check("freed slot's code stops working", false, "no error");
    } catch (error) {
      check("freed slot's code stops working", error instanceof ApiError && error.status === 404, String(error));
    }
  } catch (error) {
    check("slots", false, String(error));
    // Whatever was made is freed, so a failed run doesn't leave CPUs held.
    for (const slot of made) await host.deleteSlot(slot.id).catch(() => undefined);
    if (claimedLobby !== "") await host.forgetLobby(claimedLobby).catch(() => undefined);
  }
}

console.log(failed === 0 ? "HOST SMOKE PASSED" : `HOST SMOKE FAILED (${failed})`);
process.exit(failed === 0 ? 0 : 1);
