// The dashboard's host client against a running server-host (plan WP17.13):
// node scripts/smoke-host.ts <host url> <token file> [map id]
// The machine, the maps, a cost hint, a wrong token, then a lobby: started on "auto" CPUs, its own status through the
// host's proxy once it answers, stopped, and forgotten. Exit 0 when every check passed.

import { readFileSync } from "node:fs";
import { ApiError, HostApi, type Lobby } from "../src/api.ts";

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
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

const info = await host.host();
check("host", info.cpus.length > 0, `${info.name}, ${info.cpu_model}, ${info.cpus.length} CPUs, ${info.lobbies ?? "?"} lobbies, ai ${info.ai?.length ?? 0}`);

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

const hint = await host.hint(2, map.km ?? 10);
check("hint", typeof hint.suggested_cores === "number" && hint.suggested_cores >= 1, JSON.stringify(hint));

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
});
const join = lobby.seats?.find((seat) => seat.kind === "human")?.join ?? "";
check("create", typeof lobby.id === "string" && (lobby.cpus ?? []).length > 0, `${lobby.id} ${lobby.state} on CPU ${(lobby.cpus ?? []).join(",")}, join "${join}"`);
check("join command", join.includes("/connectserver"), join);

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
  lobby = (await host.lobbies()).find((listed) => listed.id === lobby.id) ?? lobby;
  if (lobby.state === "lobby") break;
  await new Promise((resolve) => setTimeout(resolve, 250));
}
check("listed", lobby.state === "lobby", `state ${lobby.state}`);

lobby = await host.stopLobby(lobby.id);
check("stop", lobby.state === "stopped", `state ${lobby.state}`);
await host.forgetLobby(lobby.id);
const after = await host.lobbies();
check("forget", !after.some((listed) => listed.id === lobby.id), `${after.length} lobbies left`);

console.log(failed === 0 ? "HOST SMOKE PASSED" : `HOST SMOKE FAILED (${failed})`);
process.exit(failed === 0 ? 0 : 1);
