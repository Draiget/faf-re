// The dashboard's lobby client against a lobby of a running server-host, through the host's proxy, as the page reaches
// it: node scripts/smoke.ts <host url> <token file> <lobby id>
// Status, a refused op, a wrong token, then the event stream while force_start starts the game (the lobby must be one
// the organiser starts, still in its lobby). Exit 0 when every check passed.

import { readFileSync } from "node:fs";
import { ApiError, HostApi, type ServerEvent } from "../src/api.ts";

const [url, tokenFile, lobbyId] = process.argv.slice(2);
if (!url || !tokenFile || !lobbyId) {
  console.error("usage: node scripts/smoke.ts <host url> <token file> <lobby id>");
  process.exit(2);
}
const host = new HostApi(url, readFileSync(tokenFile, "utf8").trim());
const api = host.lobbyApi(lobbyId);
let failed = 0;
function check(name: string, ok: boolean, detail: string): void {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail.slice(0, 200)}`);
  failed += ok ? 0 : 1;
}

const listed = (await host.lobbies()).find((lobby) => lobby.id === lobbyId);
check("lobby listed", listed !== undefined, listed === undefined ? `no lobby ${lobbyId} on the host` : `${listed.name} ${listed.state}, control ${listed.control}`);

const status = await api.status();
check("status", status.ok && typeof status.phase === "string", `phase ${status.phase}, ${status.seats?.length ?? 0} seats`);

const refused = await api.op("launch_missiles");
check("refused op", !refused.ok && typeof refused.error === "string", JSON.stringify(refused));

try {
  await new HostApi(url, "wrong-token-wrong-token").lobbyApi(lobbyId).status();
  check("wrong token", false, "no error");
} catch (error) {
  check("wrong token", error instanceof ApiError && error.status === 401, String(error));
}

const seen: ServerEvent[] = [];
const controller = new AbortController();
const streaming = api.events((event) => seen.push(event), controller.signal).catch(() => undefined);
await new Promise((resolve) => setTimeout(resolve, 500));
const started = await api.op("force_start");
check("force_start", started.ok, JSON.stringify(started));
const deadline = Date.now() + 15000;
while (Date.now() < deadline && !seen.some((event) => event.event === "game_started")) {
  await new Promise((resolve) => setTimeout(resolve, 200));
}
controller.abort();
await streaming;
const names = [...new Set(seen.map((event) => event.event))];
check("event stream", names.includes("game_started"), `events seen: ${names.join(", ")}`);
const after = await api.status();
check("status in game", after.phase === "game", `phase ${after.phase}, beat ${after.beat}`);

console.log(failed === 0 ? "DASHBOARD SMOKE PASSED" : `DASHBOARD SMOKE FAILED (${failed})`);
process.exit(failed === 0 ? 0 : 1);
