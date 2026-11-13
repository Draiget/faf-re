// The dashboard's control-service client against a running control service, the calls its pages make:
//   node scripts/smoke-control.ts <service url> <admin token file> [--organiser <uid> --player <uid>] [--origin <web UI origin>]
// With the admin token: health, a request without credentials refused, who the token is, the hosts and the lobbies.
// With --organiser and --player (only against tools/cmd/oidc-mock, whose authorize step takes ?login_as=<uid>): both
// sign in through the service's /auth/login, then the organiser reads a host's maps, settings, plan and a preview,
// makes an organised lobby of a tournament they organise with the player and another listed player in it, and the
// checks follow it as each sees it: the organiser gets every join line and may run it; the player gets their own line
// only, may not run it, read its armies or make a lobby, and their event stream carries no other seat's line; an
// unlisted player is refused; the lobby is stopped. Exit 0 when every check passed. Leaves a stopped lobby behind.

import { readFileSync } from "node:fs";
import { ApiError } from "../src/api.ts";
import { ControlApi, type ServiceLobby } from "../src/control.ts";

const args = process.argv.slice(2);
const [url, tokenFile] = args;
const option = (name: string): string | undefined => {
  const at = args.indexOf(`--${name}`);
  return at < 0 ? undefined : args[at + 1];
};
if (!url || !tokenFile) {
  console.error("usage: node scripts/smoke-control.ts <service url> <admin token file> [--organiser <uid> --player <uid>] [--origin <web UI origin>]");
  process.exit(2);
}
const base = url.replace(/\/+$/, "");
const origin = option("origin") ?? base;
const admin = new ControlApi(base, { token: readFileSync(tokenFile, "utf8").trim() });
let failed = 0;
function check(name: string, ok: boolean, detail: string): void {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail.slice(0, 260)}`);
  failed += ok ? 0 : 1;
}
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
async function status(promise: Promise<unknown>): Promise<number> {
  try {
    await promise;
    return 200;
  } catch (error) {
    return error instanceof ApiError ? error.status : -1;
  }
}
const lines = (lobby: ServiceLobby): number => lobby.seats.filter((seat) => typeof seat.join === "string" && seat.join !== "").length;

// ---------------------------------------------------------------- without signing in, and the admin token
const health = await new ControlApi(base).health();
check("health", health.ok && typeof health.store === "string", JSON.stringify(health));
check("no credentials", (await status(new ControlApi(base).me())) === 401, "401 expected");
const adminMe = await admin.me();
check("admin token", adminMe.user.via === "admin_token" && adminMe.roles.includes("admin"), JSON.stringify(adminMe.user));
const hosts = await admin.hosts();
check("hosts", hosts.length > 0 && hosts.every((host) => typeof host.name === "string" && typeof host.reachable === "boolean"), hosts.map((host) => `${host.name} ${host.reachable ? `load ${host.load ?? "?"}%` : "not answering"}`).join("; "));
const all = await admin.lobbies();
check("lobbies", all.every((lobby) => lobby.key === `${lobby.host}/${lobby.id}`), `${all.length} lobbies, ${all.filter((lobby) => ["starting", "lobby", "game"].includes(lobby.state)).length} running`);

// ---------------------------------------------------------------- signed in as an organiser and a player (the mock provider)
/** The authorization-code flow through the mock provider, the user picked at its authorize step: the session cookie. */
async function signIn(uid: string): Promise<string> {
  const login = await fetch(`${base}/auth/login?return=/api/v1/me`, { redirect: "manual" });
  const authorize = login.headers.get("location");
  if (authorize === null) throw new Error(`/auth/login answered ${login.status} without a redirect`);
  const back = await fetch(`${authorize}&login_as=${encodeURIComponent(uid)}`, { redirect: "manual" });
  const callback = back.headers.get("location");
  if (callback === null) throw new Error(`the provider answered ${back.status} without a redirect`);
  const done = await fetch(callback, { redirect: "manual" });
  const cookie = done.headers.getSetCookie().find((line) => line.startsWith("faf_control_session="));
  if (cookie === undefined) throw new Error(`the callback answered ${done.status} without a session`);
  return cookie.split(";")[0] ?? "";
}

const organiserUid = option("organiser");
const playerUid = option("player");
if (organiserUid !== undefined && playerUid !== undefined) {
  const organiserCookie = await signIn(organiserUid);
  const organiser = new ControlApi(base, { cookie: organiserCookie, origin });
  const player = new ControlApi(base, { cookie: await signIn(playerUid), origin });
  const me = await organiser.me();
  const pme = await player.me();
  check("organiser signed in", me.user.uid === Number(organiserUid) && me.user.via === "session" && me.roles.includes("organiser"), `${me.user.name} (FAF ${me.user.uid}): ${me.roles.join(", ")}`);
  check("player signed in", pme.user.uid === Number(playerUid) && !pme.roles.includes("organiser"), `${pme.user.name} (FAF ${pme.user.uid}): ${pme.roles.join(", ")}`);
  const playerHosts = await player.hosts();
  check("a player sees no machines", playerHosts.every((host) => host.machine === undefined && host.load === undefined), JSON.stringify(playerHosts[0] ?? {}));
  check("a player reads no host's maps", (await status(player.hostApi(hosts[0]?.name ?? "").maps())) === 403, "403 expected");

  const tournament = me.tournaments.find((item) => Array.isArray(item.players) && item.players.includes(Number(playerUid)));
  const listed = (tournament?.players ?? []).filter((uid) => uid !== Number(playerUid));
  const host = hosts.filter((item) => item.reachable).sort((a, b) => (a.load ?? 0) - (b.load ?? 0))[0];
  if (tournament === undefined || listed.length === 0 || host === undefined) {
    check("a tournament with the player and another listed player, and a host", false, JSON.stringify(me.tournaments.map((item) => item.id)));
  } else {
    // The create form's reads, from the least loaded host.
    const reads = organiser.hostApi(host.name);
    const maps = await reads.maps();
    const map = maps.find((item) => typeof item.preview === "string" && (item.players ?? 0) >= 2) ?? maps[0];
    check("host maps", maps.length > 0 && map !== undefined, `${host.name}: ${maps.length} maps; using ${map?.id}`);
    const settings = await reads.settings(map?.id);
    check("host settings", settings.options.length > 0, `${settings.options.length} options, ${settings.ai.length} AIs, ${settings.map_options.length} map options`);
    const plan = await reads.plan({ players: 2, km: map?.km ?? 10, side: "operator" });
    check("host plan", typeof plan.fits === "boolean", `fits ${plan.fits}, ${plan.cores} cores, CPU ${plan.cpus.join(",")}, ${plan.warnings.length} warnings`);
    const preview = map === undefined ? null : reads.previewUrl(map);
    if (preview !== null) {
      const image = await fetch(preview, { headers: { Cookie: organiserCookie } });
      check("map preview", image.ok && (image.headers.get("content-type") ?? "").startsWith("image/png"), `${image.status} ${image.headers.get("content-type")}`);
    }

    // Refusals: a player making a lobby, an unlisted player in a seat.
    const seats = [
      { kind: "human" as const, seat: 1, name: "Smoke A", uid: Number(playerUid), faction: 1, team: 2 },
      { kind: "human" as const, seat: 2, name: "Smoke B", uid: listed[0] ?? 0, faction: 3, team: 3 },
    ];
    check("a player can't make a lobby", (await status(player.createLobby({ tournament: tournament.id, name: "smoke", map: map?.id ?? "", seats }))) === 403, "403 expected");
    check("an unlisted player is refused", (await status(organiser.createLobby({ tournament: tournament.id, name: "smoke", map: map?.id ?? "", seats: [{ ...seats[0], uid: 987654321 }] }))) === 400, "400 expected");

    // The organised lobby, on the least loaded host that fits.
    const made = await organiser.createLobby({ tournament: tournament.id, name: "Control smoke", map: map?.id ?? "", seats, start_when_ready: 0, lobby_minutes: 5, cpus: "auto", cores: 1 });
    check("created", made.origin === "organised" && made.tournament === tournament.id && made.can_operate && lines(made) === 2, `${made.key} on ${made.host}: ${made.state}, ${lines(made)} join lines`);
    // The service lists it from its next look at the host (every poll_seconds).
    const read = (): Promise<ServiceLobby | null> => organiser.lobby(made.key).catch((error: unknown) => (error instanceof ApiError && error.status === 404 ? null : Promise.reject(error)));
    let seen = await read();
    for (let i = 0; i < 30 && seen?.state !== "lobby"; i++) {
      await sleep(1000);
      seen = await read();
    }
    if (seen === null) throw new Error(`the service never listed ${made.key}`);
    check("its lobby opens", seen.state === "lobby" && typeof seen.status?.phase === "string", `${seen.state}, status phase ${seen.status?.phase}`);
    check("the organiser sees it whole", lines(seen) === 2 && seen.host_record !== undefined && seen.host_record !== null && seen.can_stop, `${lines(seen)} join lines, host record ${seen.host_record ? "yes" : "no"}`);

    // As the player sees it.
    const mine = await player.lobby(made.key);
    const ownLine = mine.you?.join ?? "";
    check("the player's own line", mine.you?.seat === 1 && ownLine !== "", `seat ${mine.you?.seat}, line ${ownLine.slice(0, 30)}…`);
    check("no other line for the player", lines(mine) === 0 && !mine.can_operate && !mine.can_stop && (mine.host_record ?? null) === null, `${lines(mine)} join lines, can_operate ${mine.can_operate}, host record ${mine.host_record ? "yes" : "no"}`);
    const statusKeys = Object.keys((mine.status?.seats ?? [])[0] ?? {}).sort();
    check("the player's status is the public part", statusKeys.every((key) => ["uid", "name", "joined", "loaded", "lost", "gone", "away", "ping_ms", "ready", "slot"].includes(key)), statusKeys.join(","));
    check("the player can't run it", (await status(player.op(made.key, "force_start"))) === 403, "403 expected");
    check("the player can't read its armies", (await status(player.armies(made.key))) === 403, "403 expected");
    const otherLine = seen.seats.find((seat) => seat.uid !== Number(playerUid))?.join ?? "";
    const stream = new AbortController();
    let streamed = "";
    const events: string[] = [];
    const reading = player
      .events(
        (name, data) => {
          events.push(name);
          streamed += JSON.stringify(data);
        },
        stream.signal,
        undefined,
        made.key,
      )
      .catch(() => undefined);
    await sleep(500);
    const answer = await organiser.op(made.key, "pause");
    check("an op round trip", typeof answer.ok === "boolean", JSON.stringify(answer).slice(0, 120));
    await sleep(3000);
    stream.abort();
    await reading;
    check("the player's stream", events[0] === "snapshot" && !events.includes("lobby_event") && otherLine !== "" && !streamed.includes(otherLine) && streamed.includes(ownLine), `${events.length} events (${[...new Set(events)].join(", ")}); another seat's line ${streamed.includes(otherLine) ? "PRESENT" : "absent"}`);
    const requests = await player.requests();
    check("the player's requests", Array.isArray(requests), `${requests.length} requests`);

    // Stopped by the organiser.
    await organiser.stopLobby(made.key);
    let after = await organiser.lobby(made.key);
    for (let i = 0; i < 20 && after.state !== "stopped"; i++) {
      await sleep(1000);
      after = await organiser.lobby(made.key);
    }
    check("stopped", after.state === "stopped", after.state);
  }
  await player.logout();
  check("signed out", (await status(player.me())) === 401, "401 after logout");
  await organiser.logout();
}

console.log(failed === 0 ? "all checks passed" : `${failed} checks failed`);
process.exit(failed === 0 ? 0 : 1);
