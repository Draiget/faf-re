// The APIs the pages talk to: a machine's server-host (HostApi: the machine, maps, the planner, lobbies, the player
// hosting pool, the queue, metrics and logs), each lobby's own server through the host's proxy (ServerApi: status,
// the armies of a running game, control ops, the event stream; docs/SWITCHES.md `--rest`), and the public request API
// players use to ask for a server (RequestApi). The admin token goes as a bearer token; the public API has none. No
// browser-only API here, so Node runs it too (scripts/smoke.ts, scripts/smoke-host.ts).

export interface Seat {
  uid: number;
  name: string;
  joined: boolean;
  loaded?: boolean;
  lost?: boolean;
  gone?: boolean;
  away?: boolean;
  ping_ms?: number | null;
  /** In the lobby: "yes", "no", or "" before the player's lobby set it. */
  ready?: string;
  /** The lobby slot the host's lobby gave it; 0 before. */
  slot?: number;
  speed_limit?: number | null;
  camera_updates?: number;
  backlog_kb?: number;
  behind_beats?: number;
  /** "" before the launch, then "loading", "rules", "loaded". */
  load?: string;
  /** "same", "differs", "missing", or "" before the verdict. */
  content?: string;
  /** "allowed", "outside", "missing", or "" before the verdict. */
  mods?: string;
  ui_mods?: string[];
  [key: string]: unknown;
}

export interface Status {
  id: number;
  ok: true;
  phase: "lobby" | "game" | string;
  host?: number;
  started?: boolean;
  beat?: number;
  paused?: boolean;
  seats?: Seat[];
  /** The configured start-when-ready countdown in seconds; 0 or absent when off. */
  start_when_ready_seconds?: number;
  /** Seconds left of a running countdown; present only while one runs. */
  countdown_seconds?: number;
  [key: string]: unknown;
}

export interface Resource {
  stored?: number | null;
  income?: number | null;
  storage?: number | null;
}

export interface Army {
  /** The army's number, from 1. */
  army: number;
  name?: string | null;
  team?: number | null;
  /** 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim. */
  faction?: number | null;
  human?: boolean | null;
  /** Humans only. */
  uid?: number | null;
  score?: number | null;
  mass?: Resource | null;
  energy?: Resource | null;
  units?: { count?: number | null; cap?: number | null } | null;
  acu?: { alive?: boolean | null; health?: number | null; max_health?: number | null; enhancements?: string[] | null } | null;
  /** The sim's result once known, e.g. "victory 10". */
  result?: string | null;
  [key: string]: unknown;
}

export interface Armies {
  ok: true;
  beat?: number;
  armies: Army[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------- server-host (one per machine, many lobbies)

export interface HostCpu {
  id: number;
  /** Hyperthread siblings share a core id. */
  core?: number | null;
  socket?: number | null;
  /** Busy % over the last second, 0..100. */
  load?: number | null;
  /** Busy % over the last 10 s, 0..100. */
  load10?: number | null;
  /** Ids of the lobbies pinned to this CPU. */
  lobbies?: string[] | null;
  /** Its NUMA node. */
  node?: number | null;
}

/** A NUMA node: its CPUs and the memory next to them. */
export interface HostNode {
  id: number;
  cpus: number[];
  memory_mb?: { total?: number | null; free?: number | null } | null;
}

/** A network link with its speed and live traffic. */
export interface HostLink {
  name: string;
  speed_mbps?: number | null;
  in_kbps?: number | null;
  out_kbps?: number | null;
}

export interface HostInfo {
  name?: string;
  cpu_model?: string;
  memory_mb?: { total?: number | null; available?: number | null } | null;
  cpus: HostCpu[];
  nodes?: HostNode[];
  links?: HostLink[];
  lobbies?: number;
  /** AI personalities a seat may take (the settings catalog's `ai` replaces it). */
  ai?: string[];
  [key: string]: unknown;
}

/** A placement warning: `severity` info, warn or error (an error needs `force` to start anyway). */
export interface PlacementWarning {
  code: string;
  severity: "info" | "warn" | "error" | string;
  text: string;
}

/** A lobby's server process, sampled every 2 s. */
export interface Usage {
  cpu_cores?: number | null;
  rss_mb?: number | null;
}

/** What a game of that many players on a map that big needs. */
export interface Estimate {
  players?: number | null;
  km?: number | null;
  mean_cores?: number | null;
  worst_cores?: number | null;
  suggested_cores?: number | null;
  memory_mb?: number | null;
  upload_kbps?: number | null;
  min_connection_kbps?: number | null;
  basis?: string | null;
}

/** `POST /api/v1/plan`'s answer: where a game would go and what's wrong with it; nothing is started. */
export interface Plan {
  estimate: Estimate;
  cores: number;
  cpus: number[];
  nodes: number[];
  /** No error-level warning. */
  fits: boolean;
  warnings: PlacementWarning[];
}

/** Which capacity a game uses: the player-hosting pool, or the CPUs outside it (the operator's). */
export type Side = "pool" | "operator";

/** Players and map size, and either `cores` (0 or absent: the suggestion) or `cpus` by hand. */
export interface PlanRequest {
  players: number;
  km: number;
  cores?: number;
  cpus?: number[];
  /** The host's default is "operator". */
  side?: Side;
}

/** A setting's value key: a string or a number, sent back as given. */
export type SettingKey = string | number;

export interface SettingValue {
  key: SettingKey;
  text?: string | null;
  help?: string | null;
}

/** One of FAF's lobby options, or a map's own. */
export interface SettingOption {
  key: string;
  label?: string | null;
  help?: string | null;
  default?: SettingKey | null;
  /** rules, units, teams, ai, other. */
  group?: string | null;
  values: SettingValue[];
}

export interface SettingAi {
  key: string;
  name?: string | null;
  rating?: number | null;
}

export interface Settings {
  options: SettingOption[];
  ai: SettingAi[];
  /** Empty for a map without its own options (adaptive maps have them). */
  map_options: SettingOption[];
}

export interface MapInfo {
  id: string;
  name?: string;
  file?: string;
  size?: number[] | null;
  km?: number | null;
  players?: number | null;
  description?: string | null;
  /** "fa" (the game's own maps) or "vault". */
  source?: string | null;
  /** Each start spot (ARMY_n of the map's markers) as [x, z], 0..1 over the map's size, in army order. */
  spawns?: [number, number][] | null;
  /** Where the map's preview image is, relative to the host's address; absent when the map has none. */
  preview?: string | null;
}

export interface Hint {
  players?: number;
  km?: number;
  mean_cores?: number | null;
  worst_cores?: number | null;
  suggested_cores?: number | null;
  basis?: string | null;
  min_connection_kbps?: number | null;
  server_upload_kbps?: number | null;
  max_players?: number | null;
  connection_basis?: string | null;
}

export interface LobbySeat {
  /** The seat's number, which is also its start spot (ARMY_n). */
  seat: number;
  kind: "human" | "ai" | string;
  name?: string | null;
  uid?: number | null;
  ai?: string | null;
  faction?: number | null;
  team?: number | null;
  /** Humans: the switches their game starts with to join. */
  join?: string | null;
}

/** Someone who watches a lobby's game as a live replay. */
export interface LobbyObserver {
  name?: string | null;
  /** A referee watches with no delay. */
  referee?: boolean | null;
  /** The switches the game opens the live replay with: `/replay gpgnet://<host>:<port>/<token>`. */
  watch?: string | null;
}

/** tournament: the operator sets everything and nobody hosts; custom: seat 1 hosts in their own lobby screen. */
export type LobbyKind = "tournament" | "custom";

export interface LobbyMapRef {
  id?: string;
  name?: string | null;
  km?: number | null;
  players?: number | null;
}

export interface Lobby {
  id: string;
  name?: string | null;
  /** starting, lobby, game, ended, failed, stopped. */
  state: string;
  kind?: LobbyKind | string | null;
  /** operator, or pool (a player's request on the pool's CPUs). */
  side?: Side | string | null;
  /** The player request it came from (a pool game), or null. */
  request?: string | null;
  map?: LobbyMapRef | null;
  /** The game and map options it started with (`set_options` changes later aren't in it). */
  options?: Record<string, SettingKey> | null;
  cpus?: number[] | null;
  port?: number | null;
  pid?: number | null;
  created?: string | null;
  /** When it went into the queue, if it waited there. */
  queued_at?: string | null;
  started_at?: string | null;
  control?: string | null;
  start_when_ready?: number | null;
  seats?: LobbySeat[] | null;
  hint?: Hint | null;
  phase?: string | null;
  beat?: number | null;
  /** How the process exited, for a failed lobby. */
  exit?: string | null;
  observers?: LobbyObserver[] | null;
  /** How far behind the game non-referee observers watch. */
  observer_delay_seconds?: number | null;
  /** The second port observers watch from; only with observers. */
  observe_port?: number | null;
  /** The NUMA nodes its CPUs are on. */
  nodes?: number[] | null;
  /** The placement's warnings when it was made. */
  warnings?: PlacementWarning[] | null;
  usage?: Usage | null;
  [key: string]: unknown;
}

export interface NewObserver {
  /** Up to 40 characters; empty gives "Observer N". */
  name: string;
  referee?: boolean;
}

export interface NewSeat {
  kind: "human" | "ai";
  /**
   * The start spot (ARMY_n), from 1. The host's lobby gives seat n start spot n, so this is the seat's number; without
   * it the seats take spots 1, 2, 3... in the order given.
   */
  seat?: number;
  name?: string;
  uid?: number;
  ai?: string;
  /** 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim, 5 random. */
  faction: number;
  /** 1 = no team, 2.. = team 1.. (FAF's numbering). */
  team: number;
}

export interface NewLobby {
  name: string;
  map: string;
  /** The host's default follows `control`: organiser -> tournament, player -> custom. */
  kind?: LobbyKind;
  /** Game and map options together, any subset; the rest are their defaults. */
  options: Record<string, SettingKey>;
  seats: NewSeat[];
  control: "player" | "organiser";
  start_when_ready: number;
  lobby_minutes: number;
  cpus: number[] | "auto";
  cores?: number;
  /** At most 32. */
  observers?: NewObserver[];
  /** 0..3600; referees watch without it. */
  observer_delay_seconds?: number;
  /** Start despite an error-level placement warning (without it such a lobby answers 409). */
  force?: boolean;
  /** When it doesn't fit now, wait in the operator queue (202 with the queue item) instead of a 409. */
  queue?: boolean;
}

/** What waits in a queue for room: an operator lobby made with "queue if full", or a player's request. */
export interface QueueItem {
  id: string;
  side: Side | string;
  kind?: LobbyKind | string | null;
  name?: string | null;
  /** The requesting player (pool items); null for the operator's. */
  player?: string | null;
  map?: LobbyMapRef | null;
  seats?: number | null;
  estimate?: Estimate | null;
  /** 1 = next on its side. */
  position?: number | null;
  /** games (the pool's game limit), cores, memory, network or ports; "" when it fits and starts next. */
  waiting_for?: string | null;
  /** The player request it is, for a pool item. */
  request?: string | null;
  created?: string | null;
  [key: string]: unknown;
}

/** `POST /api/v1/lobbies`: the lobby started, or (with `queue: true`) the queue item it waits as. */
export interface Created {
  lobby: Lobby | null;
  queued: QueueItem | null;
}

/** Capacity for games players ask for (requests): the CPUs, limits, defaults and access. */
export interface Pool {
  enabled: boolean;
  /** Whole cores' CPUs, by NUMA node; operator lobbies' Auto doesn't pick them. */
  cpus: number[];
  nodes: number[];
  /** Games at once. */
  max_games: number;
  /** The largest player count of one game. */
  max_players: number;
  /** Cores per game: 0 = from map size and players. */
  cores: number;
  lobby_minutes: number;
  access: "open" | "code" | string;
  code: string;
  /** Default game options of player games; the player's request goes over them. */
  options: Record<string, SettingKey>;
  /** The longest the pool's queue gets before requests are refused. */
  max_queue: number;
}

export interface PoolUsage {
  games: number;
  queued: number;
  free_cores: number;
  cpus_busy: number[];
}

export interface PoolView {
  pool: Pool;
  usage: PoolUsage;
  /** After a change: what to know about it (`pool_overlap`: an operator lobby still runs on CPUs given to the pool). */
  warnings: PlacementWarning[];
}

/** `PUT /api/v1/pool`: any subset; turning it off with `drop_queue` also refuses what waits. */
export type PoolUpdate = Partial<Pool> & { drop_queue?: boolean };

/** `GET /api/v1/metrics`: the host's history, a sample every 2 s; each series lines up with `t` (null: no sample). */
export interface Metrics {
  /** Unix seconds. */
  t: number[];
  /** Whole-machine busy %. */
  cpu: (number | null)[];
  mem_used_mb: (number | null)[];
  net: Record<string, { in_kbps: (number | null)[]; out_kbps: (number | null)[] }>;
  nodes: Record<string, { cpu: (number | null)[]; mem_free_mb: (number | null)[] }>;
  lobbies: Record<string, { cpu_cores: (number | null)[]; rss_mb: (number | null)[] }>;
}

/** One line of a log: its text, with the time and level when the line says them. */
export interface LogLine {
  text: string;
  time?: string | null;
  level?: string | null;
}

export interface Answer {
  ok: boolean;
  error?: string;
  [key: string]: unknown;
}

export interface ServerEvent {
  event: string;
  [key: string]: unknown;
}

// Plain fields, not constructor parameter properties: Node runs this file by stripping types only.
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** The answer's JSON, or `ok: false` when its body isn't JSON (a proxy's error page, say). */
async function readAnswer(response: Response): Promise<Answer> {
  try {
    return (await response.json()) as Answer;
  } catch {
    return { ok: false };
  }
}

/**
 * One JSON request to `base + path`, with the token as a bearer token when there is one (the public API has none).
 * Throws `ApiError` with the HTTP status and the answer's reason when it isn't `ok`.
 */
async function requestJson(base: string, token: string | null, method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Answer> {
  const headers: Record<string, string> = {};
  if (token !== null) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  const answer = await readAnswer(response);
  if (!response.ok || !answer.ok) {
    throw new ApiError(answer.error ?? `${method} ${path}: HTTP ${response.status}`, response.status);
  }
  return answer;
}

/**
 * Reads a Server-Sent Events body until it ends or `signal` aborts: each event's `data:` lines, joined, to `onData`.
 * Read with fetch, as the browser's EventSource can't send a token.
 */
async function readSse(response: Response, onData: (data: string, event: string) => void): Promise<void> {
  if (response.body === null) return;
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      return;
    }
    buffered = (buffered + decoder.decode(value, { stream: true })).replace(/\r\n/g, "\n");
    // An event ends at a blank line; its `data:` lines hold the payload.
    let end = buffered.indexOf("\n\n");
    while (end >= 0) {
      const block = buffered.slice(0, end);
      buffered = buffered.slice(end + 2);
      const lines = block.split("\n");
      const event = lines.find((line) => line.startsWith("event:"))?.slice(6).trim() ?? "message";
      const data = lines
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).replace(/^ /, ""))
        .join("\n");
      if (event === "end") {
        await reader.cancel().catch(() => undefined);
        return;
      }
      if (data !== "") onData(data, event);
      end = buffered.indexOf("\n\n");
    }
  }
}

function settingsFrom(raw: Partial<Settings> | undefined): Settings {
  return {
    options: Array.isArray(raw?.options) ? raw.options : [],
    ai: Array.isArray(raw?.ai) ? raw.ai : [],
    map_options: Array.isArray(raw?.map_options) ? raw.map_options : [],
  };
}

function settingsQuery(mapId?: string): string {
  return mapId === undefined || mapId === "" ? "" : `?map=${encodeURIComponent(mapId)}`;
}

const LEVEL = /\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|PANIC)\b/;
const TIME = /^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*/;

/** A log line from the host: a string (time and level read from its start) or an object with text/line and fields. */
export function logLineFrom(raw: unknown): LogLine {
  if (raw !== null && typeof raw === "object") {
    const item = raw as Record<string, unknown>;
    const text = String(item.text ?? item.line ?? item.msg ?? item.message ?? "");
    const parsed = logLineFrom(text);
    return {
      text: parsed.text,
      time: typeof item.time === "string" ? item.time : typeof item.t === "number" ? new Date(item.t * 1000).toISOString() : parsed.time,
      level: typeof item.level === "string" ? item.level.toUpperCase() : parsed.level,
    };
  }
  const line = String(raw ?? "");
  const time = TIME.exec(line);
  const rest = time === null ? line : line.slice(time[0].length);
  const level = LEVEL.exec(rest.slice(0, 24));
  return { text: rest, time: time?.[1] ?? null, level: level === null ? null : level[1] === "WARNING" ? "WARN" : (level[1] ?? null) };
}

function logLinesFrom(answer: Answer): LogLine[] {
  const raw = Array.isArray(answer.lines) ? answer.lines : Array.isArray(answer.log) ? answer.log : typeof answer.log === "string" ? answer.log.split("\n") : [];
  return (raw as unknown[]).map(logLineFrom).filter((line) => line.text !== "");
}

function series(raw: unknown, length: number): (number | null)[] {
  const list = Array.isArray(raw) ? raw : [];
  return Array.from({ length }, (_, index) => {
    const value = list[index];
    return typeof value === "number" && Number.isFinite(value) ? value : null;
  });
}

/** The metrics answer, every series as long as `t` (the host's object may come bare or under `metrics`). */
function metricsFrom(answer: Answer): Metrics {
  const raw = (answer.metrics !== null && typeof answer.metrics === "object" ? answer.metrics : answer) as Record<string, unknown>;
  const t = (Array.isArray(raw.t) ? raw.t : []).filter((value): value is number => typeof value === "number");
  const n = t.length;
  const record = (value: unknown): Record<string, Record<string, unknown>> => (value !== null && typeof value === "object" ? (value as Record<string, Record<string, unknown>>) : {});
  const net: Metrics["net"] = {};
  for (const [name, link] of Object.entries(record(raw.net))) net[name] = { in_kbps: series(link.in_kbps, n), out_kbps: series(link.out_kbps, n) };
  const nodes: Metrics["nodes"] = {};
  for (const [id, node] of Object.entries(record(raw.nodes))) nodes[id] = { cpu: series(node.cpu, n), mem_free_mb: series(node.mem_free_mb, n) };
  const lobbies: Metrics["lobbies"] = {};
  for (const [id, lobby] of Object.entries(record(raw.lobbies))) lobbies[id] = { cpu_cores: series(lobby.cpu_cores, n), rss_mb: series(lobby.rss_mb, n) };
  return { t, cpu: series(raw.cpu, n), mem_used_mb: series(raw.mem_used_mb, n), net, nodes, lobbies };
}

function queueFrom(raw: unknown): QueueItem[] {
  return Array.isArray(raw) ? (raw as QueueItem[]) : [];
}

function poolFrom(answer: Answer): PoolView {
  const pool = (answer.pool ?? {}) as Partial<Pool>;
  const usage = (answer.usage ?? {}) as Partial<PoolUsage>;
  const numbers = (value: unknown): number[] => (Array.isArray(value) ? value.filter((item): item is number => typeof item === "number") : []);
  return {
    pool: {
      enabled: pool.enabled === true,
      cpus: numbers(pool.cpus),
      nodes: numbers(pool.nodes),
      max_games: typeof pool.max_games === "number" ? pool.max_games : 0,
      max_players: typeof pool.max_players === "number" ? pool.max_players : 0,
      cores: typeof pool.cores === "number" ? pool.cores : 0,
      lobby_minutes: typeof pool.lobby_minutes === "number" ? pool.lobby_minutes : 0,
      access: pool.access === "code" ? "code" : "open",
      code: typeof pool.code === "string" ? pool.code : "",
      options: pool.options !== null && typeof pool.options === "object" ? pool.options : {},
      max_queue: typeof pool.max_queue === "number" ? pool.max_queue : 0,
    },
    usage: {
      games: typeof usage.games === "number" ? usage.games : 0,
      queued: typeof usage.queued === "number" ? usage.queued : 0,
      free_cores: typeof usage.free_cores === "number" ? usage.free_cores : 0,
      cpus_busy: numbers(usage.cpus_busy),
    },
    warnings: Array.isArray(answer.warnings) ? (answer.warnings as PlacementWarning[]) : [],
  };
}

export class ServerApi {
  readonly base: string;
  private readonly token: string;

  constructor(base: string, token: string) {
    this.base = base.replace(/\/+$/, "");
    this.token = token;
  }

  private headers(json: boolean): Record<string, string> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (json) {
      headers["Content-Type"] = "application/json";
    }
    return headers;
  }

  /** `GET /api/v1/status`: the lobby or the game, with its seats. `signal` gives up on it (a time limit, say). */
  async status(signal?: AbortSignal): Promise<Status> {
    const response = await fetch(`${this.base}/api/v1/status`, { headers: this.headers(false), signal });
    const body = await readAnswer(response);
    if (!response.ok || !body.ok) {
      throw new ApiError(body.error ?? `status: HTTP ${response.status}`, response.status);
    }
    return body as Status;
  }

  /**
   * `GET /api/v1/armies`: each army of the running game (score, resources, units, ACU). Throws `ApiError` with 400
   * ("no game yet") in the lobby, and 404 from a server without this endpoint.
   */
  async armies(signal?: AbortSignal): Promise<Armies> {
    const response = await fetch(`${this.base}/api/v1/armies`, { headers: this.headers(false), signal });
    const body = await readAnswer(response);
    if (!response.ok || !body.ok) {
      throw new ApiError(body.error ?? `armies: HTTP ${response.status}`, response.status);
    }
    const armies = body as Armies;
    return { ...armies, armies: Array.isArray(armies.armies) ? armies.armies : [] };
  }

  /**
   * `POST /api/v1/ops/<op>` with the op's fields: the server's answer, `ok` false with its `error` when it refused
   * (HTTP 400). A missing or wrong token, or a server that isn't there, throws.
   */
  async op(name: string, fields: Record<string, unknown> = {}): Promise<Answer> {
    const response = await fetch(`${this.base}/api/v1/ops/${encodeURIComponent(name)}`, {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify(fields),
    });
    const body = await readAnswer(response);
    if (response.status === 401) {
      throw new ApiError(body.error ?? "the admin token was refused", 401);
    }
    if (!body.ok && body.error === undefined && !response.ok) {
      body.error = `HTTP ${response.status}`;
    }
    return body;
  }

  /**
   * `GET /api/v1/events`, read until `signal` aborts or the server closes it: each Server-Sent Event's JSON to
   * `onEvent`. `onOpen` runs once the stream is established.
   */
  async events(onEvent: (event: ServerEvent) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    const response = await fetch(`${this.base}/api/v1/events`, { headers: this.headers(false), signal });
    if (!response.ok || response.body === null) {
      throw new ApiError(`events: HTTP ${response.status}`, response.status);
    }
    onOpen?.();
    await readSse(response, (data) => {
      try {
        onEvent(JSON.parse(data) as ServerEvent);
      } catch {
        // not JSON: ignored, as the stream's comments are
      }
    });
  }
}

/**
 * A machine's `server-host`: the machine, its maps, the planner, its lobbies (each its own server reached through the
 * host, `lobbyApi`), the player-hosting pool, the queue, metrics and logs. Errors throw `ApiError` with the HTTP
 * status and the host's reason.
 */
export class HostApi {
  readonly base: string;
  private readonly token: string;

  constructor(base: string, token: string) {
    this.base = base.replace(/\/+$/, "");
    this.token = token;
  }

  private request(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Answer> {
    return requestJson(this.base, this.token, method, path, body, signal);
  }

  /** `GET /api/v1/host`. Anything but a server-host (a lone server's `--rest`, say) answers 404. */
  async host(signal?: AbortSignal): Promise<HostInfo> {
    const answer = await this.request("GET", "/api/v1/host", undefined, signal);
    const host = (answer.host ?? {}) as HostInfo;
    return { ...host, cpus: Array.isArray(host.cpus) ? host.cpus : [] };
  }

  /** `GET /api/v1/maps`, with each map's start spots and preview. */
  async maps(signal?: AbortSignal): Promise<MapInfo[]> {
    const answer = await this.request("GET", "/api/v1/maps", undefined, signal);
    return Array.isArray(answer.maps) ? (answer.maps as MapInfo[]) : [];
  }

  /**
   * The address of a map's preview image (`GET /api/v1/maps/<id>/preview.png`, PNG, no token needed: an `<img>` loads
   * it as is), or null when the map has none.
   */
  previewUrl(map: MapInfo): string | null {
    if (typeof map.preview !== "string" || map.preview === "") return null;
    return /^https?:\/\//.test(map.preview) ? map.preview : `${this.base}${map.preview.startsWith("/") ? "" : "/"}${map.preview}`;
  }

  /** `GET /api/v1/hint`: how many cores a game of that many players on a map that big needs. */
  async hint(players: number, km: number, signal?: AbortSignal): Promise<Hint> {
    const query = `players=${encodeURIComponent(String(players))}&km=${encodeURIComponent(String(km))}`;
    return (await this.request("GET", `/api/v1/hint?${query}`, undefined, signal)) as Hint;
  }

  /** `GET /api/v1/lobbies`. */
  async lobbies(signal?: AbortSignal): Promise<Lobby[]> {
    const answer = await this.request("GET", "/api/v1/lobbies", undefined, signal);
    return Array.isArray(answer.lobbies) ? (answer.lobbies as Lobby[]) : [];
  }

  /** `POST /api/v1/lobbies`: starts a lobby's server, or with `queue: true` queues it when it doesn't fit (202). */
  async createLobby(lobby: NewLobby): Promise<Created> {
    const answer = await this.request("POST", "/api/v1/lobbies", lobby);
    return { lobby: (answer.lobby as Lobby | undefined) ?? null, queued: (answer.queued as QueueItem | undefined) ?? null };
  }

  /** `DELETE /api/v1/lobbies/<id>`: stops its server; it stays listed as stopped. */
  async stopLobby(id: string): Promise<Lobby> {
    return (await this.request("DELETE", `/api/v1/lobbies/${encodeURIComponent(id)}`)).lobby as Lobby;
  }

  /** `DELETE /api/v1/lobbies/<id>?forget=1`: takes a stopped or failed lobby off the list. */
  async forgetLobby(id: string): Promise<void> {
    await this.request("DELETE", `/api/v1/lobbies/${encodeURIComponent(id)}?forget=1`);
  }

  /** `POST /api/v1/plan`: where a game would go on that side, its estimate and warnings; nothing is started. */
  async plan(request: PlanRequest, signal?: AbortSignal): Promise<Plan> {
    const plan = (await this.request("POST", "/api/v1/plan", request, signal)).plan as Partial<Plan> | undefined;
    return {
      estimate: plan?.estimate ?? {},
      cores: plan?.cores ?? 0,
      cpus: Array.isArray(plan?.cpus) ? plan.cpus : [],
      nodes: Array.isArray(plan?.nodes) ? plan.nodes : [],
      fits: plan?.fits !== false,
      warnings: Array.isArray(plan?.warnings) ? plan.warnings : [],
    };
  }

  /** `GET /api/v1/settings[?map=<id>]`: FAF's lobby options, the AIs, and the map's own options. */
  async settings(mapId?: string, signal?: AbortSignal): Promise<Settings> {
    return settingsFrom((await this.request("GET", `/api/v1/settings${settingsQuery(mapId)}`, undefined, signal)).settings as Partial<Settings> | undefined);
  }

  /** `GET /api/v1/pool`: the player-hosting pool and its live use. */
  async pool(signal?: AbortSignal): Promise<PoolView> {
    return poolFrom(await this.request("GET", "/api/v1/pool", undefined, signal));
  }

  /** `PUT /api/v1/pool`: changes any part of it; the answer is the pool as it is now. */
  async setPool(update: PoolUpdate): Promise<PoolView> {
    return poolFrom(await this.request("PUT", "/api/v1/pool", update));
  }

  /** `GET /api/v1/queue`: both sides' queued items, each with its position on its side. */
  async queue(signal?: AbortSignal): Promise<QueueItem[]> {
    return queueFrom((await this.request("GET", "/api/v1/queue", undefined, signal)).queue);
  }

  /** `DELETE /api/v1/queue/<id>`: takes it out of the queue (a player's request is refused). */
  async cancelQueued(id: string): Promise<void> {
    await this.request("DELETE", `/api/v1/queue/${encodeURIComponent(id)}`);
  }

  /** `POST /api/v1/queue/<id>/up`: one place earlier on its side. */
  async moveUp(id: string): Promise<void> {
    await this.request("POST", `/api/v1/queue/${encodeURIComponent(id)}/up`);
  }

  /** `GET /api/v1/metrics?seconds=`: the host's history, a sample every 2 s, up to an hour back. */
  async metrics(seconds: number, signal?: AbortSignal): Promise<Metrics> {
    return metricsFrom(await this.request("GET", `/api/v1/metrics?seconds=${encodeURIComponent(String(Math.round(seconds)))}`, undefined, signal));
  }

  /** `GET /api/v1/logs/host?lines=`: the host's own log, the last lines. */
  async hostLog(lines: number, signal?: AbortSignal): Promise<LogLine[]> {
    return logLinesFrom(await this.request("GET", `/api/v1/logs/host?lines=${encodeURIComponent(String(lines))}`, undefined, signal));
  }

  /** `GET /api/v1/lobbies/<id>/log?lines=`: that lobby's server log, also after it ended. */
  async lobbyLog(id: string, lines: number, signal?: AbortSignal): Promise<LogLine[]> {
    return logLinesFrom(await this.request("GET", `/api/v1/lobbies/${encodeURIComponent(id)}/log?lines=${encodeURIComponent(String(lines))}`, undefined, signal));
  }

  /**
   * `GET /api/v1/lobbies/<id>/log/stream`: new log lines as they come, until `signal` aborts or the host closes it.
   * Each event's data is the line, as text or as JSON (`{"line": ...}` or `{"text": ...}`).
   */
  async lobbyLogStream(id: string, onLine: (line: LogLine) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    await this.logStream(`/api/v1/lobbies/${encodeURIComponent(id)}/log/stream`, onLine, signal, onOpen);
  }

  /** `GET /api/v1/logs/host/stream`: the host's new log lines as they come. */
  async hostLogStream(onLine: (line: LogLine) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    await this.logStream("/api/v1/logs/host/stream", onLine, signal, onOpen);
  }

  /** A log stream: each event's data is one line (plain text; a JSON object with `line` or `text` is read too). */
  private async logStream(path: string, onLine: (line: LogLine) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    const response = await fetch(`${this.base}${path}`, { headers: { Authorization: `Bearer ${this.token}` }, signal });
    if (!response.ok || response.body === null) throw new ApiError(`log stream: HTTP ${response.status}`, response.status);
    onOpen?.();
    await readSse(response, (data) => {
      let raw: unknown = data;
      if (/^\{"(line|text)"/.test(data)) {
        try {
          raw = JSON.parse(data) as unknown;
        } catch {
          raw = data;
        }
      }
      for (const part of typeof raw === "string" ? raw.split("\n") : [raw]) {
        const line = logLineFrom(part);
        if (line.text !== "") onLine(line);
      }
    });
  }

  /** The lobby's own server API, proxied by the host with the host's token. */
  lobbyApi(id: string): ServerApi {
    return new ServerApi(`${this.base}/api/v1/lobbies/${encodeURIComponent(id)}`, this.token);
  }
}

// ---------------------------------------------------------------- the public request API (players, no admin token)

/** `GET /api/v1/public/pool`: what a player may ask for. */
export interface PublicPool {
  enabled: boolean;
  access: "open" | "code" | string;
  max_players: number;
  lobby_minutes: number;
  options: Record<string, SettingKey>;
  queue: { length: number; games: number; max_games: number };
}

/** The lobby a request became, as its player sees it, with every human seat's join line. */
export interface PublicLobby {
  id: string;
  name?: string | null;
  /** starting, lobby, game, ended, failed, stopped. */
  state: string;
  phase?: string | null;
  beat?: number | null;
  map?: LobbyMapRef | null;
  seats?: LobbySeat[] | null;
  options?: Record<string, SettingKey> | null;
  port?: number | null;
}

export interface RequestSeat {
  kind: "human" | "ai";
  /** Seat 1 (the host) defaults to the request's `player`; other humans to "Player N". */
  name?: string;
  ai?: string;
  /** The start spot (ARMY_n), from 1; without it seats take spots in order. */
  seat?: number;
  /** 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim, 5 random. */
  faction?: number;
  /** 1 = no team, 2.. = team 1.. (FAF's numbering). */
  team?: number;
}

export interface NewRequest {
  /** The player's name, 1..40 characters; seat 1, who hosts. */
  player: string;
  map: string;
  seats: RequestSeat[];
  /** Over the pool's defaults. */
  options?: Record<string, SettingKey>;
  /** The access code, when the pool asks for one. */
  code?: string;
}

export type RequestState = "queued" | "starting" | "lobby" | "game" | "ended" | "refused" | "cancelled";

export interface GameRequest {
  id: string;
  /** The requester's secret for following and cancelling it; only in the answer to the POST. */
  key?: string;
  state: RequestState | string;
  /** Its place in the pool's queue while queued. */
  position?: number | null;
  player?: string | null;
  created?: string | null;
  /** Why it was refused or cancelled. */
  reason?: string | null;
  lobby?: PublicLobby | null;
  [key: string]: unknown;
}

function requestFrom(raw: unknown): GameRequest {
  const request = (raw ?? {}) as Partial<GameRequest>;
  const lobby = request.lobby ?? null;
  return { ...request, id: String(request.id ?? ""), state: String(request.state ?? ""), lobby: lobby === null ? null : { ...lobby, seats: Array.isArray(lobby.seats) ? lobby.seats : [] } };
}

/**
 * A player's request for a server: no Authorization header is sent. The request's key, from the answer to the POST,
 * follows and cancels it. Errors throw `ApiError`: 403 when player hosting is off (maps and settings too) or the access
 * code is wrong, 429 for too many requests, 409 for a second live request of the same player or a full queue, 400
 * with the host's reason for a bad one (more cores than the whole pool, say).
 */
export class RequestApi {
  readonly base: string;

  constructor(base: string) {
    this.base = base.replace(/\/+$/, "");
  }

  private request(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Answer> {
    return requestJson(this.base, null, method, `/api/v1/public${path}`, body, signal);
  }

  /** `GET /api/v1/public/pool`. */
  async pool(signal?: AbortSignal): Promise<PublicPool> {
    const answer = await this.request("GET", "/pool", undefined, signal);
    const raw = (answer.pool !== null && typeof answer.pool === "object" ? answer.pool : answer) as Partial<PublicPool>;
    const queue = (raw.queue ?? {}) as Partial<PublicPool["queue"]>;
    return {
      enabled: raw.enabled === true,
      access: raw.access === "code" ? "code" : "open",
      max_players: typeof raw.max_players === "number" ? raw.max_players : 16,
      lobby_minutes: typeof raw.lobby_minutes === "number" ? raw.lobby_minutes : 0,
      options: raw.options !== null && typeof raw.options === "object" ? raw.options : {},
      queue: { length: queue.length ?? 0, games: queue.games ?? 0, max_games: queue.max_games ?? 0 },
    };
  }

  /** `GET /api/v1/public/maps`. */
  async maps(signal?: AbortSignal): Promise<MapInfo[]> {
    const answer = await this.request("GET", "/maps", undefined, signal);
    return Array.isArray(answer.maps) ? (answer.maps as MapInfo[]) : [];
  }

  /** The address of a map's preview image on the public API (an `<img>` may load it as is). */
  previewUrl(map: MapInfo): string | null {
    if (typeof map.preview !== "string" || map.preview === "") return null;
    const path = map.preview.startsWith("/api/v1/public/") ? map.preview : `/api/v1/public/maps/${encodeURIComponent(map.id)}/preview.png`;
    return /^https?:\/\//.test(path) ? path : `${this.base}${path}`;
  }

  /** `GET /api/v1/public/settings[?map=<id>]`. */
  async settings(mapId?: string, signal?: AbortSignal): Promise<Settings> {
    return settingsFrom((await this.request("GET", `/settings${settingsQuery(mapId)}`, undefined, signal)).settings as Partial<Settings> | undefined);
  }

  /** `POST /api/v1/public/requests`: the answer carries the key that follows it. */
  async create(request: NewRequest, signal?: AbortSignal): Promise<GameRequest> {
    return requestFrom((await this.request("POST", "/requests", request, signal)).request);
  }

  /** `GET /api/v1/public/requests/<id>?key=`. */
  async get(id: string, key: string, signal?: AbortSignal): Promise<GameRequest> {
    return requestFrom((await this.request("GET", `/requests/${encodeURIComponent(id)}?key=${encodeURIComponent(key)}`, undefined, signal)).request);
  }

  /** `DELETE /api/v1/public/requests/<id>?key=`: cancels it while it waits or before the game. */
  async cancel(id: string, key: string): Promise<GameRequest> {
    return requestFrom((await this.request("DELETE", `/requests/${encodeURIComponent(id)}?key=${encodeURIComponent(key)}`)).request);
  }
}
