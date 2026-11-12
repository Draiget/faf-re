// The APIs the dashboard talks to: a machine's server-host (HostApi), each lobby's own server through the host's proxy
// (ServerApi: status, the armies of a running game, control ops, the event stream; docs/SWITCHES.md `--rest`), and the
// players' claim API (ClaimApi). The admin token goes as a bearer token. No browser-only API here, so Node runs it too
// (scripts/smoke.ts, scripts/smoke-host.ts).

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
  /** Its NUMA node (plan WP17.16). */
  node?: number | null;
}

/** A NUMA node: its CPUs and the memory next to them (plan WP17.16). */
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

/** What a game of that many players on a map that big needs (plan WP17.17). */
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

/** Players and map size, and either `cores` (0 or absent: the suggestion) or `cpus` by hand. */
export interface PlanRequest {
  players: number;
  km: number;
  cores?: number;
  cpus?: number[];
}

/** A setting's value key: a string or a number, sent back as given. */
export type SettingKey = string | number;

export interface SettingValue {
  key: SettingKey;
  text?: string | null;
  help?: string | null;
}

/** One of FAF's lobby options, or a map's own (plan WP17.20). */
export interface SettingOption {
  key: string;
  label?: string | null;
  help?: string | null;
  default?: SettingKey | null;
  /** rules, units, ai, other. */
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

/** Capacity held for players who host themselves (plan WP17.18). */
export interface Slot {
  id: string;
  name?: string | null;
  /** open, claimed, lobby, game, ended. */
  state: string;
  max_players?: number | null;
  cpus?: number[] | null;
  nodes?: number[] | null;
  warnings?: PlacementWarning[] | null;
  /** What a player uses to host on it. */
  claim_code?: string | null;
  /** Once claimed: the lobby it became (a lobby like any other). */
  lobby?: string | null;
  host_player?: string | null;
  /** The map size it was sized for, km. */
  km?: number | null;
  lobby_minutes?: number | null;
  /** The operator's default game options for the games on it. */
  options?: Record<string, SettingKey> | null;
  /** When its game ends it opens again with a new claim code (else it ends). */
  reopen?: boolean | null;
  /** Games hosted on it so far. */
  games?: number | null;
  created?: string | null;
  [key: string]: unknown;
}

export interface NewSlots {
  name: string;
  max_players: number;
  /** The largest map expected, for the estimate (the host's default is 20). */
  km?: number;
  cores?: number;
  cpus?: number[];
  lobby_minutes: number;
  /** How many identical slots. */
  count: number;
  options?: Record<string, SettingKey>;
  /** Open again with a new code after each game (the host's default is true). */
  reopen?: boolean;
  force?: boolean;
}

// ---------------------------------------------------------------- the claim API (players, no admin token)

/** The slot as its claim code shows it to the player. */
export interface ClaimSlot {
  id: string;
  name?: string | null;
  /** open, claimed, lobby, game, ended. */
  state: string;
  max_players?: number | null;
  /** The map size it was sized for. */
  km?: number | null;
  cores?: number | null;
  lobby_minutes?: number | null;
  /** The operator's defaults; the claim's own options go over them. */
  options?: Record<string, SettingKey> | null;
}

/** The claimed lobby as its host player sees it, with every human seat's join line. */
export interface ClaimLobby {
  id: string;
  name?: string | null;
  /** starting, lobby, game, ended, failed, stopped. */
  state: string;
  phase?: string | null;
  beat?: number | null;
  map?: { id?: string; name?: string | null; km?: number | null; players?: number | null } | null;
  seats?: LobbySeat[] | null;
  options?: Record<string, SettingKey> | null;
  port?: number | null;
}

export interface ClaimView {
  slot: ClaimSlot;
  /** Null until the slot is claimed. */
  lobby: ClaimLobby | null;
}

export interface ClaimSeat {
  kind: "human" | "ai";
  /** Seat 1 (the host) defaults to the claim's `player`; other humans to "Player N". */
  name?: string;
  ai?: string;
  /** 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim, 5 random. */
  faction?: number;
  /** 1 = no team, 2.. = team 1.. (FAF's numbering). */
  team?: number;
}

/** `POST /api/v1/claim/<code>`: the player's own game. */
export interface ClaimRequest {
  /** The host player's name, 1..40 characters. */
  player: string;
  map: string;
  /** Up to the slot's max_players; seat 1 is the host, a human. None: just the host. */
  seats?: ClaimSeat[];
  /** Over the slot's options; the rest are FAF's defaults. */
  options?: Record<string, SettingKey>;
  start_when_ready?: number;
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
}

export interface Hint {
  players?: number;
  km?: number;
  mean_cores?: number | null;
  worst_cores?: number | null;
  suggested_cores?: number | null;
  basis?: string | null;
  /** Plan WPR.8: the published minimums for a game this size (WPR.7's measurements), KB/s. */
  min_connection_kbps?: number | null;
  server_upload_kbps?: number | null;
  max_players?: number | null;
  connection_basis?: string | null;
}

export interface LobbySeat {
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

/** Someone who watches a lobby's game as a live replay (plan WP13.1). */
export interface LobbyObserver {
  name?: string | null;
  /** A referee watches with no delay. */
  referee?: boolean | null;
  /** The switches the game opens the live replay with: `/replay gpgnet://<host>:<port>/<token>`. */
  watch?: string | null;
}

export interface Lobby {
  id: string;
  name?: string | null;
  /** starting, lobby, game, ended, failed, stopped. */
  state: string;
  map?: { id?: string; name?: string | null; km?: number | null; players?: number | null } | null;
  /** The game and map options it started with (`set_options` changes later aren't in it). */
  options?: Record<string, SettingKey> | null;
  cpus?: number[] | null;
  port?: number | null;
  pid?: number | null;
  created?: string | null;
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
  /** The open slot it was claimed from (plan WP17.18). */
  slot?: string | null;
  [key: string]: unknown;
}

export interface NewObserver {
  /** Up to 40 characters; empty gives "Observer N". */
  name: string;
  referee?: boolean;
}

export interface NewSeat {
  kind: "human" | "ai";
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
 * One JSON request to `base + path`, with the token as a bearer token when there is one (the claim API has none).
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
   * `onEvent`. Read with fetch, as the browser's EventSource can't send the token. `onOpen` runs once the stream is
   * established.
   */
  async events(onEvent: (event: ServerEvent) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    const response = await fetch(`${this.base}/api/v1/events`, { headers: this.headers(false), signal });
    if (!response.ok || response.body === null) {
      throw new ApiError(`events: HTTP ${response.status}`, response.status);
    }
    onOpen?.();
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffered = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        return;
      }
      buffered = (buffered + decoder.decode(value, { stream: true })).replace(/\r\n/g, "\n");
      // An event ends at a blank line; its `data:` lines hold the JSON.
      let end = buffered.indexOf("\n\n");
      while (end >= 0) {
        const block = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        const data = block
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (data !== "") {
          try {
            onEvent(JSON.parse(data) as ServerEvent);
          } catch {
            // not JSON: ignored, as the stream's comments are
          }
        }
        end = buffered.indexOf("\n\n");
      }
    }
  }
}

/**
 * A machine's `server-host` (plan WP17.13): the machine, its maps, the cost hint, and its lobbies, each lobby its own
 * server reached through the host (`lobbyApi`). Errors throw `ApiError` with the HTTP status and the host's reason.
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

  /** `GET /api/v1/maps`, sorted by name. */
  async maps(signal?: AbortSignal): Promise<MapInfo[]> {
    const answer = await this.request("GET", "/api/v1/maps", undefined, signal);
    return Array.isArray(answer.maps) ? (answer.maps as MapInfo[]) : [];
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

  /** `POST /api/v1/lobbies`: starts a lobby's server. */
  async createLobby(lobby: NewLobby): Promise<Lobby> {
    return (await this.request("POST", "/api/v1/lobbies", lobby)).lobby as Lobby;
  }

  /** `DELETE /api/v1/lobbies/<id>`: stops its server; it stays listed as stopped. */
  async stopLobby(id: string): Promise<Lobby> {
    return (await this.request("DELETE", `/api/v1/lobbies/${encodeURIComponent(id)}`)).lobby as Lobby;
  }

  /** `DELETE /api/v1/lobbies/<id>?forget=1`: takes a stopped or failed lobby off the list. */
  async forgetLobby(id: string): Promise<void> {
    await this.request("DELETE", `/api/v1/lobbies/${encodeURIComponent(id)}?forget=1`);
  }

  /** `POST /api/v1/plan`: where a game would go, its estimate and warnings; nothing is started. */
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

  /** `GET /api/v1/slots`: capacity held for players who host themselves. */
  async slots(signal?: AbortSignal): Promise<Slot[]> {
    const answer = await this.request("GET", "/api/v1/slots", undefined, signal);
    return Array.isArray(answer.slots) ? (answer.slots as Slot[]) : [];
  }

  /** `POST /api/v1/slots`: `count` identical slots. */
  async createSlots(slots: NewSlots): Promise<Slot[]> {
    const answer = await this.request("POST", "/api/v1/slots", slots);
    return Array.isArray(answer.slots) ? (answer.slots as Slot[]) : [];
  }

  /** `DELETE /api/v1/slots/<id>`: frees an unclaimed slot, or stops a claimed one's game. */
  async deleteSlot(id: string): Promise<void> {
    await this.request("DELETE", `/api/v1/slots/${encodeURIComponent(id)}`);
  }

  /** The lobby's own server API, proxied by the host with the host's token. */
  lobbyApi(id: string): ServerApi {
    return new ServerApi(`${this.base}/api/v1/lobbies/${encodeURIComponent(id)}`, this.token);
  }
}

function claimViewFrom(raw: unknown): ClaimView {
  const view = (raw ?? {}) as Partial<ClaimView>;
  const slot = (view.slot ?? { id: "", state: "" }) as ClaimSlot;
  const lobby = view.lobby ?? null;
  return { slot, lobby: lobby === null ? null : { ...lobby, seats: Array.isArray(lobby.seats) ? lobby.seats : [] } };
}

/**
 * A player's claim of an open slot (plan WP17.18): the claim code is the credential, so no Authorization header is
 * sent. Errors throw `ApiError`: 404 for an unknown code (or one that stopped working when its slot reopened after a
 * game), 409 when the slot is already claimed, 400 with the host's reason for a bad claim.
 */
export class ClaimApi {
  readonly base: string;
  readonly code: string;

  constructor(base: string, code: string) {
    this.base = base.replace(/\/+$/, "");
    this.code = code.trim();
  }

  private request(method: string, sub: string, body?: unknown, signal?: AbortSignal): Promise<Answer> {
    return requestJson(this.base, null, method, `/api/v1/claim/${encodeURIComponent(this.code)}${sub}`, body, signal);
  }

  /** `GET /api/v1/claim/<code>`: the slot and, once claimed, its lobby. */
  async view(signal?: AbortSignal): Promise<ClaimView> {
    return claimViewFrom((await this.request("GET", "", undefined, signal)).claim);
  }

  /** `GET /api/v1/claim/<code>/maps`: the host's maps, as `/api/v1/maps` gives them. */
  async maps(signal?: AbortSignal): Promise<MapInfo[]> {
    const answer = await this.request("GET", "/maps", undefined, signal);
    return Array.isArray(answer.maps) ? (answer.maps as MapInfo[]) : [];
  }

  /** `GET /api/v1/claim/<code>/settings[?map=<id>]`: as `/api/v1/settings`. */
  async settings(mapId?: string, signal?: AbortSignal): Promise<Settings> {
    return settingsFrom((await this.request("GET", `/settings${settingsQuery(mapId)}`, undefined, signal)).settings as Partial<Settings> | undefined);
  }

  /** `POST /api/v1/claim/<code>`: claims the slot; the answer is the view with the new lobby. */
  async claim(request: ClaimRequest, signal?: AbortSignal): Promise<ClaimView> {
    return claimViewFrom((await this.request("POST", "", request, signal)).claim);
  }
}
