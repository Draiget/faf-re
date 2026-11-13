// The control service's API (tools/cmd/control-service, docs/CONTROL_SERVICE.md): who is signed in and their roles,
// the tournaments, every host it follows, the lobbies across them as the viewer may see them, organised lobbies made
// on the host chosen or the least loaded one that fits, players' requests, and the live state as Server-Sent Events.
// In the browser the session cookie goes with every request (fetch with credentials); scripts send the admin token or
// a cookie header instead. Also the adapters that let the dashboard's host views run on it: one host's reads
// (ControlHostApi: maps, settings, the planner, previews), one lobby (ControlLobbyApi: its status, ops, armies and
// events), and the lobbies across hosts by key (ControlRootApi, the store's api in this mode). No browser-only API
// here, so Node runs it too (scripts/smoke-control.ts).

import {
  ApiError,
  HostApi,
  readSse,
  ServerApi,
  type Answer,
  type Armies,
  type Created,
  type Hint,
  type HostInfo,
  type Lobby,
  type LobbyMapRef,
  type LobbySeat,
  type MapInfo,
  type NewLobby,
  type NewSeat,
  type Plan,
  type PlanRequest,
  type ServerEvent,
  type SettingKey,
  type Settings,
  type Status,
} from "./api.ts";

// ---------------------------------------------------------------- what the service answers

export interface ServiceUser {
  /** The FAF user id; 0 for the admin token. */
  uid: number;
  name: string;
  /** session, access_token or admin_token. */
  via: string;
}

/** A tournament as the viewer may see it: its lists only for admins, global organisers and its own organisers. */
export interface ServiceTournament {
  id: string;
  name: string;
  /** The viewer's part in it: organiser, player, observer. */
  you: string[];
  organisers?: number[];
  players?: number[];
  observers?: number[];
}

export interface Me {
  user: ServiceUser;
  /** admin, organiser, player. */
  roles: string[];
  tournaments: ServiceTournament[];
  /** Signed-in players may ask for a game they host. */
  player_hosting: boolean;
}

export interface Health {
  ok: boolean;
  /** redis or memory. */
  store: string;
  hosts: number;
  hosts_reachable: number;
}

/** A host as the viewer may see it: players get its name, region, reachability, lobby count and player hosting. */
export interface ServiceHost {
  name: string;
  region?: string;
  reachable: boolean;
  error?: string;
  /** The host's own name. */
  machine?: string;
  cpu_model?: string;
  cpus?: number;
  nodes?: number;
  /** Mean CPU busy % over the last 10 s. */
  load?: number;
  memory_total_mb?: number;
  memory_available_mb?: number;
  /** Lobbies running. */
  lobbies: number;
  player_hosting: boolean;
  pool_games?: number;
  pool_queued?: number;
  pool_max_games?: number;
  /** Where players probe its ping (UDP, host:port). */
  rtt_echo?: string;
  checked?: string;
}

export interface ServiceSeat extends LobbySeat {
  uid?: number | null;
}

export interface ServiceObserver {
  name?: string | null;
  uid?: number | null;
  referee?: boolean | null;
  watch?: string | null;
}

/** A lobby across hosts as its viewer sees it (docs/CONTROL_SERVICE.md, "A lobby as its viewer sees it"). */
export interface ServiceLobby {
  /** `<host>/<id>`. */
  key: string;
  host: string;
  id: string;
  name?: string;
  state: string;
  phase?: string;
  beat?: number;
  /** tournament or custom, as the host has it. */
  kind?: string;
  /** organiser or player. */
  control?: string;
  /** organised (made through the service), hosted (a player's request), host (made on the host itself). */
  origin: string;
  tournament?: string;
  created_by?: { uid: number; name: string } | null;
  map?: LobbyMapRef | null;
  options?: Record<string, SettingKey> | null;
  seats: ServiceSeat[];
  observers: ServiceObserver[];
  observer_delay_seconds?: number;
  created?: string;
  started_at?: string;
  exit?: string;
  /** The lobby server's status while it runs: whole for those who run it, the presence and readiness for others. */
  status?: Partial<Status> | null;
  /** The host didn't answer at the last poll. */
  stale: boolean;
  updated?: string;
  /** The viewer's own seat and join line, or watch line. */
  you?: { seat?: number; join?: string; watch?: string } | null;
  can_operate: boolean;
  can_stop: boolean;
  /** The host's record as it came (CPUs, port, warnings, live use): for those who run it and the requesting player. */
  host_record?: Lobby | null;
}

/** A player's request for a game they host, as the host keeps it (without its key), with `ref` `<host>/<id>`. */
export interface ServiceRequest {
  ref: string;
  host: string;
  id: string;
  /** queued, starting, lobby, game, ended, refused, cancelled; unknown when the host didn't answer. */
  state: string;
  position?: number | null;
  reason?: string | null;
  player?: string | null;
  created?: string | null;
  map?: string | LobbyMapRef | null;
  lobby?: { id?: string; name?: string | null; state?: string; seats?: LobbySeat[] | null; map?: LobbyMapRef | null } | null;
  [key: string]: unknown;
}

/** `POST /api/v1/lobbies`: the host's lobby fields and the service's own (host, region, placement, tournament). */
export interface ServiceNewLobby {
  tournament?: string;
  /** Empty: the least loaded host that fits, or by the players' ping with `placement` "ping". */
  host?: string;
  region?: string;
  /** "load" (default): the least loaded host that fits; "ping": the one whose worst player ping is lowest. */
  placement?: "load" | "ping";
  name: string;
  map: string;
  seats: NewSeat[];
  observers?: { uid?: number; name: string; referee?: boolean }[];
  options?: Record<string, SettingKey>;
  observer_delay_seconds?: number;
  start_when_ready?: number;
  lobby_minutes?: number;
  cpus?: number[] | "auto";
  cores?: number;
  /** Admins only: past the planner's errors. */
  force?: boolean;
}

/** One host's row of a placement by ping. */
export interface ServicePlacementHost {
  host: string;
  region?: string;
  /** The highest ping among the players who reported this host; null when none did. */
  worst_ms: number | null;
  worst_player?: string;
  /** Players with a ping to it. */
  measured: number;
  /** Players who reported other hosts but not this one. */
  unmeasured?: string[];
  /** Players none of whose probes came back from it. */
  unreachable_for?: string[];
  load: number;
  /** Reachable, has the map and room for it. */
  candidate: boolean;
  reason?: string;
  /** The order the service tries it in, 1 first; absent when it isn't a candidate. */
  rank?: number;
}

/** How a lobby was (or would be) placed by the players' ping. */
export interface ServicePlacement {
  mode: string;
  margin_ms: number;
  /** Human seats. */
  players: number;
  measured: number;
  missing: { seat: number; uid?: number; name: string; why: string }[];
  basis: string;
  hosts: ServicePlacementHost[];
  picked?: string;
}

export interface ServiceNewRequest {
  map: string;
  /** Seat 1 is the signed-in player. */
  seats: { kind: "human" | "ai"; name?: string; ai?: string; faction?: number; team?: number }[];
  options?: Record<string, SettingKey>;
  host?: string;
  region?: string;
}

/** How a script signs in: the admin token, or a session cookie (`faf_control_session=...`). The browser needs neither. */
export interface ControlAuth {
  token?: string;
  cookie?: string;
  /** With a cookie, a change must come from an allowed origin: the web UI's (scripts say it; browsers do themselves). */
  origin?: string;
}

// ---------------------------------------------------------------- the client

function keyPath(key: string): string {
  const at = key.indexOf("/");
  return at < 0 ? encodeURIComponent(key) : `${encodeURIComponent(key.slice(0, at))}/${encodeURIComponent(key.slice(at + 1))}`;
}

/** The host part of a lobby key `<host>/<id>`. */
export function hostOfKey(key: string): string {
  const at = key.indexOf("/");
  return at < 0 ? "" : key.slice(0, at);
}

/** The lobby a page shows from the service's view: the host's record under it, its id the key `<host>/<id>`. */
export function lobbyFrom(view: ServiceLobby): Lobby {
  const record = view.host_record ?? null;
  return {
    ...(record ?? {}),
    id: view.key,
    name: view.name ?? record?.name ?? null,
    state: view.state,
    kind: view.kind ?? record?.kind ?? null,
    control: view.control ?? record?.control ?? null,
    map: view.map ?? record?.map ?? null,
    options: view.options ?? record?.options ?? null,
    seats: view.seats,
    observers: view.observers,
    observer_delay_seconds: view.observer_delay_seconds ?? null,
    created: view.created || record?.created || null,
    started_at: view.started_at || record?.started_at || null,
    phase: view.phase ?? null,
    beat: view.beat ?? null,
    exit: view.exit ?? null,
    service: view,
  };
}

export class ControlApi {
  readonly base: string;
  private readonly auth: ControlAuth;

  constructor(base: string, auth: ControlAuth = {}) {
    this.base = base.replace(/\/+$/, "");
    this.auth = auth;
  }

  private headers(json: boolean): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.auth.token !== undefined) headers.Authorization = `Bearer ${this.auth.token}`;
    if (this.auth.cookie !== undefined) headers.Cookie = this.auth.cookie;
    if (this.auth.origin !== undefined) headers.Origin = this.auth.origin;
    if (json) headers["Content-Type"] = "application/json";
    return headers;
  }

  /** The service's answer as it came, ok or not (an op's refusal is an answer, not an error). */
  async raw(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<{ status: number; answer: Answer }> {
    const response = await fetch(`${this.base}${path}`, {
      method,
      headers: this.headers(body !== undefined),
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: "include",
    });
    let answer: Answer;
    try {
      answer = (await response.json()) as Answer;
    } catch {
      answer = { ok: false };
    }
    return { status: response.status, answer };
  }

  /** One request; throws `ApiError` with the status and the service's (or the host's) reason when it isn't ok. */
  async request(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Answer> {
    const { status, answer } = await this.raw(method, path, body, signal);
    if (status < 200 || status >= 300 || !answer.ok) throw new ApiError(answer.error ?? `${method} ${path}: HTTP ${status}`, status);
    return answer;
  }

  /** `GET /api/v1/health`: answers without sign-in; a server-host doesn't have it. */
  async health(signal?: AbortSignal): Promise<Health> {
    const answer = await this.request("GET", "/api/v1/health", undefined, signal);
    if (typeof answer.store !== "string" || typeof answer.hosts !== "number") throw new ApiError(`${this.base} answered, but not as a control service`, 404);
    return answer as unknown as Health;
  }

  /** Where the browser goes to sign in with FAF; the service sends it back to `returnTo` (a page on its web UI origin). */
  loginUrl(returnTo: string): string {
    return `${this.base}/auth/login?return=${encodeURIComponent(returnTo)}`;
  }

  /** `POST /auth/logout`: ends the session. */
  async logout(): Promise<void> {
    await this.request("POST", "/auth/logout");
  }

  /** `GET /api/v1/me`: 401 when nobody is signed in. */
  async me(signal?: AbortSignal): Promise<Me> {
    const answer = await this.request("GET", "/api/v1/me", undefined, signal);
    return {
      user: (answer.user ?? { uid: 0, name: "", via: "" }) as ServiceUser,
      roles: Array.isArray(answer.roles) ? (answer.roles as string[]) : [],
      tournaments: Array.isArray(answer.tournaments) ? (answer.tournaments as ServiceTournament[]) : [],
      player_hosting: answer.player_hosting === true,
    };
  }

  async tournaments(signal?: AbortSignal): Promise<ServiceTournament[]> {
    const answer = await this.request("GET", "/api/v1/tournaments", undefined, signal);
    return Array.isArray(answer.tournaments) ? (answer.tournaments as ServiceTournament[]) : [];
  }

  async hosts(signal?: AbortSignal): Promise<ServiceHost[]> {
    const answer = await this.request("GET", "/api/v1/hosts", undefined, signal);
    return Array.isArray(answer.hosts) ? (answer.hosts as ServiceHost[]) : [];
  }

  /** `GET /api/v1/lobbies[?host=&tournament=&running=1]`. */
  async lobbies(filter: { host?: string; tournament?: string; running?: boolean } = {}, signal?: AbortSignal): Promise<ServiceLobby[]> {
    const query = new URLSearchParams();
    if (filter.host) query.set("host", filter.host);
    if (filter.tournament) query.set("tournament", filter.tournament);
    if (filter.running) query.set("running", "1");
    const text = query.toString();
    const answer = await this.request("GET", `/api/v1/lobbies${text === "" ? "" : `?${text}`}`, undefined, signal);
    return Array.isArray(answer.lobbies) ? (answer.lobbies as ServiceLobby[]) : [];
  }

  async lobby(key: string, signal?: AbortSignal): Promise<ServiceLobby> {
    return (await this.request("GET", `/api/v1/lobbies/${keyPath(key)}`, undefined, signal)).lobby as ServiceLobby;
  }

  /** `POST /api/v1/lobbies`: an organised lobby; 409 with each host's reason when none can take it now. */
  async createLobby(lobby: ServiceNewLobby): Promise<ServiceLobby> {
    return (await this.createLobbyPlaced(lobby)).lobby;
  }

  /** `POST /api/v1/lobbies` with the placement table it answers when placed by ping (else null). */
  async createLobbyPlaced(lobby: ServiceNewLobby): Promise<{ lobby: ServiceLobby; placement: ServicePlacement | null }> {
    const answer = await this.request("POST", "/api/v1/lobbies", lobby);
    return { lobby: answer.lobby as ServiceLobby, placement: (answer.placement as ServicePlacement | undefined) ?? null };
  }

  /** `POST /api/v1/placement`: where a lobby with `placement` "ping" would go now; nothing is made. */
  async placement(lobby: ServiceNewLobby, signal?: AbortSignal): Promise<ServicePlacement> {
    return (await this.request("POST", "/api/v1/placement", lobby, signal)).placement as ServicePlacement;
  }

  /** `DELETE /api/v1/lobbies/<host>/<id>`: its server stops. */
  async stopLobby(key: string): Promise<void> {
    await this.request("DELETE", `/api/v1/lobbies/${keyPath(key)}`);
  }

  /** A control op: the lobby server's answer, `ok` false with its reason when it refused. 401 and 403 throw. */
  async op(key: string, name: string, fields: Record<string, unknown> = {}): Promise<Answer> {
    const { status, answer } = await this.raw("POST", `/api/v1/lobbies/${keyPath(key)}/ops/${encodeURIComponent(name)}`, fields);
    if (status === 401 || status === 403) throw new ApiError(answer.error ?? `HTTP ${status}`, status);
    if (!answer.ok && answer.error === undefined && (status < 200 || status >= 300)) answer.error = `HTTP ${status}`;
    return answer;
  }

  /** `GET .../armies`: those who run the lobby only; the host's 400 in the lobby is passed on. */
  async armies(key: string, signal?: AbortSignal): Promise<Armies> {
    const answer = await this.request("GET", `/api/v1/lobbies/${keyPath(key)}/armies`, undefined, signal);
    const armies = answer as unknown as Armies;
    return { ...armies, armies: Array.isArray(armies.armies) ? armies.armies : [] };
  }

  async requests(signal?: AbortSignal): Promise<ServiceRequest[]> {
    const answer = await this.request("GET", "/api/v1/requests", undefined, signal);
    return Array.isArray(answer.requests) ? (answer.requests as ServiceRequest[]) : [];
  }

  async createRequest(request: ServiceNewRequest): Promise<ServiceRequest> {
    return (await this.request("POST", "/api/v1/requests", request)).request as ServiceRequest;
  }

  async cancelRequest(ref: string): Promise<ServiceRequest> {
    return (await this.request("DELETE", `/api/v1/requests/${keyPath(ref)}`)).request as ServiceRequest;
  }

  /**
   * `GET /api/v1/events[?lobby=<key>]` until `signal` aborts or the service closes it: each event's name and JSON data
   * to `onEvent` (snapshot first). `onOpen` runs once the stream is established.
   */
  async events(onEvent: (name: string, data: unknown) => void, signal: AbortSignal, onOpen?: () => void, lobby?: string): Promise<void> {
    const response = await fetch(`${this.base}/api/v1/events${lobby === undefined ? "" : `?lobby=${encodeURIComponent(lobby)}`}`, { headers: this.headers(false), signal, credentials: "include" });
    if (!response.ok || response.body === null) throw new ApiError(`events: HTTP ${response.status}`, response.status);
    onOpen?.();
    await readSse(response, (data, name) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(data) as unknown;
      } catch {
        return; // not JSON: ignored, as the stream's comments are
      }
      onEvent(name, parsed);
    });
  }

  /** One host's reads for a lobby form (organisers and admins). */
  hostApi(name: string): ControlHostApi {
    return new ControlHostApi(this, name);
  }

  /** One lobby, by key. `current` gives its last known view (for who may see what). */
  lobbyApi(key: string, current: () => ServiceLobby | undefined): ControlLobbyApi {
    return new ControlLobbyApi(this, key, current);
  }
}

// ---------------------------------------------------------------- adapters for the host views

function notHere(what: string): ApiError {
  return new ApiError(`${what} isn't available through the control service: open the host's own dashboard for it`, 404);
}

/** A host's reads through the service: `/api/v1/hosts/<name>/...`. Its base differs per host, so caches keyed by it don't mix hosts. */
export class ControlHostApi extends HostApi {
  readonly control: ControlApi;
  readonly name: string;

  constructor(control: ControlApi, name: string) {
    super(`${control.base}/api/v1/hosts/${encodeURIComponent(name)}`, "");
    this.control = control;
    this.name = name;
  }

  private path(rest: string): string {
    return `/api/v1/hosts/${encodeURIComponent(this.name)}${rest}`;
  }

  async host(signal?: AbortSignal): Promise<HostInfo> {
    const host = (await this.control.request("GET", this.path(""), undefined, signal)).host as ServiceHost | undefined;
    return {
      name: host?.machine ?? this.name,
      cpu_model: host?.cpu_model,
      cpus: [],
      memory_mb: { total: host?.memory_total_mb ?? null, available: host?.memory_available_mb ?? null },
      lobbies: host?.lobbies,
    };
  }

  async maps(signal?: AbortSignal): Promise<MapInfo[]> {
    const answer = await this.control.request("GET", this.path("/maps"), undefined, signal);
    return Array.isArray(answer.maps) ? (answer.maps as MapInfo[]) : [];
  }

  /** The host's preview path (`/api/v1/maps/<id>/preview.png`) through the service; an `<img>` sends the session cookie. */
  previewUrl(map: MapInfo): string | null {
    if (typeof map.preview !== "string" || map.preview === "") return null;
    return `${this.base}/maps/${encodeURIComponent(map.id)}/preview.png`;
  }

  async hint(players: number, km: number, signal?: AbortSignal): Promise<Hint> {
    return (await this.control.request("GET", this.path(`/hint?players=${encodeURIComponent(String(players))}&km=${encodeURIComponent(String(km))}`), undefined, signal)) as Hint;
  }

  async plan(request: PlanRequest, signal?: AbortSignal): Promise<Plan> {
    const plan = (await this.control.request("POST", this.path("/plan"), request, signal)).plan as Partial<Plan> | undefined;
    return {
      estimate: plan?.estimate ?? {},
      cores: plan?.cores ?? 0,
      cpus: Array.isArray(plan?.cpus) ? plan.cpus : [],
      nodes: Array.isArray(plan?.nodes) ? plan.nodes : [],
      fits: plan?.fits !== false,
      warnings: Array.isArray(plan?.warnings) ? plan.warnings : [],
    };
  }

  async settings(mapId?: string, signal?: AbortSignal): Promise<Settings> {
    const raw = (await this.control.request("GET", this.path(`/settings${mapId === undefined || mapId === "" ? "" : `?map=${encodeURIComponent(mapId)}`}`), undefined, signal)).settings as Partial<Settings> | undefined;
    return { options: Array.isArray(raw?.options) ? raw.options : [], ai: Array.isArray(raw?.ai) ? raw.ai : [], map_options: Array.isArray(raw?.map_options) ? raw.map_options : [] };
  }

  async lobbies(signal?: AbortSignal): Promise<Lobby[]> {
    return (await this.control.lobbies({ host: this.name }, signal)).map(lobbyFrom);
  }

  async createLobby(_lobby: NewLobby): Promise<Created> {
    throw notHere("Creating a lobby by the host's own fields");
  }

  async stopLobby(id: string): Promise<Lobby> {
    await this.control.stopLobby(id.includes("/") ? id : `${this.name}/${id}`);
    return { id, state: "stopped" };
  }

  async forgetLobby(_id: string): Promise<void> {
    throw new ApiError("The control service doesn't take lobbies off a host's list: the host's own dashboard does", 400);
  }

  async pool(): Promise<never> {
    throw notHere("Player hosting's settings");
  }

  async setPool(): Promise<never> {
    throw notHere("Player hosting's settings");
  }

  async queue(): Promise<never> {
    throw notHere("The host's queue");
  }

  async cancelQueued(): Promise<never> {
    throw notHere("The host's queue");
  }

  async moveUp(): Promise<never> {
    throw notHere("The host's queue");
  }

  async metrics(): Promise<never> {
    throw notHere("The host's metrics");
  }

  async hostLog(): Promise<never> {
    throw notHere("The host's log");
  }

  async lobbyLog(): Promise<never> {
    throw notHere("A lobby's server log");
  }

  async lobbyLogStream(): Promise<never> {
    throw notHere("A lobby's server log");
  }

  async hostLogStream(): Promise<never> {
    throw notHere("The host's log");
  }
}

/**
 * The store's api in control-service mode: lobbies across hosts by key (`<host>/<id>`), each lobby's own api, stopping;
 * maps, settings and the planner of the host `formHost()` names (the one a lobby form reads from).
 */
export class ControlRootApi extends ControlHostApi {
  private readonly formHost: () => string;
  private readonly known: (key: string) => ServiceLobby | undefined;

  constructor(control: ControlApi, formHost: () => string, known: (key: string) => ServiceLobby | undefined) {
    super(control, "");
    this.formHost = formHost;
    this.known = known;
  }

  private form(): ControlHostApi {
    return this.control.hostApi(this.formHost());
  }

  async host(signal?: AbortSignal): Promise<HostInfo> {
    return this.form().host(signal);
  }

  async maps(signal?: AbortSignal): Promise<MapInfo[]> {
    return this.form().maps(signal);
  }

  previewUrl(map: MapInfo): string | null {
    return this.form().previewUrl(map);
  }

  async hint(players: number, km: number, signal?: AbortSignal): Promise<Hint> {
    return this.form().hint(players, km, signal);
  }

  async plan(request: PlanRequest, signal?: AbortSignal): Promise<Plan> {
    return this.form().plan(request, signal);
  }

  async settings(mapId?: string, signal?: AbortSignal): Promise<Settings> {
    return this.form().settings(mapId, signal);
  }

  async lobbies(signal?: AbortSignal): Promise<Lobby[]> {
    return (await this.control.lobbies({}, signal)).map(lobbyFrom);
  }

  async stopLobby(key: string): Promise<Lobby> {
    await this.control.stopLobby(key);
    return { id: key, state: "stopped" };
  }

  lobbyApi(key: string): ServerApi {
    return this.control.lobbyApi(key, () => this.known(key));
  }

  lobbyHost(key: string): HostApi {
    return this.control.hostApi(hostOfKey(key));
  }
}

/** Why a lobby has no status to show yet, from its state. */
function noStatus(lobby: ServiceLobby): string {
  if (lobby.stale) return `the host ${lobby.host} didn't answer at the last look`;
  switch (lobby.state) {
    case "starting":
      return "the lobby's server is starting";
    case "failed":
      return `the lobby's server failed${lobby.exit ? `: ${lobby.exit}` : ""}`;
    case "stopped":
      return "the lobby was stopped";
    case "ended":
      return "the game has ended";
    default:
      return "no status from the lobby's server yet";
  }
}

/** One lobby through the service, in the shape of its own server's API (lobby.ts and controls.ts use it as is). */
export class ControlLobbyApi extends ServerApi {
  readonly control: ControlApi;
  readonly key: string;
  private readonly current: () => ServiceLobby | undefined;

  constructor(control: ControlApi, key: string, current: () => ServiceLobby | undefined) {
    super(`${control.base}/api/v1/lobbies/${keyPath(key)}`, "");
    this.control = control;
    this.key = key;
    this.current = current;
  }

  /** The lobby server's status as the service last read it (every poll, at once after an event). */
  async status(signal?: AbortSignal): Promise<Status> {
    const lobby = await this.control.lobby(this.key, signal);
    const status = lobby.status;
    if (status === undefined || status === null || typeof status.phase !== "string") throw new ApiError(noStatus(lobby), 503);
    return { id: 0, ...status, ok: true, phase: status.phase, seats: Array.isArray(status.seats) ? status.seats : [] } as Status;
  }

  /** Those who run the lobby only (a player would see the enemy's economy): for others, as if the server had none. */
  async armies(signal?: AbortSignal): Promise<Armies> {
    if (this.current()?.can_operate === false) throw new ApiError("the armies are for those who run the lobby", 404);
    return this.control.armies(this.key, signal);
  }

  async op(name: string, fields: Record<string, unknown> = {}): Promise<Answer> {
    return this.control.op(this.key, name, fields);
  }

  /** The lobby server's events as the service relays them (to those who run the lobby; players get none). */
  async events(onEvent: (event: ServerEvent) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    await this.control.events(
      (name, data) => {
        if (name !== "lobby_event" || data === null || typeof data !== "object") return;
        const relayed = data as { key?: string; event?: string; data?: unknown };
        if (relayed.key !== this.key) return;
        const inner = relayed.data;
        if (inner !== null && typeof inner === "object" && typeof (inner as ServerEvent).event === "string") onEvent(inner as ServerEvent);
        else onEvent({ ...(inner !== null && typeof inner === "object" ? (inner as Record<string, unknown>) : { text: inner }), event: relayed.event ?? "message" });
      },
      signal,
      onOpen,
      this.key,
    );
  }
}

// ---------------------------------------------------------------- roles, for the page

/** May the viewer make organised lobbies of tournament `id` ("" = outside tournaments)? The service decides; this hides what it would refuse. */
export function canOrganise(me: Me | null, id: string): boolean {
  if (me === null) return false;
  if (me.roles.includes("admin")) return true;
  if (id === "") return globalOrganiser(me);
  if (globalOrganiser(me)) return true;
  return me.tournaments.some((tournament) => tournament.id === id && tournament.you.includes("organiser"));
}

/**
 * A global organiser (every tournament, and lobbies outside them). The service doesn't say it outright: an organiser
 * who sees a tournament's lists without organising it, or who organises none, is one.
 */
export function globalOrganiser(me: Me | null): boolean {
  if (me === null) return false;
  if (me.roles.includes("admin")) return true;
  if (!me.roles.includes("organiser")) return false;
  const own = me.tournaments.filter((tournament) => tournament.you.includes("organiser"));
  return own.length === 0 || me.tournaments.some((tournament) => !tournament.you.includes("organiser") && Array.isArray(tournament.players));
}

/** The tournaments the viewer may make lobbies for. */
export function organisedTournaments(me: Me | null): ServiceTournament[] {
  return (me?.tournaments ?? []).filter((tournament) => canOrganise(me, tournament.id));
}

/** The viewer's highest role, for a badge: admin, organiser or player. */
export function topRole(me: Me | null): "admin" | "organiser" | "player" {
  if (me?.roles.includes("admin")) return "admin";
  if (me?.roles.includes("organiser")) return "organiser";
  return "player";
}
