// The dashboard on the control service: who is signed in, the hosts it follows, and the lobbies across them, kept live
// from its event stream (a snapshot, then each host and lobby that changes) and fed into the shared store, so the
// views draw them as they draw one host's. Reconnects after a break; each reconnect starts with a fresh snapshot.

import { ApiError } from "./api.ts";
import { ControlRootApi, hostOfKey, lobbyFrom, type ControlApi, type Me, type ServiceHost, type ServiceLobby } from "./control.ts";
import { actions, displayName, emit, RUNNING, store } from "./plane/store.ts";

const RETRY_MS = 3000;
const ME_MS = 60000;

export interface ServiceChange {
  at: number;
  tone: "ok" | "bad" | "warn" | "info";
  text: string;
  lobby?: string;
}

export interface ServiceState {
  api: ControlApi | null;
  me: Me | null;
  hosts: ServiceHost[];
  /** "" for every host; else the overview and the lobby list show this one. */
  hostFilter: string;
  /** The host a lobby form reads its maps, settings and plan from. */
  formHost: string;
  /** The event stream is open. */
  live: boolean;
  /** What changed while the page watched, newest first. */
  changes: ServiceChange[];
}

export const service: ServiceState = { api: null, me: null, hosts: [], hostFilter: "", formHost: "", live: false, changes: [] };

export interface ServiceCallbacks {
  /** The stream opened (null) or broke (why); `signedOut` when the session is gone. */
  onHealth(error: string | null, signedOut: boolean): void;
}

let stream: AbortController | null = null;
let meTimer: number | undefined;
let callbacks: ServiceCallbacks | null = null;
const views = new Map<string, ServiceLobby>();

/** The service's last view of a lobby, by key. */
export function serviceLobby(key: string): ServiceLobby | undefined {
  return views.get(key);
}

/** Why a host doesn't answer, without the service's own "host <name> didn't answer:" before it. */
export function hostError(host: ServiceHost): string {
  const text = (host.error ?? "").replace(new RegExp(`^host ${host.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} didn't answer: `), "");
  return text.trim();
}

export function hostByName(name: string): ServiceHost | undefined {
  return service.hosts.find((host) => host.name === name);
}

/** The reachable hosts, least loaded first (players' views carry no load: then by name). */
export function reachableHosts(): ServiceHost[] {
  return service.hosts.filter((host) => host.reachable).sort((a, b) => (a.load ?? 0) - (b.load ?? 0) || a.name.localeCompare(b.name));
}

function remember(change: Omit<ServiceChange, "at">): void {
  service.changes.unshift({ ...change, at: Date.now() });
  if (service.changes.length > 60) service.changes.length = 60;
}

const STATE_WORDS: Record<string, [ServiceChange["tone"], string]> = {
  lobby: ["ok", "is open"],
  game: ["ok", "started its game"],
  ended: ["info", "ended its game"],
  failed: ["bad", "failed"],
  stopped: ["info", "was stopped"],
};

function putLobby(view: ServiceLobby, quiet: boolean): void {
  const before = views.get(view.key);
  views.set(view.key, view);
  if (!quiet) {
    const name = view.name || view.key;
    if (before === undefined) remember({ tone: "info", text: `${name} was created on ${view.host}`, lobby: view.key });
    else if (before.state !== view.state && STATE_WORDS[view.state] !== undefined) {
      const [tone, words] = STATE_WORDS[view.state] ?? ["info", view.state];
      remember({ tone, text: `${name} ${words}${view.state === "failed" && view.exit ? `: ${view.exit}` : ""}`, lobby: view.key });
    }
  }
}

function publishLobbies(): void {
  store.lobbies = [...views.values()].map(lobbyFrom).sort((a, b) => a.id.localeCompare(b.id));
  emit("lists");
  emit("alerts");
}

function putHost(host: ServiceHost): void {
  const before = hostByName(host.name);
  if (before !== undefined && before.reachable !== host.reachable) remember({ tone: host.reachable ? "ok" : "bad", text: `Host ${host.name} ${host.reachable ? "answers again" : `stopped answering${host.error ? `: ${host.error}` : ""}`}` });
  service.hosts = [...service.hosts.filter((item) => item.name !== host.name), host].sort((a, b) => a.name.localeCompare(b.name));
  if (service.formHost === "" || hostByName(service.formHost) === undefined) service.formHost = reachableHosts()[0]?.name ?? host.name;
}

function onEvent(name: string, data: unknown): void {
  if (data === null || typeof data !== "object") return;
  const item = data as Record<string, unknown>;
  switch (name) {
    case "snapshot": {
      service.hosts = [];
      for (const host of Array.isArray(item.hosts) ? (item.hosts as ServiceHost[]) : []) putHost(host);
      views.clear();
      for (const lobby of Array.isArray(item.lobbies) ? (item.lobbies as ServiceLobby[]) : []) putLobby(lobby, true);
      publishLobbies();
      emit("service");
      emit("host");
      break;
    }
    case "host":
      putHost(item as unknown as ServiceHost);
      emit("service");
      emit("host");
      emit("alerts");
      break;
    case "host_removed":
      service.hosts = service.hosts.filter((host) => host.name !== item.name);
      emit("service");
      emit("host");
      break;
    case "lobby":
      putLobby(item as unknown as ServiceLobby, false);
      publishLobbies();
      break;
    case "lobby_removed": {
      const key = String(item.key ?? "");
      const gone = views.get(key);
      if (views.delete(key)) {
        remember({ tone: "info", text: `${gone?.name || key} left ${hostOfKey(key)}'s list` });
        publishLobbies();
      }
      break;
    }
  }
}

function follow(api: ControlApi): void {
  stream?.abort();
  const controller = new AbortController();
  stream = controller;
  api
    .events(onEvent, controller.signal, () => {
      if (stream !== controller) return;
      service.live = true;
      emit("service");
      callbacks?.onHealth(null, false);
    })
    .then(
      () => retry(null),
      (error: unknown) => retry(error),
    );
  function retry(error: unknown): void {
    if (controller.signal.aborted || stream !== controller) return;
    service.live = false;
    emit("service");
    const signedOut = error instanceof ApiError && error.status === 401;
    callbacks?.onHealth(error === null ? "the service closed the event stream" : error instanceof Error ? error.message : String(error), signedOut);
    if (signedOut) return;
    window.setTimeout(() => {
      if (stream === controller) follow(api);
    }, RETRY_MS);
  }
}

/** Reads the lobbies again now (after a change this page made, before its event comes). */
async function refresh(): Promise<void> {
  const api = service.api;
  if (api === null) return;
  try {
    const list = await api.lobbies({}, AbortSignal.timeout(5000));
    if (service.api !== api) return;
    for (const lobby of list) putLobby(lobby, false);
    const keys = new Set(list.map((lobby) => lobby.key));
    for (const key of [...views.keys()]) if (!keys.has(key)) views.delete(key);
    publishLobbies();
  } catch {
    // the stream catches up
  }
}

/** Shows the service as `me`: the store's api becomes the service's, then the event stream keeps it live. */
export function startService(api: ControlApi, me: Me, events: ServiceCallbacks): void {
  stopService();
  service.api = api;
  service.me = me;
  callbacks = events;
  store.mode = "service";
  store.api = new ControlRootApi(api, () => service.formHost, serviceLobby);
  store.poolSupported = false;
  store.queueSupported = false;
  store.metricsSupported = false;
  store.logsSupported = false;
  actions.refresh = (): void => void refresh();
  follow(api);
  // Roles change when the service reads its configuration again: look now and then.
  meTimer = window.setInterval(() => {
    void api.me(AbortSignal.timeout(5000)).then(
      (next) => {
        if (service.api !== api) return;
        if (JSON.stringify(next) !== JSON.stringify(service.me)) {
          service.me = next;
          emit("service");
        }
      },
      (error: unknown) => {
        if (error instanceof ApiError && error.status === 401) callbacks?.onHealth("the session ended", true);
      },
    );
  }, ME_MS);
  emit("service");
}

export function stopService(): void {
  stream?.abort();
  stream = null;
  window.clearInterval(meTimer);
  meTimer = undefined;
  callbacks = null;
  views.clear();
  service.api = null;
  service.me = null;
  service.hosts = [];
  service.hostFilter = "";
  service.formHost = "";
  service.live = false;
  service.changes = [];
  if (store.mode === "service") {
    store.api = null;
    store.lobbies = [];
    actions.refresh = (): void => undefined;
  }
  store.mode = "host";
}

/** Running lobbies on a host, as the viewer sees them. */
export function runningOn(host: string): ServiceLobby[] {
  return [...views.values()].filter((lobby) => lobby.host === host && RUNNING.has(lobby.state));
}

/** For a toast: a lobby's name. */
export function lobbyName(key: string): string {
  const view = views.get(key);
  return view === undefined ? key : displayName({ id: key, name: view.name });
}
