// Polls the host every 2 s (the machine, lobbies, the pool, the queue) and its metrics every 4 s, feeds the shared store
// and keeps what changed between polls as the recent events the overview shows. A host without the pool, queue or
// metrics (404) is shown without them; without metrics the top bar's history is gathered from the polls.

import { ApiError, type HostApi, type HostInfo, type Lobby, type Metrics, type QueueItem } from "./api.ts";
import { isNumber } from "./dom.ts";
import { actions, cpuLoad, displayName, emit, RUNNING, store } from "./plane/store.ts";

const POLL_MS = 2000;
const METRICS_MS = 4000;
const REQUEST_MS = 5000;
/** How much history the store keeps for the top bar and the overview. */
export const RECENT_SECONDS = 600;

export interface HostCallbacks {
  /** Each poll's outcome: null when the host answered, else why not (and whether the token was refused). */
  onHealth(error: string | null, unauthorized: boolean): void;
}

export interface HostEvent {
  at: number;
  tone: "ok" | "bad" | "warn" | "info";
  text: string;
  /** The lobby it is about, for a link. */
  lobby?: string;
}

/** What changed while the page watched, newest first. */
export const recentEvents: HostEvent[] = [];

let callbacks: HostCallbacks | null = null;
let timer: number | undefined;
let metricsTimer: number | undefined;
let polling = false;
let first = true;

function remember(event: Omit<HostEvent, "at">): void {
  recentEvents.unshift({ ...event, at: Date.now() });
  if (recentEvents.length > 60) recentEvents.length = 60;
}

const STATE_EVENT: Record<string, [HostEvent["tone"], string]> = {
  lobby: ["ok", "is open"],
  game: ["ok", "started its game"],
  ended: ["info", "ended its game"],
  failed: ["bad", "failed"],
  stopped: ["info", "was stopped"],
};

/** Compares the new answer with the last one and remembers what changed. */
function diff(before: { lobbies: Lobby[]; queue: QueueItem[]; pool: boolean | null }, after: { lobbies: Lobby[]; queue: QueueItem[]; pool: boolean | null }): void {
  const old = new Map(before.lobbies.map((lobby) => [lobby.id, lobby]));
  for (const lobby of after.lobbies) {
    const was = old.get(lobby.id);
    if (was === undefined) {
      remember({ tone: "info", text: `${displayName(lobby)} was created${lobby.queued_at ? " from the queue" : ""}`, lobby: lobby.id });
    } else if (was.state !== lobby.state && STATE_EVENT[lobby.state] !== undefined) {
      const [tone, words] = STATE_EVENT[lobby.state] ?? ["info", lobby.state];
      remember({ tone, text: `${displayName(lobby)} ${words}${lobby.state === "failed" && lobby.exit ? `: ${lobby.exit}` : ""}`, lobby: lobby.id });
    }
  }
  const queued = new Set(before.queue.map((item) => item.id));
  for (const item of after.queue) if (!queued.has(item.id)) remember({ tone: "warn", text: `${item.name ?? item.id} is waiting in the ${item.side === "pool" ? "player" : "operator"} queue` });
  const still = new Set(after.queue.map((item) => item.id));
  for (const item of before.queue) if (!still.has(item.id)) remember({ tone: "info", text: `${item.name ?? item.id} left the queue` });
  if (before.pool !== null && after.pool !== null && before.pool !== after.pool) remember({ tone: "info", text: `Player hosting was turned ${after.pool ? "on" : "off"}` });
}

/** Without the host's metrics: one sample per poll, from the machine's answer, the last 10 minutes. */
function sampleFromPoll(info: HostInfo, lobbies: Lobby[]): void {
  const now = Math.round(Date.now() / 1000);
  const m: Metrics = store.metrics ?? { t: [], cpu: [], mem_used_mb: [], net: {}, nodes: {}, lobbies: {} };
  const n = m.t.length;
  const push = <T>(list: T[], value: T): void => void list.push(value);
  push(m.t, now);
  const cpus = info.cpus;
  push(m.cpu, cpus.length === 0 ? null : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length);
  const total = info.memory_mb?.total;
  const available = info.memory_mb?.available;
  push(m.mem_used_mb, isNumber(total) && isNumber(available) ? total - available : null);
  const fill = (): null[] => Array.from({ length: n }, () => null);
  for (const link of info.links ?? []) {
    const series = (m.net[link.name] ??= { in_kbps: fill(), out_kbps: fill() });
    push(series.in_kbps, isNumber(link.in_kbps) ? link.in_kbps : null);
    push(series.out_kbps, isNumber(link.out_kbps) ? link.out_kbps : null);
  }
  for (const node of info.nodes ?? []) {
    const own = cpus.filter((cpu) => node.cpus.includes(cpu.id));
    const series = (m.nodes[String(node.id)] ??= { cpu: fill(), mem_free_mb: fill() });
    push(series.cpu, own.length === 0 ? null : own.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / own.length);
    push(series.mem_free_mb, isNumber(node.memory_mb?.free) ? node.memory_mb.free : null);
  }
  for (const lobby of lobbies) {
    if (!RUNNING.has(lobby.state)) continue;
    const series = (m.lobbies[lobby.id] ??= { cpu_cores: fill(), rss_mb: fill() });
    push(series.cpu_cores, isNumber(lobby.usage?.cpu_cores) ? lobby.usage.cpu_cores : null);
    push(series.rss_mb, isNumber(lobby.usage?.rss_mb) ? lobby.usage.rss_mb : null);
  }
  // Every series as long as t; then drop what is older than the window.
  const length = m.t.length;
  const pad = (list: (number | null)[]): void => {
    while (list.length < length) list.push(null);
  };
  for (const link of Object.values(m.net)) [link.in_kbps, link.out_kbps].forEach(pad);
  for (const node of Object.values(m.nodes)) [node.cpu, node.mem_free_mb].forEach(pad);
  for (const lobby of Object.values(m.lobbies)) [lobby.cpu_cores, lobby.rss_mb].forEach(pad);
  const drop = m.t.findIndex((t) => t >= now - RECENT_SECONDS);
  if (drop > 0) {
    const cut = (list: (number | null)[]): void => void list.splice(0, drop);
    m.t.splice(0, drop);
    [m.cpu, m.mem_used_mb].forEach(cut);
    for (const link of Object.values(m.net)) [link.in_kbps, link.out_kbps].forEach(cut);
    for (const node of Object.values(m.nodes)) [node.cpu, node.mem_free_mb].forEach(cut);
    for (const lobby of Object.values(m.lobbies)) [lobby.cpu_cores, lobby.rss_mb].forEach(cut);
  }
  store.metrics = m;
  emit("metrics");
}

function optional<T>(supported: boolean, request: () => Promise<T>, unsupported: () => void, fallback: T): Promise<T> {
  if (!supported) return Promise.resolve(fallback);
  return request().catch((error: unknown) => {
    if (error instanceof ApiError && error.status === 404) {
      unsupported();
      return fallback;
    }
    throw error;
  });
}

async function poll(): Promise<void> {
  const api = store.api;
  if (api === null || polling) return;
  polling = true;
  try {
    const [host, lobbies, pool, queue] = await Promise.all([
      api.host(AbortSignal.timeout(REQUEST_MS)),
      api.lobbies(AbortSignal.timeout(REQUEST_MS)),
      optional(store.poolSupported, () => api.pool(AbortSignal.timeout(REQUEST_MS)), () => (store.poolSupported = false), null),
      optional(store.queueSupported, () => api.queue(AbortSignal.timeout(REQUEST_MS)), () => (store.queueSupported = false), [] as QueueItem[]),
    ]);
    if (store.api !== api) return;
    if (!first) diff({ lobbies: store.lobbies, queue: store.queue, pool: store.pool?.pool.enabled ?? null }, { lobbies, queue, pool: pool?.pool.enabled ?? null });
    first = false;
    store.info = host;
    store.lobbies = lobbies;
    store.pool = pool;
    store.queue = queue;
    if (!store.metricsSupported) sampleFromPoll(host, lobbies);
    emit("host");
    emit("lists");
    emit("pool");
    emit("queue");
    emit("alerts");
    callbacks?.onHealth(null, false);
  } catch (error) {
    if (store.api !== api) return;
    callbacks?.onHealth(error instanceof Error ? error.message : String(error), error instanceof ApiError && error.status === 401);
  } finally {
    polling = false;
  }
}

async function pollMetrics(): Promise<void> {
  const api = store.api;
  if (api === null || !store.metricsSupported) return;
  try {
    const metrics = await api.metrics(RECENT_SECONDS, AbortSignal.timeout(REQUEST_MS));
    if (store.api !== api) return;
    store.metrics = metrics;
    emit("metrics");
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) store.metricsSupported = false;
  }
}

actions.refresh = (): void => void poll();

/** Shows this host: its first answer, then polls until `stopHost`. */
export function startHost(api: HostApi, info: HostInfo, events: HostCallbacks): void {
  stopHost();
  store.api = api;
  store.info = info;
  callbacks = events;
  first = true;
  emit("host");
  timer = window.setInterval(() => void poll(), POLL_MS);
  metricsTimer = window.setInterval(() => void pollMetrics(), METRICS_MS);
  void poll();
  void pollMetrics();
}

export function stopHost(): void {
  window.clearInterval(timer);
  window.clearInterval(metricsTimer);
  timer = undefined;
  metricsTimer = undefined;
  callbacks = null;
  store.api = null;
  store.info = null;
  store.lobbies = [];
  store.pool = null;
  store.poolSupported = true;
  store.queue = [];
  store.queueSupported = true;
  store.metrics = null;
  store.metricsSupported = true;
  store.logsSupported = true;
  recentEvents.length = 0;
}
