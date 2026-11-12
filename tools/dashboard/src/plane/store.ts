// The dashboard's shared state: what the host last said (machine, lobbies, pool, queue, metrics), and helpers over
// it. Views read it and listen for the topics they draw; host.ts polls the host and emits.

import type { HostApi, HostCpu, HostInfo, HostNode, Lobby, Metrics, PoolView, QueueItem } from "../api.ts";
import { isNumber } from "../dom.ts";

export type Topic = "host" | "lists" | "pool" | "queue" | "metrics" | "alerts";

export interface Store {
  api: HostApi | null;
  info: HostInfo | null;
  lobbies: Lobby[];
  /** Null before the first answer, or when the host has no pool (404). */
  pool: PoolView | null;
  poolSupported: boolean;
  queue: QueueItem[];
  queueSupported: boolean;
  /** The last few minutes of host history: the host's, or gathered from polls when it has no metrics. */
  metrics: Metrics | null;
  metricsSupported: boolean;
  logsSupported: boolean;
}

export const store: Store = {
  api: null,
  info: null,
  lobbies: [],
  pool: null,
  poolSupported: true,
  queue: [],
  queueSupported: true,
  metrics: null,
  metricsSupported: true,
  logsSupported: true,
};

/** What one module asks of another without importing it (set by their owners). */
export const actions = {
  /** Ask the host again now. */
  refresh: (): void => undefined,
};

const listeners = new Map<Topic, Set<() => void>>();

export function on(topic: Topic, listener: () => void): () => void {
  const set = listeners.get(topic) ?? new Set();
  set.add(listener);
  listeners.set(topic, set);
  return () => set.delete(listener);
}

export function emit(topic: Topic): void {
  for (const listener of listeners.get(topic) ?? []) listener();
}

// ---------------------------------------------------------------- helpers over the host's answer

/** Lobby states that hold their CPUs. */
export const RUNNING = new Set(["starting", "lobby", "game"]);
/** States a lobby page can still talk to (an ended game's server answers until it exits). */
export const LIVE = new Set(["starting", "lobby", "game", "ended"]);

export function hue(id: string): number {
  let hash = 0;
  for (const char of id) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return Math.round((hash * 137.508) % 360);
}

export function colour(id: string): string {
  return `hsl(${hue(id)} 68% 50%)`;
}

export function lobbyById(id: string): Lobby | undefined {
  return store.lobbies.find((lobby) => lobby.id === id);
}

export function cpuById(id: number): HostCpu | undefined {
  return store.info?.cpus.find((cpu) => cpu.id === id);
}

export function cpuLoad(cpu: HostCpu): number {
  return isNumber(cpu.load10) ? cpu.load10 : isNumber(cpu.load) ? cpu.load : 0;
}

/** A CPU's NUMA node: its own field, else the node that lists it, else its socket. */
export function nodeOf(cpu: HostCpu): number {
  if (isNumber(cpu.node)) return cpu.node;
  const listed = store.info?.nodes?.find((node) => node.cpus.includes(cpu.id));
  if (listed !== undefined) return listed.id;
  return isNumber(cpu.socket) ? cpu.socket : 0;
}

/** A physical core: its node, socket and core id (hyperthread siblings share it). */
export function coreKey(cpu: HostCpu): string {
  return `${nodeOf(cpu)}:${isNumber(cpu.socket) ? cpu.socket : 0}:${isNumber(cpu.core) ? cpu.core : `cpu${cpu.id}`}`;
}

/** Every CPU of the same physical core as `id` (itself included). */
export function siblingsOf(id: number): number[] {
  const cpu = cpuById(id);
  if (cpu === undefined) return [id];
  const key = coreKey(cpu);
  return (store.info?.cpus ?? []).filter((other) => coreKey(other) === key).map((other) => other.id);
}

/** The machine's NUMA nodes; one per socket when the host gives no topology. */
export function nodesOf(): HostNode[] {
  const info = store.info;
  if (info === null) return [];
  if (info.nodes !== undefined && info.nodes.length > 0) return [...info.nodes].sort((a, b) => a.id - b.id);
  const byNode = new Map<number, number[]>();
  for (const cpu of info.cpus) byNode.set(nodeOf(cpu), [...(byNode.get(nodeOf(cpu)) ?? []), cpu.id]);
  return [...byNode.entries()].sort((a, b) => a[0] - b[0]).map(([id, list]) => ({ id, cpus: list }));
}

export function coresOf(cpus: number[]): number {
  return new Set(cpus.map((id) => cpuById(id)).filter((cpu): cpu is HostCpu => cpu !== undefined).map(coreKey)).size;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

export function displayName(item: { id: string; name?: string | null }): string {
  return item.name || item.id;
}

/** The CPUs the player-hosting pool holds now (none when it's off). */
export function poolCpus(): Set<number> {
  const view = store.pool;
  return new Set(view !== null && view.pool.enabled ? view.pool.cpus : []);
}

/** A lobby made from a player's request runs on the pool. */
export function isPoolLobby(lobby: Lobby): boolean {
  return lobby.side === "pool" || (typeof lobby.request === "string" && lobby.request !== "");
}

/** tournament or custom: the lobby's own kind, else what its control says. */
export function kindOf(lobby: Lobby): "tournament" | "custom" {
  if (lobby.kind === "tournament" || lobby.kind === "custom") return lobby.kind;
  return lobby.control === "organiser" ? "tournament" : "custom";
}

/** The running lobby holding a CPU, if any. */
export function holderOf(cpuId: number): Lobby | undefined {
  return store.lobbies.find((lobby) => RUNNING.has(lobby.state) && (lobby.cpus ?? []).includes(cpuId));
}

/** Seconds since an ISO time, or null. */
export function ageSeconds(time: string | null | undefined): number | null {
  if (typeof time !== "string" || time === "") return null;
  const at = Date.parse(time);
  return Number.isFinite(at) ? Math.max(0, (Date.now() - at) / 1000) : null;
}

/** "45 s", "12 min", "3 h 5 min". */
export function duration(seconds: number | null): string {
  if (seconds === null) return "–";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.round((seconds % 3600) / 60);
  return minutes === 0 ? `${hours} h` : `${hours} h ${minutes} min`;
}
