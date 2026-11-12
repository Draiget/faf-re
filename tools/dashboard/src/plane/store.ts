// The control plane's shared state (plan WP17.19): what the host last said, what the operator picked, and the plan
// for what they're configuring. Modules read it and listen for the topics they draw.

import type { HostApi, HostCpu, HostInfo, Lobby, Plan, Slot } from "../api.ts";
import { isNumber } from "../dom.ts";

export type Topic = "host" | "lists" | "plan" | "picked";

export interface Store {
  api: HostApi | null;
  info: HostInfo | null;
  lobbies: Lobby[];
  slots: Slot[];
  /** False when the host answers 404 for /api/v1/slots (before WP17.18). */
  slotsSupported: boolean;
  /** CPUs clicked on the heatmap for what's being configured. */
  picked: Set<number>;
  /** Auto placement, or the picked cells. */
  auto: boolean;
  /** The plan for what's being configured, or null. */
  plan: Plan | null;
  /** The plan is being asked for. */
  planning: boolean;
}

export const store: Store = {
  api: null,
  info: null,
  lobbies: [],
  slots: [],
  slotsSupported: true,
  picked: new Set(),
  auto: true,
  plan: null,
  planning: false,
};

/** What one module asks of another without importing it (set by their owners). */
export const actions = {
  /** Show the configuration panel for a lobby or for slots. */
  configure: (_kind: "lobby" | "slots"): void => undefined,
  /** Ask the host again now. */
  refresh: (): void => undefined,
};

const listeners = new Map<Topic, Set<() => void>>();

export function on(topic: Topic, listener: () => void): void {
  const set = listeners.get(topic) ?? new Set();
  set.add(listener);
  listeners.set(topic, set);
}

export function emit(topic: Topic): void {
  for (const listener of listeners.get(topic) ?? []) listener();
}

// ---------------------------------------------------------------- helpers over the host's answer

export const RUNNING = new Set(["starting", "lobby", "game", "ended"]);
/** Slot states that hold their CPUs. */
export const SLOT_HOLDING = new Set(["open", "claimed", "lobby", "game", "ended"]);

export function hue(id: string): number {
  let hash = 0;
  for (const char of id) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return Math.round((hash * 137.508) % 360);
}

export function colour(id: string): string {
  return `hsl(${hue(id)} 72% 52%)`;
}

export function lobbyById(id: string): Lobby | undefined {
  return store.lobbies.find((lobby) => lobby.id === id);
}

/** The slot a lobby came from, if it was a claimed slot's. */
export function slotOfLobby(id: string): Slot | undefined {
  return store.slots.find((slot) => slot.lobby === id);
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

export function coreKey(cpu: HostCpu): string {
  return `${nodeOf(cpu)}:${isNumber(cpu.socket) ? cpu.socket : 0}:${isNumber(cpu.core) ? cpu.core : `cpu${cpu.id}`}`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

export function displayName(item: { id: string; name?: string | null }): string {
  return item.name || item.id;
}

/** What holds a CPU: lobbies (solid) and slots (dashed). A claimed slot's lobby counts once, as the slot. */
export interface Holder {
  id: string;
  kind: "lobby" | "slot";
  name: string;
}

export function holdersOf(cpuId: number): Holder[] {
  const holders: Holder[] = [];
  const slotLobbies = new Set(store.slots.map((slot) => slot.lobby).filter((id): id is string => typeof id === "string"));
  for (const slot of store.slots) {
    if (SLOT_HOLDING.has(slot.state) && (slot.cpus ?? []).includes(cpuId)) holders.push({ id: slot.id, kind: "slot", name: displayName(slot) });
  }
  for (const lobby of store.lobbies) {
    if (slotLobbies.has(lobby.id) || !RUNNING.has(lobby.state)) continue;
    if ((lobby.cpus ?? []).includes(cpuId)) holders.push({ id: lobby.id, kind: "lobby", name: displayName(lobby) });
  }
  return holders;
}
