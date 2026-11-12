// The control plane (plan WP17.16-WP17.20): one page for a machine's server-host. Capacity by NUMA node with what is
// allocated and its live use (plane/capacity.ts), the tournament lobbies and open slots that use it (plane/lists.ts),
// and the configuration panel that plans and creates either (plane/config.ts). A lobby opens in the server view
// (main.ts) through the host's proxy.

import "./host.css";
import { ApiError, type HostApi, type HostInfo, type Lobby } from "./api.ts";
import { resetCapacity } from "./plane/capacity.ts";
import { resetConfig, startConfig } from "./plane/config.ts";
import { resetLists, stateChip as listStateChip } from "./plane/lists.ts";
import { actions, emit, hue, lobbyById as findLobby, store } from "./plane/store.ts";

const POLL_MS = 2000;
const REQUEST_MS = 5000;

export interface HostCallbacks {
  /** Each poll's outcome: null when the host answered, else why not (and whether the token was refused). */
  onHealth(error: string | null, unauthorized: boolean): void;
  /** The lobby list changed (the server view's lobby bar follows it). */
  onLobbies(lobbies: Lobby[]): void;
}

let callbacks: HostCallbacks | null = null;
let timer: number | undefined;
let polling = false;

export function lobbyById(id: string): Lobby | undefined {
  return findLobby(id);
}

export function lobbyHue(id: string): number {
  return hue(id);
}

export function stateChip(state: string): HTMLElement {
  return listStateChip(state);
}

async function poll(): Promise<void> {
  const api = store.api;
  if (api === null || polling) return;
  polling = true;
  try {
    const slots = store.slotsSupported
      ? api.slots(AbortSignal.timeout(REQUEST_MS)).catch((error: unknown) => {
          // A host before WP17.18 has no slots: the list says so and the panel offers lobbies only.
          if (error instanceof ApiError && error.status === 404) {
            store.slotsSupported = false;
            return [];
          }
          throw error;
        })
      : Promise.resolve([]);
    const [host, lobbies, slotList] = await Promise.all([api.host(AbortSignal.timeout(REQUEST_MS)), api.lobbies(AbortSignal.timeout(REQUEST_MS)), slots]);
    if (store.api !== api) return;
    store.info = host;
    store.lobbies = lobbies;
    store.slots = slotList;
    emit("lists");
    emit("host");
    callbacks?.onHealth(null, false);
    callbacks?.onLobbies(lobbies);
  } catch (error) {
    if (store.api !== api) return;
    callbacks?.onHealth(error instanceof Error ? error.message : String(error), error instanceof ApiError && error.status === 401);
  } finally {
    polling = false;
  }
}

actions.refresh = (): void => void poll();

/** Shows this host: its first answer, then polls every 2 s until `stopHost`. */
export function startHost(api: HostApi, first: HostInfo, events: HostCallbacks): void {
  stopHost();
  store.api = api;
  store.info = first;
  callbacks = events;
  emit("host");
  startConfig();
  timer = window.setInterval(() => void poll(), POLL_MS);
  void poll();
}

export function stopHost(): void {
  window.clearInterval(timer);
  timer = undefined;
  callbacks = null;
  store.api = null;
  store.info = null;
  store.lobbies = [];
  store.slots = [];
  store.slotsSupported = true;
  store.picked.clear();
  store.auto = true;
  store.plan = null;
  store.planning = false;
  resetCapacity();
  resetLists();
  resetConfig();
}
