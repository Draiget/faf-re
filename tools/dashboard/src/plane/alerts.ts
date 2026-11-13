// What needs the operator's eye now, read from the store: failed lobbies, placements forced past an error or on the
// pool's CPUs, low memory, a busy machine or link, long waits in the queue, a full queue, a pool without CPUs.

import { isNumber } from "../dom.ts";
import { service } from "../service.ts";
import { ageSeconds, cpuLoad, displayName, duration, RUNNING, store } from "./store.ts";

export interface Alert {
  tone: "bad" | "warn";
  text: string;
  /** Where to look: a hash route. */
  href?: string;
}

const LONG_WAIT_S = 15 * 60;

/** Through the control service: hosts that don't answer or run short, failed lobbies, lobbies of a silent host. */
function serviceAlerts(): Alert[] {
  const out: Alert[] = [];
  for (const host of service.hosts) {
    if (!host.reachable) {
      out.push({ tone: "bad", text: `Host ${host.name} doesn't answer the control service`, href: "#/" });
      continue;
    }
    if (isNumber(host.load) && host.load > 85) out.push({ tone: "warn", text: `Host ${host.name} is ${Math.round(host.load)}% busy`, href: "#/" });
    const total = host.memory_total_mb;
    const available = host.memory_available_mb;
    if (isNumber(total) && isNumber(available) && total > 0 && available / total < 0.1) out.push({ tone: "warn", text: `Host ${host.name} has ${Math.round((available / total) * 100)}% of its memory free`, href: "#/" });
  }
  for (const lobby of store.lobbies) {
    const href = `#/lobby/${encodeURIComponent(lobby.id)}`;
    if (lobby.state === "failed" && lobby.service?.can_stop === true) out.push({ tone: "bad", text: `${displayName(lobby)} failed${lobby.exit ? `: ${lobby.exit}` : ""}`, href });
    if (lobby.service?.stale === true && RUNNING.has(lobby.state)) out.push({ tone: "warn", text: `${displayName(lobby)}: its host didn't answer at the last look; what's shown may be old`, href });
  }
  return out;
}

export function currentAlerts(): Alert[] {
  if (store.mode === "service") return serviceAlerts();
  const out: Alert[] = [];
  const info = store.info;
  if (info === null) return out;
  for (const lobby of store.lobbies) {
    const href = `#/lobby/${encodeURIComponent(lobby.id)}`;
    if (lobby.state === "failed") out.push({ tone: "bad", text: `${displayName(lobby)} failed${lobby.exit ? `: ${lobby.exit}` : ""}`, href });
    if (!RUNNING.has(lobby.state)) continue;
    const warnings = lobby.warnings ?? [];
    if (warnings.some((warning) => warning.severity === "error")) out.push({ tone: "warn", text: `${displayName(lobby)} was started despite a placement error`, href });
    if (warnings.some((warning) => warning.code === "pool_overlap")) out.push({ tone: "warn", text: `${displayName(lobby)} runs on CPUs now in the player-hosting pool; they go to the pool when it ends`, href });
  }
  const total = info.memory_mb?.total;
  const available = info.memory_mb?.available;
  if (isNumber(total) && isNumber(available) && total > 0) {
    const free = available / total;
    if (free < 0.1) out.push({ tone: "bad", text: `Memory is almost full: ${Math.round(free * 100)}% free`, href: "#/metrics" });
    else if (free < 0.2) out.push({ tone: "warn", text: `Memory is getting low: ${Math.round(free * 100)}% free`, href: "#/metrics" });
  }
  for (const node of info.nodes ?? []) {
    const nodeTotal = node.memory_mb?.total;
    const nodeFree = node.memory_mb?.free;
    if (isNumber(nodeTotal) && isNumber(nodeFree) && nodeTotal > 0 && nodeFree / nodeTotal < 0.1) out.push({ tone: "warn", text: `Node ${node.id} has ${Math.round((nodeFree / nodeTotal) * 100)}% of its memory free: games placed there reach across nodes`, href: "#/metrics" });
  }
  const cpus = info.cpus;
  const load = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
  if (load > 85) out.push({ tone: "warn", text: `The machine is ${Math.round(load)}% busy`, href: "#/metrics" });
  for (const link of info.links ?? []) {
    const capacity = isNumber(link.speed_mbps) && link.speed_mbps > 0 ? link.speed_mbps * 125 : 0;
    if (capacity > 0 && isNumber(link.out_kbps) && link.out_kbps / capacity > 0.8) out.push({ tone: "warn", text: `${link.name} sends at ${Math.round((link.out_kbps / capacity) * 100)}% of its speed`, href: "#/metrics" });
  }
  for (const item of store.queue) {
    const waited = ageSeconds(item.created);
    if (waited !== null && waited > LONG_WAIT_S) out.push({ tone: "warn", text: `${item.name ?? item.id} has waited ${duration(waited)} for ${waitingText(item.waiting_for)}`, href: "#/queue" });
  }
  const pool = store.pool;
  if (pool !== null && pool.pool.enabled) {
    if (pool.pool.cpus.length === 0) out.push({ tone: "warn", text: "Player hosting is on but has no CPUs: every request waits", href: "#/hosting" });
    if (pool.pool.max_queue > 0 && pool.usage.queued >= pool.pool.max_queue) out.push({ tone: "warn", text: `The player queue is full (${pool.usage.queued}): new requests are refused`, href: "#/hosting" });
  }
  return out;
}

/** What a queued item waits for, in plain words. */
export function waitingText(reason: string | null | undefined): string {
  switch (reason) {
    case "cores":
      return "free CPU cores";
    case "memory":
      return "free memory";
    case "games":
      return "a free game place";
    case "ports":
      return "a free port";
    case "network":
      return "network room";
    case "":
      return "nothing: it starts next";
    default:
      return reason ? reason : "room";
  }
}
