// Capacity (plan WP17.16, WP17.19): the machine by NUMA node, each node's CPUs as a heatmap of physical cores with their
// hyperthread siblings, its memory, the network links, and what is allocated to which lobby or slot with its live use.

import type { HostCpu, HostLink, HostNode } from "../api.ts";
import { byId, fill, h, isNumber, num, type Child } from "../dom.ts";
import { colour, coreKey, cpuLoad, displayName, emit, holdersOf, nodeOf, on, plural, RUNNING, SLOT_HOLDING, store } from "./store.ts";

const machineName = byId<HTMLElement>("plane-host-name");
const machineModel = byId<HTMLElement>("plane-host-model");
const machineTiles = byId<HTMLElement>("plane-tiles");
const nodesBox = byId<HTMLElement>("plane-nodes");
const linksBox = byId<HTMLElement>("plane-links");
const allocBox = byId<HTMLElement>("plane-alloc");
const pickedText = byId<HTMLElement>("plane-picked");
const pickedClear = byId<HTMLButtonElement>("plane-picked-clear");

export function gb(mb: number): string {
  return `${(mb / 1024).toFixed(mb >= 100 * 1024 ? 0 : 1)} GB`;
}

/** KB/s for people. */
export function rate(kbs: unknown): string {
  if (!isNumber(kbs)) return "–";
  if (kbs >= 1000) return `${(kbs / 1000).toFixed(kbs >= 10000 ? 0 : 1)} MB/s`;
  return `${kbs.toFixed(kbs < 10 ? 1 : 0)} KB/s`;
}

function speed(mbps: unknown): string {
  if (!isNumber(mbps) || mbps <= 0) return "speed unknown";
  return mbps >= 1000 ? `${num(mbps / 1000, 1)} Gbit/s` : `${mbps} Mbit/s`;
}

function bar(label: string, value: number, max: number, text: string, tone = ""): HTMLElement {
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  const fillEl = h("span", { class: "fill" });
  fillEl.style.width = `${(ratio * 100).toFixed(1)}%`;
  return h(
    "div",
    { class: `bar${tone === "" ? "" : ` tone-${tone}`}`, role: "meter", "aria-label": label, "aria-valuemin": 0, "aria-valuemax": max, "aria-valuenow": Math.round(value), "aria-valuetext": text },
    fillEl,
  );
}

function tile(label: string, value: Child, sub?: Child): HTMLElement {
  return h("div", { class: "tile" }, h("dt", {}, label), h("dd", {}, value), sub === undefined ? null : h("span", { class: "tile-sub" }, sub));
}

// ---------------------------------------------------------------- machine

function renderMachine(): void {
  const info = store.info;
  if (info === null) return;
  machineName.textContent = info.name ?? "Host";
  machineModel.textContent = info.cpu_model ?? "CPU model unknown";
  const cpus = info.cpus;
  const cores = new Set(cpus.map(coreKey)).size;
  const nodeCount = info.nodes?.length ?? new Set(cpus.map(nodeOf)).size;
  const average = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
  const total = info.memory_mb?.total;
  const available = info.memory_mb?.available;
  const running = store.lobbies.filter((lobby) => RUNNING.has(lobby.state)).length;
  const holding = store.slots.filter((slot) => SLOT_HOLDING.has(slot.state)).length;
  const memory =
    isNumber(total) && total > 0 && isNumber(available)
      ? tile("Memory", h("span", {}, gb(available), h("span", { class: "dim small" }, ` free of ${gb(total)}`)), bar("Machine memory in use", total - available, total, `${gb(total - available)} of ${gb(total)} in use`, available / total < 0.1 ? "bad" : available / total < 0.25 ? "warn" : ""))
      : tile("Memory", "–");
  machineTiles.replaceChildren(
    tile("CPUs", String(cpus.length), `${plural(cores, "core")} · ${plural(nodeCount, "NUMA node")}`),
    tile("Load (10 s)", `${Math.round(average)}%`),
    memory,
    tile("In use", `${running} ${running === 1 ? "lobby" : "lobbies"}`, store.slotsSupported ? `${plural(holding, "slot")} held` : "slots: not on this host"),
  );
}

// ---------------------------------------------------------------- nodes and the heatmap

const cells = new Map<number, HTMLButtonElement>();
const nodeHeads = new Map<number, HTMLElement>();
let signature = "";

function nodesOf(): HostNode[] {
  const info = store.info;
  if (info === null) return [];
  if (info.nodes !== undefined && info.nodes.length > 0) return [...info.nodes].sort((a, b) => a.id - b.id);
  // No topology from the host: one node per socket.
  const byNode = new Map<number, number[]>();
  for (const cpu of info.cpus) byNode.set(nodeOf(cpu), [...(byNode.get(nodeOf(cpu)) ?? []), cpu.id]);
  return [...byNode.entries()].sort((a, b) => a[0] - b[0]).map(([id, list]) => ({ id, cpus: list }));
}

function buildNodes(): void {
  const info = store.info;
  if (info === null) return;
  cells.clear();
  nodeHeads.clear();
  const byId = new Map(info.cpus.map((cpu) => [cpu.id, cpu]));
  nodesBox.replaceChildren(
    ...nodesOf().map((node) => {
      // Physical cores of this node, each with its hyperthread siblings.
      const cores = new Map<string, HostCpu[]>();
      for (const id of node.cpus) {
        const cpu = byId.get(id);
        if (cpu === undefined) continue;
        const key = coreKey(cpu);
        cores.set(key, [...(cores.get(key) ?? []), cpu]);
      }
      const ordered = [...cores.values()]
        .map((siblings) => siblings.sort((a, b) => a.id - b.id))
        .sort((a, b) => (a[0]?.id ?? 0) - (b[0]?.id ?? 0));
      const head = h("div", { class: "node-head" });
      nodeHeads.set(node.id, head);
      return h(
        "section",
        { class: "node", "aria-label": `NUMA node ${node.id}` },
        head,
        h(
          "div",
          { class: "cores" },
          ...ordered.map((siblings) => {
            const first = siblings[0];
            return h(
              "div",
              { class: `core${siblings.length > 1 ? " smt" : ""}`, title: first && isNumber(first.core) ? `Core ${first.core}, socket ${first.socket ?? 0}` : "Core" },
              ...siblings.map((cpu) => {
                const cell = h("button", { type: "button", class: "cpu" });
                const id = cpu.id;
                cell.addEventListener("click", () => toggle(id));
                cells.set(cpu.id, cell);
                return cell;
              }),
            );
          }),
        ),
      );
    }),
  );
}

function renderNodeHead(node: HostNode): void {
  const head = nodeHeads.get(node.id);
  if (head === undefined) return;
  const info = store.info;
  const cpus = (info?.cpus ?? []).filter((cpu) => node.cpus.includes(cpu.id));
  const cores = new Set(cpus.map(coreKey)).size;
  const load = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
  const total = node.memory_mb?.total;
  const free = node.memory_mb?.free;
  const planned = store.plan?.nodes.includes(node.id) === true;
  fill(
    head,
    h("h3", {}, `Node ${node.id}`, planned ? h("span", { class: "chip tiny tone-accent" }, "planned") : null),
    h("span", { class: "dim small" }, `${plural(cpus.length, "CPU")} · ${plural(cores, "core")} · ${Math.round(load)}% load`),
    isNumber(total) && total > 0 && isNumber(free)
      ? h(
          "div",
          { class: "node-mem" },
          h("span", { class: "small" }, h("b", {}, gb(free)), h("span", { class: "dim" }, ` free of ${gb(total)}`)),
          bar(`Node ${node.id} memory in use`, total - free, total, `${gb(total - free)} of ${gb(total)} in use`, free / total < 0.1 ? "bad" : free / total < 0.25 ? "warn" : ""),
        )
      : h("span", { class: "dim small" }, "memory unknown"),
  );
}

function renderCells(): void {
  const info = store.info;
  if (info === null) return;
  const planned = new Set(store.plan?.cpus ?? []);
  for (const cpu of info.cpus) {
    const cell = cells.get(cpu.id);
    if (cell === undefined) continue;
    const load10 = cpuLoad(cpu);
    const load = isNumber(cpu.load) ? cpu.load : load10;
    const holders = holdersOf(cpu.id);
    const first = holders[0];
    cell.style.setProperty("--heat-h", String(Math.round(140 - 140 * Math.min(1, Math.max(0, load10) / 100))));
    cell.style.setProperty("--heat-mix", `${Math.round(14 + 0.72 * Math.min(100, Math.max(0, load10)))}%`);
    if (first !== undefined) cell.style.setProperty("--hold", colour(first.id));
    else cell.style.removeProperty("--hold");
    cell.classList.toggle("held", first?.kind === "lobby");
    cell.classList.toggle("held-slot", first?.kind === "slot");
    cell.classList.toggle("picked", store.picked.has(cpu.id));
    cell.classList.toggle("planned", planned.has(cpu.id));
    cell.classList.toggle("hot", load10 >= 70);
    cell.setAttribute("aria-pressed", String(store.picked.has(cpu.id)));
    const where = `core ${isNumber(cpu.core) ? cpu.core : "?"}, socket ${isNumber(cpu.socket) ? cpu.socket : 0}, node ${nodeOf(cpu)}`;
    const held = holders.length === 0 ? "free" : holders.map((holder) => `${holder.kind} ${holder.name}`).join(", ");
    cell.title = `CPU ${cpu.id} (${where})\nLoad ${Math.round(load)}% now, ${Math.round(load10)}% over 10 s\n${holders.length === 0 ? "Free" : holders.map((holder) => `${holder.kind === "slot" ? "Slot" : "Lobby"}: ${holder.name}`).join("\n")}${planned.has(cpu.id) ? "\nPlanned for the new one" : ""}`;
    cell.setAttribute("aria-label", `CPU ${cpu.id}, ${where}, load ${Math.round(load)} percent, ${Math.round(load10)} over 10 seconds, ${held}${planned.has(cpu.id) ? ", planned" : ""}`);
    fill(
      cell,
      h("span", { class: "cpu-id" }, String(cpu.id)),
      h("span", { class: "cpu-load" }, `${Math.round(load10)}%`),
      holders.length === 0
        ? null
        : h(
            "span",
            { class: "cpu-dots", "aria-hidden": "true" },
            ...holders.slice(0, 3).map((holder) => {
              const dot = h("span", { class: `cpu-dot${holder.kind === "slot" ? " slot" : ""}` });
              dot.style.setProperty("--dot", colour(holder.id));
              return dot;
            }),
          ),
    );
  }
}

function renderNodes(): void {
  const info = store.info;
  if (info === null) return;
  const sig = nodesOf()
    .map((node) => `${node.id}:${node.cpus.join(",")}`)
    .concat(info.cpus.map((cpu) => `${cpu.id}/${coreKey(cpu)}`))
    .join("|");
  if (sig !== signature) {
    signature = sig;
    buildNodes();
  }
  for (const id of [...store.picked]) {
    if (!cells.has(id)) store.picked.delete(id);
  }
  for (const node of nodesOf()) renderNodeHead(node);
  renderCells();
  renderPicked();
}

function toggle(id: number): void {
  if (store.picked.has(id)) store.picked.delete(id);
  else store.picked.add(id);
  store.auto = store.picked.size === 0 ? store.auto : false;
  renderCells();
  renderPicked();
  emit("picked");
}

function renderPicked(): void {
  const list = [...store.picked].sort((a, b) => a - b);
  pickedText.textContent =
    list.length === 0 ? "Click CPUs to place the new lobby or slots by hand; Auto places them otherwise." : `Picked by hand: CPU ${list.join(", ")}`;
  pickedClear.hidden = list.length === 0;
}

pickedClear.addEventListener("click", () => {
  store.picked.clear();
  store.auto = true;
  renderCells();
  renderPicked();
  emit("picked");
});

// ---------------------------------------------------------------- links

function renderLinks(): void {
  const links: HostLink[] = store.info?.links ?? [];
  if (links.length === 0) {
    linksBox.replaceChildren(h("p", { class: "dim small" }, "The host reports no network links."));
    return;
  }
  linksBox.replaceChildren(
    ...links.map((link) => {
      const capacity = isNumber(link.speed_mbps) && link.speed_mbps > 0 ? link.speed_mbps * 125 : 0;
      const out = isNumber(link.out_kbps) ? link.out_kbps : 0;
      const ratio = capacity > 0 ? out / capacity : 0;
      return h(
        "div",
        { class: "link" },
        h("div", { class: "link-head" }, h("strong", {}, link.name), h("span", { class: "dim small" }, speed(link.speed_mbps))),
        h("div", { class: "link-rates small" }, h("span", {}, "↑ ", h("b", {}, rate(link.out_kbps))), h("span", {}, "↓ ", h("b", {}, rate(link.in_kbps)))),
        capacity > 0 ? bar(`${link.name} upload`, out, capacity, `${rate(out)} of ${rate(capacity)}`, ratio > 0.9 ? "bad" : ratio > 0.7 ? "warn" : "") : null,
      );
    }),
  );
}

// ---------------------------------------------------------------- allocations

interface Allocation {
  id: string;
  kind: "lobby" | "slot";
  name: string;
  state: string;
  cpus: number[];
  nodes: number[];
  cpuCores: number | null;
  rssMb: number | null;
  lobby: string | null;
}

function allocations(): Allocation[] {
  const out: Allocation[] = [];
  const slotLobbies = new Set(store.slots.map((slot) => slot.lobby).filter((id): id is string => typeof id === "string"));
  for (const lobby of store.lobbies) {
    if (!RUNNING.has(lobby.state) || slotLobbies.has(lobby.id)) continue;
    out.push({
      id: lobby.id,
      kind: "lobby",
      name: displayName(lobby),
      state: lobby.state,
      cpus: (lobby.cpus ?? []).filter(isNumber),
      nodes: (lobby.nodes ?? []).filter(isNumber),
      cpuCores: isNumber(lobby.usage?.cpu_cores) ? lobby.usage.cpu_cores : null,
      rssMb: isNumber(lobby.usage?.rss_mb) ? lobby.usage.rss_mb : null,
      lobby: lobby.id,
    });
  }
  for (const slot of store.slots) {
    if (!SLOT_HOLDING.has(slot.state)) continue;
    const lobby = typeof slot.lobby === "string" ? store.lobbies.find((candidate) => candidate.id === slot.lobby) : undefined;
    out.push({
      id: slot.id,
      kind: "slot",
      name: displayName(slot),
      state: slot.state,
      cpus: (slot.cpus ?? []).filter(isNumber),
      nodes: (slot.nodes ?? []).filter(isNumber),
      cpuCores: isNumber(lobby?.usage?.cpu_cores) ? lobby.usage.cpu_cores : null,
      rssMb: isNumber(lobby?.usage?.rss_mb) ? lobby.usage.rss_mb : null,
      lobby: lobby?.id ?? null,
    });
  }
  return out;
}

function renderAllocations(): void {
  const list = allocations();
  if (list.length === 0) {
    allocBox.replaceChildren(h("p", { class: "dim small" }, "Nothing is allocated: every CPU is free."));
    return;
  }
  allocBox.replaceChildren(
    h(
      "div",
      { class: "table-scroll" },
      h(
        "table",
        { class: "mini alloc" },
        h(
          "thead",
          {},
          h(
            "tr",
            {},
            h("th", { scope: "col" }, "Allocated to"),
            h("th", { scope: "col" }, "CPUs"),
            h("th", { scope: "col" }, "Node"),
            h("th", { scope: "col" }, "CPU use"),
            h("th", { scope: "col", class: "num" }, "Memory"),
          ),
        ),
        h(
          "tbody",
          {},
          ...list.map((item) => {
            const swatch = h("span", { class: `swatch${item.kind === "slot" ? " slot" : ""}`, "aria-hidden": "true" });
            swatch.style.setProperty("--swatch", colour(item.id));
            const allocated = Math.max(1, item.cpus.length);
            const use =
              item.cpuCores === null
                ? h("span", { class: "dim" }, item.kind === "slot" && item.lobby === null ? "held" : "–")
                : h(
                    "div",
                    { class: "use" },
                    bar(`${item.name} CPU use`, item.cpuCores, allocated, `${num(item.cpuCores, 2)} of ${allocated} cores`, item.cpuCores / allocated > 0.9 ? "bad" : item.cpuCores / allocated > 0.7 ? "warn" : ""),
                    h("span", { class: "small" }, `${num(item.cpuCores, 2)} / ${allocated}`),
                  );
            return h(
              "tr",
              {},
              h(
                "td",
                {},
                swatch,
                item.lobby !== null ? h("a", { href: `#/lobby/${encodeURIComponent(item.lobby)}` }, item.name) : h("span", {}, item.name),
                h("span", { class: "dim small" }, ` · ${item.kind === "slot" ? "slot" : "lobby"}, ${item.state}`),
              ),
              h("td", { class: "num-left" }, item.cpus.join(", ") || "–"),
              h("td", {}, item.nodes.length === 0 ? "–" : item.nodes.join(", ")),
              h("td", {}, use),
              h("td", { class: "num" }, item.rssMb === null ? "–" : `${item.rssMb} MB`),
            );
          }),
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------- wiring

function renderAll(): void {
  renderMachine();
  renderNodes();
  renderLinks();
  renderAllocations();
}

on("host", renderAll);
on("lists", () => {
  renderMachine();
  renderCells();
  renderAllocations();
});
on("plan", () => {
  for (const node of nodesOf()) renderNodeHead(node);
  renderCells();
});
on("picked", () => {
  renderCells();
  renderPicked();
});

export function resetCapacity(): void {
  cells.clear();
  nodeHeads.clear();
  signature = "";
  nodesBox.replaceChildren();
  linksBox.replaceChildren();
  allocBox.replaceChildren();
  machineTiles.replaceChildren();
}
