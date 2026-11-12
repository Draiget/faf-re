// The machine map: the machine by NUMA node, each node's physical cores with their hyperthread siblings as CPU cells.
// A cell shows its load (colour), the lobby it is pinned to (a ring in the lobby's colour), whether it belongs to the
// player-hosting pool (hatched), and, when picking, whether it is picked or where Auto would put the game. Used on the
// overview (look), the create flow's placement (pick CPUs) and player hosting (pick whole cores for the pool).

import type { HostCpu, HostNode } from "../api.ts";
import { fill, h, icon, isNumber } from "../dom.ts";
import { gb, meter } from "./parts.ts";
import { colour, coreKey, cpuLoad, displayName, holderOf, nodeOf, nodesOf, plural, poolCpus, store } from "./store.ts";

export interface MachineOptions {
  /** "view": cells open their lobby; "pick": cells toggle. */
  mode: "view" | "pick";
  /** Picking toggles a whole core (both siblings). */
  wholeCores?: boolean;
  /** The picked CPUs (pick mode). */
  selected?: () => ReadonlySet<number>;
  /** Where the planner would put it. */
  planned?: () => ReadonlySet<number>;
  /** The CPUs drawn as the pool; default: the host's pool. */
  pool?: () => ReadonlySet<number>;
  /** Pick mode: CPUs turned on or off. */
  onToggle?(cpus: number[], on: boolean): void;
  /** Pick mode: per node "use all" and "none" buttons. */
  nodeButtons?: boolean;
  /** What a picked cell means, for the legend ("Picked", "In the pool"). */
  pickedLabel?: string;
}

export class MachineMap {
  readonly root: HTMLElement;
  private readonly options: MachineOptions;
  private readonly legend: HTMLElement;
  private readonly nodesBox: HTMLElement;
  private readonly cells = new Map<number, HTMLElement>();
  private readonly heads = new Map<number, HTMLElement>();
  private signature = "";

  constructor(options: MachineOptions) {
    this.options = options;
    this.legend = h("div", { class: "legend", "aria-label": "Legend" });
    this.nodesBox = h("div", { class: "nodes" });
    this.root = h("div", { class: `machine machine-${options.mode}` }, this.legend, this.nodesBox);
    this.renderLegend();
    this.update();
  }

  private renderLegend(): void {
    const item = (cell: string, text: string): HTMLElement => h("span", { class: "legend-item" }, h("span", { class: `legend-cell ${cell}`, "aria-hidden": "true" }), text);
    fill(this.legend, 
      h("span", { class: "legend-item" }, h("span", {}, "Load"), h("span", { class: "legend-bar", "aria-hidden": "true" }), h("span", { class: "dim" }, "0 → 100%")),
      item("held", "Used by a lobby (its colour)"),
      item("pool", "Player-hosting pool"),
      this.options.mode === "pick" ? item("picked", this.options.pickedLabel ?? "Picked") : null,
      this.options.planned !== undefined ? item("planned", "Where Auto puts it") : null,
    );
  }

  private build(): void {
    const info = store.info;
    if (info === null) return;
    this.cells.clear();
    this.heads.clear();
    const byId = new Map(info.cpus.map((cpu) => [cpu.id, cpu]));
    this.nodesBox.replaceChildren(
      ...nodesOf().map((node) => {
        const cores = new Map<string, HostCpu[]>();
        for (const id of node.cpus) {
          const cpu = byId.get(id);
          if (cpu === undefined) continue;
          cores.set(coreKey(cpu), [...(cores.get(coreKey(cpu)) ?? []), cpu]);
        }
        const ordered = [...cores.values()].map((siblings) => siblings.sort((a, b) => a.id - b.id)).sort((a, b) => (a[0]?.id ?? 0) - (b[0]?.id ?? 0));
        const head = h("div", { class: "node-head" });
        this.heads.set(node.id, head);
        return h(
          "section",
          { class: "node", "aria-label": `NUMA node ${node.id}` },
          head,
          h(
            "div",
            { class: "cores" },
            ...ordered.map((siblings) =>
              h(
                "div",
                { class: `core${siblings.length > 1 ? " smt" : ""}`, title: `Core ${siblings[0]?.core ?? "?"}: CPU ${siblings.map((cpu) => cpu.id).join(" and ")}` },
                ...siblings.map((cpu) => {
                  const cell = this.options.mode === "pick" ? h("button", { type: "button", class: "cpu" }) : h("a", { class: "cpu" });
                  const id = cpu.id;
                  if (this.options.mode === "pick") cell.addEventListener("click", () => this.toggle(id));
                  this.cells.set(cpu.id, cell);
                  return cell;
                }),
              ),
            ),
          ),
        );
      }),
    );
  }

  private toggle(id: number): void {
    const selected = this.options.selected?.() ?? new Set<number>();
    const cpus = this.options.wholeCores === true ? this.coreOf(id) : [id];
    this.options.onToggle?.(cpus, !selected.has(id));
  }

  private coreOf(id: number): number[] {
    const cpu = store.info?.cpus.find((item) => item.id === id);
    if (cpu === undefined) return [id];
    const key = coreKey(cpu);
    return (store.info?.cpus ?? []).filter((other) => coreKey(other) === key).map((other) => other.id);
  }

  private renderHead(node: HostNode): void {
    const head = this.heads.get(node.id);
    if (head === undefined) return;
    const cpus = (store.info?.cpus ?? []).filter((cpu) => node.cpus.includes(cpu.id));
    const cores = new Set(cpus.map(coreKey)).size;
    const load = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
    const pool = this.options.pool?.() ?? poolCpus();
    const inPool = cpus.filter((cpu) => pool.has(cpu.id)).length;
    const planned = this.options.planned?.() ?? new Set<number>();
    const total = node.memory_mb?.total;
    const free = node.memory_mb?.free;
    const buttons: HTMLElement[] = [];
    if (this.options.mode === "pick" && this.options.nodeButtons === true) {
      const all = h("button", { type: "button", class: "btn small" }, `Use all of node ${node.id}`);
      all.addEventListener("click", () => this.options.onToggle?.(node.cpus, true));
      const none = h("button", { type: "button", class: "btn small ghost" }, "None");
      none.addEventListener("click", () => this.options.onToggle?.(node.cpus, false));
      buttons.push(all, none);
    }
    fill(head, 
      h(
        "div",
        { class: "node-title" },
        h("h3", {}, `Node ${node.id}`),
        cpus.some((cpu) => planned.has(cpu.id)) ? h("span", { class: "chip tiny tone-accent" }, "Auto puts it here") : null,
        inPool > 0 ? h("span", { class: "chip tiny pool-chip" }, `${inPool} in the pool`) : null,
        buttons.length > 0 ? h("span", { class: "node-buttons" }, ...buttons) : null,
      ),
      h("p", { class: "node-sub" }, `${plural(cpus.length, "CPU")} · ${plural(cores, "core")} · ${Math.round(load)}% busy`),
      isNumber(total) && total > 0 && isNumber(free)
        ? h(
            "div",
            { class: "node-mem" },
            h("span", { class: "small" }, "Memory ", h("b", {}, `${gb(free)} free`), h("span", { class: "dim" }, ` of ${gb(total)}`)),
            meter(`Node ${node.id} memory in use`, total - free, total, `${gb(total - free)} of ${gb(total)} in use`, free / total < 0.1 ? "bad" : free / total < 0.25 ? "warn" : ""),
          )
        : h("span", { class: "dim small" }, "memory unknown"),
    );
  }

  /** Redraws from the store (and the options' sets). */
  update(): void {
    const info = store.info;
    if (info === null) {
      this.nodesBox.replaceChildren(h("p", { class: "dim" }, "Not connected."));
      this.signature = "";
      return;
    }
    const sig = nodesOf()
      .map((node) => `${node.id}:${node.cpus.join(",")}`)
      .concat(info.cpus.map((cpu) => `${cpu.id}/${coreKey(cpu)}`))
      .join("|");
    if (sig !== this.signature) {
      this.signature = sig;
      this.build();
    }
    for (const node of nodesOf()) this.renderHead(node);
    const selected = this.options.selected?.() ?? new Set<number>();
    const planned = this.options.planned?.() ?? new Set<number>();
    const pool = this.options.pool?.() ?? poolCpus();
    for (const cpu of info.cpus) {
      const cell = this.cells.get(cpu.id);
      if (cell === undefined) continue;
      const load = cpuLoad(cpu);
      const holder = holderOf(cpu.id);
      cell.style.setProperty("--heat-h", String(Math.round(140 - 140 * Math.min(1, Math.max(0, load) / 100))));
      cell.style.setProperty("--heat-mix", `${Math.round(10 + 0.7 * Math.min(100, Math.max(0, load)))}%`);
      if (holder !== undefined) cell.style.setProperty("--hold", colour(holder.id));
      else cell.style.removeProperty("--hold");
      cell.classList.toggle("held", holder !== undefined);
      cell.classList.toggle("pool", pool.has(cpu.id));
      cell.classList.toggle("picked", selected.has(cpu.id));
      cell.classList.toggle("planned", planned.has(cpu.id));
      cell.classList.toggle("hot", load >= 70);
      if (this.options.mode === "pick") cell.setAttribute("aria-pressed", String(selected.has(cpu.id)));
      else if (holder !== undefined) cell.setAttribute("href", `#/lobby/${encodeURIComponent(holder.id)}`);
      else cell.removeAttribute("href");
      const where = `core ${isNumber(cpu.core) ? cpu.core : "?"}, node ${nodeOf(cpu)}`;
      const lines = [
        `CPU ${cpu.id} (${where})`,
        `${Math.round(load)}% busy`,
        holder === undefined ? "Free" : `Lobby: ${displayName(holder)}`,
        pool.has(cpu.id) ? "In the player-hosting pool" : "",
        planned.has(cpu.id) ? "Auto puts the new game here" : "",
        selected.has(cpu.id) ? (this.options.pickedLabel ?? "Picked") : "",
      ].filter((line) => line !== "");
      cell.title = lines.join("\n");
      cell.setAttribute("aria-label", lines.join(", "));
      fill(cell, 
        h("span", { class: "cpu-id" }, String(cpu.id)),
        h("span", { class: "cpu-load" }, `${Math.round(load)}%`),
        holder === undefined ? null : h("span", { class: "cpu-dot", "aria-hidden": "true" }),
        selected.has(cpu.id) ? h("span", { class: "cpu-check", "aria-hidden": "true" }, icon("check")) : null,
      );
    }
  }
}
