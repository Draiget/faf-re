// Metrics: the host's history as charts, over the last 5 minutes, 15 minutes or hour: the machine's CPU, CPU by NUMA
// node, memory in use, free memory by node, each network link's traffic, and each lobby's CPU and memory. A lobby's
// own page draws its two charts with `LobbyCharts`. Lobby colours stay the same while the page is open.

import type { Metrics } from "../api.ts";
import { LineChart, seriesColor } from "../chart.ts";
import { byId, h, isNumber, num } from "../dom.ts";
import { rate } from "../plane/parts.ts";
import { displayName, lobbyById, on, store } from "../plane/store.ts";
import { pageHead, type View } from "./common.ts";

const REFRESH_MS = 4000;
const RANGES: [number, string][] = [
  [300, "5 minutes"],
  [900, "15 minutes"],
  [3600, "1 hour"],
];

const lobbyColours = new Map<string, number>();
/** A lobby keeps its colour in every chart while the page is open. */
export function lobbyColour(id: string): string {
  let index = lobbyColours.get(id);
  if (index === undefined) {
    index = lobbyColours.size;
    lobbyColours.set(id, index);
  }
  return seriesColor(index);
}

const pct = (value: number): string => `${Math.round(value)}%`;
const gbText = (mb: number): string => `${num(mb / 1024, mb >= 10240 || mb % 1024 === 0 ? 0 : 1)} GB`;
const mbText = (mb: number): string => (mb >= 1024 ? gbText(mb) : `${Math.round(mb)} MB`);
const coresText = (value: number): string => num(value, value < 10 ? 2 : 1);

function chartCard(title: string, sub: string, chart: LineChart, wide = false): HTMLElement {
  return h("section", { class: `card chart-card${wide ? " wide" : ""}` }, h("div", { class: "card-head" }, h("h2", {}, title), h("span", { class: "card-meta" }, sub)), chart.root);
}

async function fetchMetrics(seconds: number): Promise<Metrics | null> {
  const api = store.api;
  if (api === null) return null;
  if (!store.metricsSupported) return store.metrics;
  try {
    return await api.metrics(seconds, AbortSignal.timeout(8000));
  } catch {
    return store.metrics;
  }
}

export function metricsView(): View {
  const root = byId<HTMLElement>("view-metrics");
  let range = 900;
  let timer: number | undefined;
  const chips = h("div", { class: "seg-chips", role: "group", "aria-label": "Time range" });
  const note = h("p", { class: "note tone-warn", hidden: true }, "This host keeps no history: the charts hold what this page has seen since it connected, every 2 s.");
  const cpu = new LineChart({ label: "Machine CPU busy, percent", format: pct, max: 100 });
  const nodesCpu = new LineChart({ label: "CPU busy by NUMA node, percent", format: pct, max: 100 });
  const mem = new LineChart({ label: "Memory in use", format: gbText, unit: 1024 });
  const nodesMem = new LineChart({ label: "Free memory by NUMA node", format: gbText, unit: 1024 });
  const lobbiesCpu = new LineChart({ label: "CPU by lobby, cores", format: coresText });
  const lobbiesMem = new LineChart({ label: "Memory by lobby", format: mbText, unit: 1024 });
  const netBox = h("div", { class: "chart-grid" });
  const netCharts = new Map<string, LineChart>();
  const lobbyNote = h("span", {});
  root.replaceChildren(
    pageHead("Metrics", "A sample every 2 seconds, kept for an hour. Hover a chart to read every line at that time.", chips),
    note,
    h(
      "div",
      { class: "chart-grid" },
      chartCard("Machine CPU", "busy, all CPUs", cpu),
      chartCard("CPU by NUMA node", "busy, each node's CPUs", nodesCpu),
      chartCard("Memory in use", "the whole machine", mem),
      chartCard("Free memory by NUMA node", "a game's memory stays on its node", nodesMem),
    ),
    h("h2", { class: "section-title" }, "Network"),
    netBox,
    h("h2", { class: "section-title" }, "Lobbies ", h("span", { class: "dim small" }, lobbyNote)),
    h("div", { class: "chart-grid" }, chartCard("CPU by lobby", "cores used by each lobby's server", lobbiesCpu), chartCard("Memory by lobby", "each lobby's server process", lobbiesMem)),
  );

  function renderChips(): void {
    chips.replaceChildren(
      ...RANGES.map(([seconds, text]) => {
        const button = h("button", { type: "button", class: "seg-chip", "aria-pressed": String(range === seconds) }, text);
        button.addEventListener("click", () => {
          range = seconds;
          renderChips();
          void refresh();
        });
        return button;
      }),
    );
  }

  function draw(m: Metrics | null): void {
    note.hidden = store.metricsSupported;
    if (m === null) return;
    const t = m.t;
    cpu.update({ t, series: [{ name: "Machine", values: m.cpu, color: seriesColor(0) }] });
    const nodeIds = Object.keys(m.nodes).sort((a, b) => Number(a) - Number(b));
    nodesCpu.update({ t, series: nodeIds.map((id, i) => ({ name: `Node ${id}`, values: m.nodes[id]?.cpu ?? [], color: seriesColor(i) })) });
    mem.update({ t, series: [{ name: "In use", values: m.mem_used_mb, color: seriesColor(1) }] });
    nodesMem.update({ t, series: nodeIds.map((id, i) => ({ name: `Node ${id}`, values: m.nodes[id]?.mem_free_mb ?? [], color: seriesColor(i) })) });
    const links = Object.keys(m.net).sort();
    for (const name of [...netCharts.keys()]) if (!links.includes(name)) netCharts.delete(name);
    for (const name of links) {
      if (!netCharts.has(name)) netCharts.set(name, new LineChart({ label: `Network link ${name}`, format: (value) => rate(value) }));
    }
    netBox.replaceChildren(
      ...(links.length === 0
        ? [h("p", { class: "dim" }, "No network links in the history.")]
        : links.map((name) => {
            const chart = netCharts.get(name) as LineChart;
            const speed = store.info?.links?.find((link) => link.name === name)?.speed_mbps;
            chart.update({ t, series: [{ name: "Sending", values: m.net[name]?.out_kbps ?? [], color: seriesColor(0) }, { name: "Receiving", values: m.net[name]?.in_kbps ?? [], color: seriesColor(1) }] });
            return chartCard(`Link ${name}`, isNumber(speed) ? `${speed >= 1000 ? `${speed / 1000} Gbit/s` : `${speed} Mbit/s`} link` : "", chart);
          })),
    );
    const ids = Object.keys(m.lobbies).filter((id) => m.lobbies[id]?.cpu_cores.some((value) => value !== null));
    ids.sort((a, b) => (lobbyColours.get(a) ?? 99) - (lobbyColours.get(b) ?? 99) || a.localeCompare(b));
    const shown = ids.slice(0, 8);
    lobbyNote.textContent = ids.length === 0 ? "no lobby ran in this range" : ids.length > 8 ? `the first 8 of ${ids.length}` : "";
    const name = (id: string): string => {
      const lobby = lobbyById(id);
      return lobby === undefined ? id : displayName(lobby);
    };
    lobbiesCpu.update({ t, series: shown.map((id) => ({ name: name(id), values: m.lobbies[id]?.cpu_cores ?? [], color: lobbyColour(id) })) });
    lobbiesMem.update({ t, series: shown.map((id) => ({ name: name(id), values: m.lobbies[id]?.rss_mb ?? [], color: lobbyColour(id) })) });
  }

  async function refresh(): Promise<void> {
    draw(await fetchMetrics(range));
  }

  renderChips();
  return {
    show(): void {
      void refresh();
      window.clearInterval(timer);
      timer = window.setInterval(() => void refresh(), REFRESH_MS);
    },
    hide(): void {
      window.clearInterval(timer);
      timer = undefined;
    },
  };
}

/** A lobby's own two charts (CPU cores against its CPUs, memory), fed from the host's metrics. */
export class LobbyCharts {
  readonly root: HTMLElement;
  private readonly cpu = new LineChart({ label: "The lobby's CPU, cores", format: coresText, height: 190 });
  private readonly mem = new LineChart({ label: "The lobby's memory", format: mbText, height: 190, unit: 256 });
  private readonly note = h("p", { class: "dim small" });
  private id: string | null = null;
  private timer: number | undefined;
  private off: (() => void) | null = null;

  constructor() {
    this.root = h("div", {}, this.note, h("div", { class: "chart-grid" }, chartCard("CPU", "cores its server uses, against the cores it was given", this.cpu), chartCard("Memory", "its server process", this.mem)));
  }

  open(id: string): void {
    this.close();
    this.id = id;
    const tick = async (): Promise<void> => {
      const m = await fetchMetrics(1800);
      if (this.id === id) this.draw(m);
    };
    void tick();
    this.timer = window.setInterval(() => void tick(), REFRESH_MS);
    if (!store.metricsSupported) this.off = on("metrics", () => this.draw(store.metrics));
  }

  close(): void {
    window.clearInterval(this.timer);
    this.timer = undefined;
    this.off?.();
    this.off = null;
    this.id = null;
  }

  private draw(m: Metrics | null): void {
    if (this.id === null || m === null) return;
    const own = m.lobbies[this.id];
    // From its first sample on: an older lobby's chart starts where the history does.
    let first = own === undefined ? -1 : own.cpu_cores.findIndex((value) => value !== null);
    if (first < 0) first = Math.max(0, m.t.length - 30);
    const t = m.t.slice(first);
    const given = (lobbyById(this.id)?.cpus ?? []).length;
    this.note.textContent = own === undefined ? "No samples of this lobby yet: they come every 2 s while it runs." : store.metricsSupported ? "" : "This host keeps no history: these are this page's samples.";
    this.cpu.update({ t, series: [{ name: "Used", values: (own?.cpu_cores ?? []).slice(first), color: lobbyColour(this.id) }, { name: "Given (CPUs)", values: t.map(() => (given > 0 ? given : null)), color: "var(--faint)" }] });
    this.mem.update({ t, series: [{ name: "Memory", values: (own?.rss_mb ?? []).slice(first), color: lobbyColour(this.id) }] });
  }
}
