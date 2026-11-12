// Charts drawn as SVG by hand: a line chart over time (gridlines, time axis, a legend for two or more series, a hover
// crosshair with every series' value) and a sparkline. Series colours are CSS custom properties (--series-1..8), the
// categorical palette in style.css, assigned in a fixed order by the caller.

import { h } from "./dom.ts";

const SVG = "http://www.w3.org/2000/svg";

function svg<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number> = {}): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  return node;
}

export interface ChartSeries {
  name: string;
  values: (number | null)[];
  /** A CSS colour, usually `var(--series-n)`. */
  color: string;
}

export interface ChartData {
  /** Unix seconds, one per sample. */
  t: number[];
  series: ChartSeries[];
}

export interface ChartOptions {
  /** What the chart shows, for screen readers and the empty state. */
  label: string;
  /** A value for people, e.g. "42%". */
  format(value: number): string;
  /** The y axis starts here (default 0). */
  min?: number;
  /** A fixed top (100 for percentages); else from the data. */
  max?: number;
  /** Plot height in px (default 170). */
  height?: number;
  /** The top is a round number in this unit (1024 for MB shown as GB); default 1. */
  unit?: number;
}

/** A round number at or above `value`: 1, 2, 2.5, 5 times a power of ten. */
function niceCeil(value: number): number {
  if (value <= 0) return 1;
  const power = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) if (value <= step * power) return step * power;
  return 10 * power;
}

function clockText(seconds: number, withSeconds: boolean): string {
  return new Date(seconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: withSeconds ? "2-digit" : undefined });
}

/** A line chart that redraws to its box's width; `update` gives it new data. */
export class LineChart {
  readonly root: HTMLElement;
  private readonly legend: HTMLElement;
  private readonly plot: HTMLElement;
  private readonly tip: HTMLElement;
  private readonly options: ChartOptions;
  private data: ChartData = { t: [], series: [] };
  private width = 0;
  private hover: number | null = null;
  private readonly observer: ResizeObserver;

  constructor(options: ChartOptions) {
    this.options = options;
    this.legend = h("div", { class: "chart-legend" });
    this.plot = h("div", { class: "chart-plot", role: "img", "aria-label": options.label });
    this.tip = h("div", { class: "chart-tip", hidden: true });
    this.root = h("div", { class: "chart" }, this.legend, h("div", { class: "chart-box" }, this.plot, this.tip));
    this.observer = new ResizeObserver(() => {
      const width = Math.floor(this.plot.clientWidth);
      if (width !== this.width && width > 0) {
        this.width = width;
        this.draw();
      }
    });
    this.observer.observe(this.plot);
    this.plot.addEventListener("pointermove", (event) => this.onMove(event));
    this.plot.addEventListener("pointerleave", () => {
      this.hover = null;
      this.tip.hidden = true;
      this.draw();
    });
  }

  update(data: ChartData): void {
    this.data = data;
    this.renderLegend();
    this.width = Math.floor(this.plot.clientWidth) || this.width;
    this.draw();
  }

  disconnect(): void {
    this.observer.disconnect();
  }

  private renderLegend(): void {
    const series = this.data.series;
    // One series: the chart's title names it, no legend box.
    if (series.length < 2) {
      this.legend.replaceChildren();
      return;
    }
    this.legend.replaceChildren(
      ...series.map((item) => {
        const last = [...item.values].reverse().find((value): value is number => value !== null);
        const key = h("span", { class: "chart-key", "aria-hidden": "true" });
        key.style.background = item.color;
        return h("span", { class: "chart-legend-item" }, key, h("span", {}, item.name), last === undefined ? null : h("span", { class: "chart-legend-value" }, this.options.format(last)));
      }),
    );
  }

  private geometry(): { width: number; height: number; left: number; right: number; top: number; bottom: number; min: number; max: number; t0: number; t1: number } {
    const height = this.options.height ?? 170;
    const values = this.data.series.flatMap((item) => item.values).filter((value): value is number => value !== null);
    const min = this.options.min ?? 0;
    const unit = this.options.unit ?? 1;
    const max = this.options.max ?? niceCeil((Math.max(min + 1e-9, ...values) * 1.08) / unit) * unit;
    const t0 = this.data.t[0] ?? 0;
    const t1 = this.data.t[this.data.t.length - 1] ?? t0 + 1;
    return { width: Math.max(160, this.width), height, left: 52, right: 10, top: 8, bottom: 22, min, max, t0, t1: t1 === t0 ? t0 + 1 : t1 };
  }

  private draw(): void {
    const g = this.geometry();
    const { t } = this.data;
    const root = svg("svg", { width: g.width, height: g.height, viewBox: `0 0 ${g.width} ${g.height}`, class: "chart-svg" });
    const plotW = g.width - g.left - g.right;
    const plotH = g.height - g.top - g.bottom;
    const x = (time: number): number => g.left + ((time - g.t0) / (g.t1 - g.t0)) * plotW;
    const y = (value: number): number => g.top + plotH - ((value - g.min) / (g.max - g.min || 1)) * plotH;

    // Gridlines and y labels: 4 steps.
    for (let i = 0; i <= 4; i++) {
      const value = g.min + ((g.max - g.min) * i) / 4;
      const yy = Math.round(y(value)) + 0.5;
      root.append(svg("line", { x1: g.left, x2: g.width - g.right, y1: yy, y2: yy, class: i === 0 ? "chart-axis" : "chart-gridline" }));
      const label = svg("text", { x: g.left - 6, y: yy + 3.5, class: "chart-label", "text-anchor": "end" });
      label.textContent = this.options.format(value);
      root.append(label);
    }
    // Time labels: about one per 110 px.
    if (t.length > 1) {
      const span = g.t1 - g.t0;
      const ticks = Math.max(2, Math.min(7, Math.floor(plotW / 110)));
      for (let i = 0; i <= ticks; i++) {
        const time = g.t0 + (span * i) / ticks;
        const label = svg("text", { x: x(time), y: g.height - 5, class: "chart-label", "text-anchor": i === 0 ? "start" : i === ticks ? "end" : "middle" });
        label.textContent = clockText(time, span < 300);
        root.append(label);
      }
    }
    if (t.length === 0) {
      const empty = svg("text", { x: g.left + plotW / 2, y: g.top + plotH / 2, class: "chart-label", "text-anchor": "middle" });
      empty.textContent = "No samples yet";
      root.append(empty);
    }
    // Lines, broken where a sample is missing.
    for (const item of this.data.series) {
      let d = "";
      let pen = false;
      item.values.forEach((value, index) => {
        const time = t[index];
        if (value === null || time === undefined) {
          pen = false;
          return;
        }
        d += `${pen ? "L" : "M"}${x(time).toFixed(1)},${y(Math.min(g.max, Math.max(g.min, value))).toFixed(1)}`;
        pen = true;
      });
      if (d !== "") root.append(svg("path", { d, class: "chart-line", stroke: item.color }));
    }
    // The hover crosshair: a vertical line and a dot per series.
    if (this.hover !== null) {
      const time = t[this.hover];
      if (time !== undefined) {
        const xx = x(time);
        root.append(svg("line", { x1: xx, x2: xx, y1: g.top, y2: g.top + plotH, class: "chart-cross" }));
        for (const item of this.data.series) {
          const value = item.values[this.hover];
          if (value === null || value === undefined) continue;
          root.append(svg("circle", { cx: xx, cy: y(Math.min(g.max, Math.max(g.min, value))), r: 4, fill: item.color, class: "chart-dot" }));
        }
      }
    }
    this.plot.replaceChildren(root);
  }

  private onMove(event: PointerEvent): void {
    const { t, series } = this.data;
    if (t.length === 0) return;
    const g = this.geometry();
    const box = this.plot.getBoundingClientRect();
    const px = event.clientX - box.left;
    const time = g.t0 + ((px - g.left) / (g.width - g.left - g.right)) * (g.t1 - g.t0);
    let best = 0;
    for (let i = 1; i < t.length; i++) if (Math.abs((t[i] ?? 0) - time) < Math.abs((t[best] ?? 0) - time)) best = i;
    this.hover = best;
    this.draw();
    const rows = series.map((item) => {
      const value = item.values[best];
      const key = h("span", { class: "chart-key", "aria-hidden": "true" });
      key.style.background = item.color;
      return h("div", { class: "chart-tip-row" }, key, h("span", { class: "chart-tip-name" }, item.name), h("b", {}, value === null || value === undefined ? "–" : this.options.format(value)));
    });
    this.tip.replaceChildren(h("div", { class: "chart-tip-time" }, clockText(t[best] ?? 0, true)), ...rows);
    this.tip.hidden = false;
    const tipWidth = this.tip.offsetWidth;
    const left = Math.min(Math.max(4, px + 14), box.width - tipWidth - 4);
    this.tip.style.left = `${left < px && px + 14 + tipWidth > box.width ? Math.max(4, px - tipWidth - 14) : left}px`;
    this.tip.style.top = "6px";
  }
}

/** A small trend line for a tile: the values as a line with a soft area under it; `max` fixes the top. */
export function sparkline(values: (number | null)[], color: string, max?: number): SVGSVGElement {
  const width = 120;
  const height = 32;
  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "none", class: "spark", "aria-hidden": "true" });
  const known = values.filter((value): value is number => value !== null);
  if (known.length < 2) return root;
  const top = max ?? Math.max(...known) * 1.15;
  const step = width / Math.max(1, values.length - 1);
  let line = "";
  let first: number | null = null;
  let last = 0;
  values.forEach((value, index) => {
    if (value === null) return;
    const xx = index * step;
    const yy = height - 1 - (Math.min(top, value) / (top || 1)) * (height - 2);
    line += `${line === "" ? "M" : "L"}${xx.toFixed(1)},${yy.toFixed(1)}`;
    first ??= xx;
    last = xx;
  });
  root.append(svg("path", { d: `${line}L${last.toFixed(1)},${height}L${(first ?? 0).toFixed(1)},${height}Z`, class: "spark-area", fill: color }));
  root.append(svg("path", { d: line, class: "spark-line", stroke: color }));
  return root;
}

/** The categorical colours, in their fixed order. */
export function seriesColor(index: number): string {
  return `var(--series-${(index % 8) + 1})`;
}
