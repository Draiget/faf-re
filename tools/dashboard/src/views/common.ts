// What the dashboard's views share: the host's maps (loaded once per connection) with their previews fetched with the
// admin token, a page header, cards, tiles with a sparkline, and the view interface the router drives.

import type { MapInfo } from "../api.ts";
import { h, isNumber, type Child } from "../dom.ts";
import type { PreviewSource } from "../maps.ts";
import { store } from "../plane/store.ts";

export interface View {
  /** The view becomes the one shown; `arg` is the rest of the route (a lobby id, say). */
  show(arg: string | null): void;
  hide(): void;
}

let maps: MapInfo[] | null = null;
let mapsLoading: Promise<MapInfo[]> | null = null;
let mapsBase = "";

/** The host's maps, asked for once per connection. */
export function hostMaps(): Promise<MapInfo[]> {
  const api = store.api;
  if (api === null) return Promise.resolve([]);
  if (api.base !== mapsBase) {
    maps = null;
    mapsLoading = null;
    mapsBase = api.base;
  }
  if (maps !== null) return Promise.resolve(maps);
  mapsLoading ??= api.maps(AbortSignal.timeout(15000)).then(
    (list) => {
      maps = [...list].sort((a, b) => (a.name ?? a.id).localeCompare(b.name ?? b.id));
      return maps;
    },
    (error: unknown) => {
      mapsLoading = null;
      throw error;
    },
  );
  return mapsLoading;
}

/** A map the host listed, if the list is in. */
export function knownMap(id: string | undefined): MapInfo | undefined {
  return id === undefined ? undefined : maps?.find((map) => map.id === id);
}

/** Previews straight from the host (they need no token). */
export const hostPreview: PreviewSource = (map) => Promise.resolve(store.api?.previewUrl(map) ?? null);

export function forgetHostData(): void {
  maps = null;
  mapsLoading = null;
  mapsBase = "";
}

export function pageHead(title: string, sub: Child, ...actions: Child[]): HTMLElement {
  return h("header", { class: "page-head" }, h("div", { class: "page-titles" }, h("h1", {}, title), sub === null || sub === "" ? null : h("p", { class: "page-sub" }, sub)), actions.length === 0 ? null : h("div", { class: "page-actions" }, ...actions));
}

export function card(title: string, meta: Child, ...body: Child[]): HTMLElement {
  return h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, title), meta === null || meta === "" ? null : h("span", { class: "card-meta" }, meta)), ...body);
}

/** A key number with its label, a line under it, and an optional sparkline. */
export function kpi(label: string, value: Child, sub: Child, spark?: SVGElement | null, href?: string, tone = ""): HTMLElement {
  const body: Child[] = [h("span", { class: "kpi-label" }, label), h("span", { class: "kpi-value" }, value), h("span", { class: "kpi-sub" }, sub), spark ?? null];
  return href === undefined ? h("div", { class: `kpi${tone === "" ? "" : ` tone-${tone}`}` }, ...body) : h("a", { class: `kpi link${tone === "" ? "" : ` tone-${tone}`}`, href }, ...body);
}

/** The last known value of a series. */
export function last(values: (number | null)[] | undefined): number | null {
  if (values === undefined) return null;
  for (let i = values.length - 1; i >= 0; i--) {
    const value = values[i];
    if (isNumber(value)) return value;
  }
  return null;
}

/** Sums series sample by sample (null where all are null). */
export function sumSeries(list: (number | null)[][]): (number | null)[] {
  const length = Math.max(0, ...list.map((values) => values.length));
  return Array.from({ length }, (_, i) => {
    let sum = 0;
    let any = false;
    for (const values of list) {
      const value = values[i];
      if (isNumber(value)) {
        sum += value;
        any = true;
      }
    }
    return any ? sum : null;
  });
}
