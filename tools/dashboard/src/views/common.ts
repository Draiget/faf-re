// What the dashboard's views share: the host's maps (loaded once per connection) with their previews fetched with the
// admin token, a page header, cards, tiles with a sparkline, and the view interface the router drives.

import type { HostApi, MapInfo } from "../api.ts";
import { h, isNumber, type Child } from "../dom.ts";
import type { PreviewSource } from "../maps.ts";
import { store } from "../plane/store.ts";

export interface View {
  /** The view becomes the one shown; `arg` is the rest of the route (a lobby id, say). */
  show(arg: string | null): void;
  hide(): void;
}

/** Each host's maps by its address (through the control service, one per host), and those being asked for. */
const mapCache = new Map<string, MapInfo[]>();
const mapLoads = new Map<string, Promise<MapInfo[]>>();

/** The host's maps (`from`, else the store's host), asked for once per host. */
export function hostMaps(from?: HostApi | null): Promise<MapInfo[]> {
  const api = from ?? store.api;
  if (api === null) return Promise.resolve([]);
  const base = api.base;
  const cached = mapCache.get(base);
  if (cached !== undefined) return Promise.resolve(cached);
  let loading = mapLoads.get(base);
  if (loading === undefined) {
    loading = api.maps(AbortSignal.timeout(15000)).then(
      (list) => {
        const sorted = [...list].sort((a, b) => (a.name ?? a.id).localeCompare(b.name ?? b.id));
        mapCache.set(base, sorted);
        mapLoads.delete(base);
        return sorted;
      },
      (error: unknown) => {
        mapLoads.delete(base);
        throw error;
      },
    );
    mapLoads.set(base, loading);
  }
  return loading;
}

/** A map the store's host listed, if the list is in. */
export function knownMap(id: string | undefined): MapInfo | undefined {
  const base = store.api?.base;
  return id === undefined || base === undefined ? undefined : mapCache.get(base)?.find((map) => map.id === id);
}

/** Previews straight from the host (they need no token). */
export const hostPreview: PreviewSource = (map) => Promise.resolve(store.api?.previewUrl(map) ?? null);

export function forgetHostData(): void {
  mapCache.clear();
  mapLoads.clear();
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
