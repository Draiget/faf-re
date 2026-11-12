// Maps as people pick them: a gallery of previews (search, size, start spots) and a large preview with the start spots
// drawn on it and the seats assigned to them. Shared by the dashboard's create flow (previews fetched with the admin
// token) and the public request page (previews loaded straight from the public API).

import type { MapInfo } from "./api.ts";
import { fill, h, icon, isNumber } from "./dom.ts";

const SVG = "http://www.w3.org/2000/svg";

/** Where a map's preview image is: an address an `<img>` can load, or null when it has none. */
export type PreviewSource = (map: MapInfo) => Promise<string | null>;

/** The map's description without the game's localisation tag ("<LOC id>text"); null when nothing is left. */
export function mapDescription(map: MapInfo): string | null {
  const text = (map.description ?? "").replace(/<LOC[^>]*>/g, "").replace(/[\s\\]+$/, "").trim();
  return text === "" ? null : text;
}

/** A map's size and spots for people: "10 km · 8 spots". */
export function mapFacts(map: MapInfo): string {
  const spots = isNumber(map.players) ? map.players : (map.spawns?.length ?? null);
  return `${isNumber(map.km) ? `${map.km} km` : "size unknown"} · ${spots === null ? "? spots" : `${spots} ${spots === 1 ? "spot" : "spots"}`}`;
}

/** The map's start spots, normalised: its own when given, else a ring (so seats still have a place to show). */
export function spotsOf(map: MapInfo): { x: number; z: number; known: boolean }[] {
  const given = (map.spawns ?? []).filter((spot) => Array.isArray(spot) && isNumber(spot[0]) && isNumber(spot[1]));
  if (given.length > 0) return given.map(([x, z]) => ({ x: Math.min(1, Math.max(0, x)), z: Math.min(1, Math.max(0, z)), known: true }));
  const count = isNumber(map.players) && map.players > 0 ? map.players : 2;
  return Array.from({ length: count }, (_, i) => ({ x: 0.5 + 0.36 * Math.cos((2 * Math.PI * i) / count - Math.PI / 2), z: 0.5 + 0.36 * Math.sin((2 * Math.PI * i) / count - Math.PI / 2), known: false }));
}

const lazy =
  typeof IntersectionObserver === "undefined"
    ? null
    : new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (!entry.isIntersecting) continue;
            lazy?.unobserve(entry.target);
            (entry.target as HTMLElement & { load?: () => void }).load?.();
          }
        },
        { rootMargin: "300px" },
      );

/** Previews the page has shown once: drawn again at once (from the browser's cache), not when scrolled near. */
const shown = new Set<string>();

/** The preview image (or a placeholder with the size) filling its box; loaded when it scrolls near. */
export function mapArt(map: MapInfo, source: PreviewSource, eager = false): HTMLElement {
  const box = h("div", { class: "map-art" }, h("span", { class: "map-art-size", "aria-hidden": "true" }, isNumber(map.km) ? `${map.km} km` : "?"));
  const load = (): void => {
    void source(map).then((url) => {
      if (url === null) {
        box.classList.add("no-preview");
        return;
      }
      const img = h("img", { alt: "", decoding: "async", draggable: "false" });
      img.addEventListener("load", () => {
        shown.add(url);
        box.classList.add("loaded");
      });
      img.addEventListener("error", () => box.classList.add("no-preview"));
      if (shown.has(url)) box.classList.add("loaded");
      img.src = url;
      box.prepend(img);
    });
  };
  if (eager || lazy === null || (typeof map.preview === "string" && [...shown].some((url) => url.endsWith(map.preview ?? "")))) load();
  else {
    (box as HTMLElement & { load?: () => void }).load = load;
    lazy.observe(box);
  }
  return box;
}

/** Small dots for the start spots over a thumbnail. */
function spotDots(map: MapInfo): SVGSVGElement {
  const root = document.createElementNS(SVG, "svg");
  root.setAttribute("viewBox", "0 0 100 100");
  root.setAttribute("class", "map-dots");
  root.setAttribute("aria-hidden", "true");
  for (const spot of spotsOf(map)) {
    if (!spot.known) continue;
    const dot = document.createElementNS(SVG, "circle");
    dot.setAttribute("cx", String(spot.x * 100));
    dot.setAttribute("cy", String(spot.z * 100));
    dot.setAttribute("r", "3.2");
    root.append(dot);
  }
  return root;
}

// ---------------------------------------------------------------- the gallery

export interface GalleryOptions {
  source: PreviewSource;
  onSelect(map: MapInfo): void;
  /** At least this many start spots (the seats asked for); maps with fewer are marked. */
  minSpots?: () => number;
  /** The largest map size allowed, km; larger ones are marked. */
  maxKm?: () => number | null;
}

const SIZES = [5, 10, 20, 40, 81];
const MAX_SHOWN = 120;

export class MapGallery {
  readonly root: HTMLElement;
  private maps: MapInfo[] = [];
  private selected = "";
  private size: number | null = null;
  private readonly search: HTMLInputElement;
  private readonly sizes: HTMLElement;
  private readonly grid: HTMLElement;
  private readonly count: HTMLElement;
  private readonly options: GalleryOptions;

  constructor(options: GalleryOptions) {
    this.options = options;
    this.search = h("input", { type: "search", placeholder: "Search maps by name", spellcheck: "false", "aria-label": "Search maps" });
    this.search.addEventListener("input", () => this.render());
    this.sizes = h("div", { class: "seg-chips", role: "group", "aria-label": "Map size" });
    this.count = h("span", { class: "dim small" });
    this.grid = h("div", { class: "map-grid", role: "listbox", "aria-label": "Maps" });
    this.root = h("div", { class: "gallery" }, h("div", { class: "gallery-tools" }, h("div", { class: "gallery-search" }, icon("map", "icon"), this.search), this.sizes, this.count), this.grid);
    this.renderSizes();
  }

  private renderSizes(): void {
    const chip = (value: number | null, text: string): HTMLButtonElement => {
      const button = h("button", { type: "button", class: "seg-chip", "aria-pressed": String(this.size === value) }, text);
      button.addEventListener("click", () => {
        this.size = value;
        this.renderSizes();
        this.render();
      });
      return button;
    };
    this.sizes.replaceChildren(chip(null, "All sizes"), ...SIZES.map((km) => chip(km, `${km} km`)));
  }

  setMaps(maps: MapInfo[], selected: string): void {
    this.maps = maps;
    this.selected = selected;
    this.render();
  }

  select(id: string): void {
    this.selected = id;
    for (const card of this.grid.querySelectorAll<HTMLElement>(".map-card")) {
      const on = card.dataset.id === id;
      card.classList.toggle("selected", on);
      card.setAttribute("aria-selected", String(on));
    }
  }

  /** Re-marks the cards that don't fit (after the seats or limits changed). */
  refreshFit(): void {
    const min = this.options.minSpots?.() ?? 0;
    const maxKm = this.options.maxKm?.() ?? null;
    for (const card of this.grid.querySelectorAll<HTMLElement>(".map-card")) {
      const map = this.maps.find((item) => item.id === card.dataset.id);
      if (map === undefined) continue;
      const why = this.misfit(map, min, maxKm);
      card.classList.toggle("misfit", why !== "");
      const note = card.querySelector(".map-misfit");
      if (note !== null) note.textContent = why;
    }
  }

  private misfit(map: MapInfo, min: number, maxKm: number | null): string {
    if (isNumber(map.players) && map.players < min) return `only ${map.players} spots`;
    if (maxKm !== null && isNumber(map.km) && map.km > maxKm) return `larger than ${maxKm} km`;
    return "";
  }

  render(): void {
    const query = this.search.value.trim().toLowerCase();
    const matching = this.maps.filter((map) => (query === "" || `${map.name ?? ""} ${map.id}`.toLowerCase().includes(query)) && (this.size === null || map.km === this.size));
    const shown = matching.slice(0, MAX_SHOWN);
    const current = this.maps.find((map) => map.id === this.selected);
    if (current !== undefined && !shown.includes(current) && query === "" && this.size === null) shown.unshift(current);
    this.count.textContent = matching.length === this.maps.length ? `${this.maps.length} maps` : `${matching.length} of ${this.maps.length} maps`;
    if (shown.length === 0) {
      this.grid.replaceChildren(h("p", { class: "empty" }, this.maps.length === 0 ? "The host lists no maps." : "No map matches."));
      return;
    }
    const min = this.options.minSpots?.() ?? 0;
    const maxKm = this.options.maxKm?.() ?? null;
    this.grid.replaceChildren(
      ...shown.map((map) => {
        const why = this.misfit(map, min, maxKm);
        const art = mapArt(map, this.options.source);
        art.append(spotDots(map));
        const card = h(
          "button",
          { type: "button", class: `map-card${map.id === this.selected ? " selected" : ""}${why !== "" ? " misfit" : ""}`, role: "option", "aria-selected": String(map.id === this.selected), "data-id": map.id, title: mapDescription(map) ?? map.name ?? map.id },
          art,
          h("span", { class: "map-card-text" }, h("span", { class: "map-card-name" }, map.name ?? map.id), h("span", { class: "map-card-facts" }, mapFacts(map), map.source === "fa" ? h("span", { class: "source source-fa" }, "FA") : null), h("span", { class: "map-misfit" }, why)),
        );
        card.addEventListener("click", () => {
          this.select(map.id);
          this.options.onSelect(map);
        });
        return card;
      }),
      matching.length > MAX_SHOWN ? h("p", { class: "dim small map-more" }, `Showing ${MAX_SHOWN} of ${matching.length}: search to narrow it.`) : "",
    );
  }
}

// ---------------------------------------------------------------- the large preview with spots

export interface SpotMark {
  /** What the spot shows under its number: a name, "AI: Rush", "Open". */
  label: string;
  kind: "human" | "ai" | "open" | "empty";
  /** FAF's team number (1 = no team). */
  team: number;
  selected?: boolean;
}

/** The large preview: the image with every start spot numbered, coloured by its seat's team, labelled with the seat. */
export class MapPreview {
  readonly root: HTMLElement;
  private readonly frame: HTMLElement;
  private readonly overlay: SVGSVGElement;
  private readonly caption: HTMLElement;
  private readonly source: PreviewSource;
  private readonly onSpot: ((spot: number) => void) | null;
  private mapId = "";

  constructor(source: PreviewSource, onSpot?: (spot: number) => void) {
    this.source = source;
    this.onSpot = onSpot ?? null;
    this.overlay = document.createElementNS(SVG, "svg");
    this.overlay.setAttribute("viewBox", "0 0 1000 1000");
    this.overlay.setAttribute("class", "spots");
    this.frame = h("div", { class: "preview-frame" });
    this.caption = h("div", { class: "preview-caption" });
    this.root = h("figure", { class: "map-preview" }, this.frame, this.caption);
  }

  update(map: MapInfo | undefined, marks: SpotMark[]): void {
    if (map === undefined) {
      this.mapId = "";
      this.frame.replaceChildren(h("div", { class: "preview-empty" }, icon("map", "icon"), h("span", {}, "Pick a map to see its start spots")));
      fill(this.caption, );
      return;
    }
    if (map.id !== this.mapId) {
      this.mapId = map.id;
      this.frame.replaceChildren(mapArt(map, this.source, true), this.overlay);
      fill(this.caption, 
        h("strong", {}, map.name ?? map.id),
        h("span", { class: "dim" }, ` · ${mapFacts(map)}`),
        mapDescription(map) === null ? null : h("p", { class: "map-description" }, mapDescription(map)),
      );
    }
    const spots = spotsOf(map);
    this.overlay.replaceChildren();
    spots.forEach((spot, index) => {
      const mark = marks[index] ?? { label: "", kind: "empty", team: 1 };
      const g = document.createElementNS(SVG, "g");
      g.setAttribute("class", `spot spot-${mark.kind}${mark.selected === true ? " selected" : ""}${spot.known ? "" : " guessed"}`);
      g.setAttribute("transform", `translate(${(spot.x * 1000).toFixed(0)} ${(spot.z * 1000).toFixed(0)})`);
      g.style.setProperty("--team", mark.team > 1 ? `var(--series-${((mark.team - 2) % 8) + 1})` : "var(--neutral)");
      const ring = document.createElementNS(SVG, "circle");
      ring.setAttribute("r", "34");
      ring.setAttribute("class", "spot-ring");
      const number = document.createElementNS(SVG, "text");
      number.setAttribute("class", "spot-number");
      number.setAttribute("text-anchor", "middle");
      number.setAttribute("dy", "12");
      number.textContent = String(index + 1);
      g.append(ring, number);
      if (mark.label !== "") {
        // Under the spot, unless another spot sits just below it (or the map's edge does): then above.
        const crowded = spots.some((other, j) => j !== index && Math.abs(other.x - spot.x) < 0.14 && other.z - spot.z > 0 && other.z - spot.z < 0.11);
        const below = spot.z < 0.86 && !crowded;
        const label = document.createElementNS(SVG, "text");
        label.setAttribute("class", "spot-label");
        label.setAttribute("text-anchor", spot.x < 0.12 ? "start" : spot.x > 0.88 ? "end" : "middle");
        label.setAttribute("x", spot.x < 0.12 ? "-30" : spot.x > 0.88 ? "30" : "0");
        label.setAttribute("y", below ? "76" : "-50");
        label.textContent = mark.label.length > 16 ? `${mark.label.slice(0, 15)}…` : mark.label;
        g.append(label);
      }
      const title = document.createElementNS(SVG, "title");
      title.textContent = `Start spot ${index + 1}${mark.label === "" ? "" : `: ${mark.label}`}${mark.team > 1 ? `, team ${mark.team - 1}` : ""}`;
      g.append(title);
      if (this.onSpot !== null) {
        g.setAttribute("role", "button");
        g.setAttribute("tabindex", "0");
        g.addEventListener("click", () => this.onSpot?.(index + 1));
        g.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            this.onSpot?.(index + 1);
          }
        });
      }
      this.overlay.append(g);
    });
  }
}
