// Small DOM and formatting helpers for the page. Text from the server always goes in as text, never as HTML.

export type Child = Node | string | number | null | undefined | false;
export type Attrs = Record<string, string | number | boolean | null | undefined>;

/** An element with attributes (`class`, `aria-*`, `data-*`, ...) and children; false/null children are skipped. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    node.setAttribute(key, value === true ? "" : String(value));
  }
  append(node, children);
  return node;
}

export function append(node: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" || typeof child === "number" ? document.createTextNode(String(child)) : child);
  }
}

export function byId<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) {
    throw new Error(`no #${id}`);
  }
  return found as T;
}

// Icons: 24x24 stroke paths, drawn in currentColor. Static strings, so innerHTML is safe here.
const ICONS: Record<string, string> = {
  join: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="M10 17l5-5-5-5"/><path d="M15 12H3"/>',
  leave: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
  away: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  back: '<path d="M20 6L9 17l-5-5"/>',
  crown: '<path d="M3 18h18"/><path d="M4 15l-1-9 5 4 4-6 4 6 5-4-1 9z"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  x: '<path d="M18 6L6 18"/><path d="M6 6l12 12"/>',
  rocket: '<path d="M5 15c-1.5 1.5-2 5-2 5s3.5-.5 5-2"/><path d="M9 12a12 12 0 0 1 11-9 12 12 0 0 1-9 11l-3 1-1-1z"/><circle cx="15" cy="9" r="1.5"/>',
  play: '<path d="M7 4l13 8-13 8z"/>',
  pause: '<path d="M8 5v14"/><path d="M16 5v14"/>',
  flag: '<path d="M5 21V4"/><path d="M5 4h11l-2 4 2 4H5"/>',
  trophy: '<path d="M8 21h8"/><path d="M12 17v4"/><path d="M7 4h10v5a5 5 0 0 1-10 0z"/><path d="M17 5h3v2a3 3 0 0 1-3 3"/><path d="M7 5H4v2a3 3 0 0 0 3 3"/>',
  chart: '<path d="M4 20V10"/><path d="M10 20V4"/><path d="M16 20v-7"/><path d="M22 20H2"/>',
  stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
  box: '<path d="M21 8l-9-5-9 5 9 5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>',
  eye: '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  swap: '<path d="M7 4L3 8l4 4"/><path d="M3 8h14"/><path d="M17 20l4-4-4-4"/><path d="M21 16H7"/>',
  sliders: '<path d="M4 6h10"/><path d="M18 6h2"/><circle cx="16" cy="6" r="2"/><path d="M4 12h4"/><path d="M12 12h8"/><circle cx="10" cy="12" r="2"/><path d="M4 18h12"/><circle cx="18" cy="18" r="2"/>',
  timer: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2"/><path d="M9 2h6"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  terminal: '<path d="M4 17l6-5-6-5"/><path d="M12 19h8"/>',
  dot: '<circle cx="12" cy="12" r="4"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7"/><path d="M18 14a6.5 6.5 0 0 1 3.5 6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
  auto: '<circle cx="12" cy="12" r="9"/><path d="M12 3v18" /><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor"/>',
  trash: '<path d="M4 7h16"/><path d="M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><path d="M12 7.5v.5"/>',
};

export function icon(name: string, className = "icon"): HTMLSpanElement {
  const span = document.createElement("span");
  span.className = className;
  span.setAttribute("aria-hidden", "true");
  span.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] ?? ICONS.dot}</svg>`;
  return span;
}

/** Game time from beats (10 beats a game second): m:ss, or h:mm:ss past the hour. */
export function clock(beat: number): string {
  const seconds = Math.max(0, Math.floor(beat / 10));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = String(seconds % 60).padStart(2, "0");
  return hours > 0 ? `${hours}:${String(minutes).padStart(2, "0")}:${rest}` : `${String(minutes).padStart(2, "0")}:${rest}`;
}

export function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** A number for people: a dash when missing, k/M past ten thousand. */
export function num(value: unknown, digits = 0): string {
  if (!isNumber(value)) return "–";
  const abs = Math.abs(value);
  if (abs >= 1e6) return `${(value / 1e6).toFixed(abs >= 1e7 ? 0 : 1)}M`;
  if (abs >= 1e4) return `${(value / 1e3).toFixed(abs >= 1e5 ? 0 : 1)}k`;
  return value.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: 0 });
}

/** "ResourceAllocation" -> "Resource Allocation". */
export function words(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/_/g, " ");
}

export function initials(name: string): string {
  const parts = name.trim().split(/[\s_\-.]+/).filter((part) => part !== "");
  if (parts.length === 0) return "?";
  const first = parts[0] ?? "";
  const second = parts[1] ?? "";
  return (second === "" ? first.slice(0, 2) : first.slice(0, 1) + second.slice(0, 1)).toUpperCase();
}

export const FACTIONS: Record<number, { name: string; short: string; key: string }> = {
  1: { name: "UEF", short: "UEF", key: "uef" },
  2: { name: "Aeon", short: "AEON", key: "aeon" },
  3: { name: "Cybran", short: "CYB", key: "cybran" },
  4: { name: "Seraphim", short: "SER", key: "seraphim" },
};

/** The tone of a result text: "victory 10" ok, "defeat" bad, anything else neutral. */
export function resultTone(result: string): string {
  const word = result.trim().split(/\s+/)[0]?.toLowerCase() ?? "";
  if (word === "victory") return "ok";
  if (word === "defeat") return "bad";
  if (word === "draw") return "info";
  return "neutral";
}

/** The faction for its number (1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim); undefined when missing or unknown. */
export function faction(value: unknown): { name: string; short: string; key: string } | undefined {
  return isNumber(value) ? FACTIONS[value] : undefined;
}
