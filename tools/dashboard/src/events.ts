// The event timeline: each server event as one readable entry, with its icon, tone and filter category.

import type { ServerEvent } from "./api.ts";
import { clock, faction, h, icon, isNumber, num, resultTone, type Child } from "./dom.ts";

export type Category = "players" | "game" | "results" | "content" | "console";

export const CATEGORIES: { id: Category; label: string }[] = [
  { id: "players", label: "Players" },
  { id: "game", label: "Game" },
  { id: "results", label: "Results" },
  { id: "content", label: "Content" },
  { id: "console", label: "Console" },
];

interface Kind {
  category: Category;
  icon: string;
  tone: string;
}

const KINDS: Record<string, Kind> = {
  joined: { category: "players", icon: "join", tone: "ok" },
  left: { category: "players", icon: "leave", tone: "neutral" },
  away: { category: "players", icon: "away", tone: "warn" },
  back: { category: "players", icon: "back", tone: "ok" },
  host: { category: "players", icon: "crown", tone: "accent" },
  ready: { category: "players", icon: "check", tone: "ok" },
  substitute: { category: "players", icon: "swap", tone: "accent" },
  launched: { category: "game", icon: "rocket", tone: "accent" },
  game_started: { category: "game", icon: "play", tone: "ok" },
  game_ended: { category: "game", icon: "stop", tone: "accent" },
  options: { category: "game", icon: "sliders", tone: "neutral" },
  countdown: { category: "game", icon: "timer", tone: "accent" },
  countdown_cancelled: { category: "game", icon: "timer", tone: "warn" },
  result: { category: "results", icon: "trophy", tone: "ok" },
  stats: { category: "results", icon: "chart", tone: "accent" },
  content: { category: "content", icon: "box", tone: "neutral" },
  observer_request: { category: "content", icon: "eye", tone: "accent" },
  log: { category: "console", icon: "terminal", tone: "muted" },
};

export function kindOf(name: string): Kind {
  return KINDS[name] ?? { category: "game", icon: "info", tone: "neutral" };
}

/** Context the timeline needs from the page: the seats' names, and the results gathered so far. */
export interface EventContext {
  nameOf(uid: unknown): string;
  results: Map<number, { name: string; result: string }>;
}

function text(value: unknown): string {
  return value === undefined || value === null ? "" : String(value);
}

function scroller(table: HTMLTableElement): HTMLElement {
  return h("div", { class: "table-scroll" }, table);
}

function resultsTable(results: Map<number, { name: string; result: string }>): HTMLElement | null {
  if (results.size === 0) return null;
  const rows = [...results.entries()].sort((a, b) => a[0] - b[0]);
  return scroller(
    h(
      "table",
      { class: "mini" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Army"), h("th", { scope: "col" }, "Player"), h("th", { scope: "col" }, "Result"))),
      h(
        "tbody",
        {},
        ...rows.map(([army, row]) =>
          h(
            "tr",
            {},
            h("td", { class: "num" }, army),
            h("td", {}, row.name),
            h("td", {}, h("span", { class: `result-chip tone-${resultTone(row.result)}` }, row.result)),
          ),
        ),
      ),
    ),
  );
}

interface Counts {
  count?: number;
  mass?: number;
  energy?: number;
}

function count(value: unknown): number | undefined {
  if (isNumber(value)) return value;
  if (value !== null && typeof value === "object" && isNumber((value as Counts).count)) return (value as Counts).count;
  return undefined;
}

/** The stats event's armies: `stats` may be the list itself, `{stats: [...]}`, or a table keyed by army. */
function statsArmies(raw: unknown): Record<string, unknown>[] {
  let list: unknown = raw;
  if (list !== null && typeof list === "object" && !Array.isArray(list) && "stats" in list) {
    list = (list as { stats: unknown }).stats;
  }
  const values = Array.isArray(list) ? list : list !== null && typeof list === "object" ? Object.values(list) : [];
  return values.filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object");
}

function statsTable(raw: unknown): HTMLElement {
  const armies = statsArmies(raw);
  if (armies.length === 0) {
    return h("p", { class: "dim" }, "No army stats in the event.");
  }
  return scroller(
    h(
      "table",
      { class: "mini" },
      h(
        "thead",
        {},
        h(
          "tr",
          {},
          h("th", { scope: "col" }, "Army"),
          h("th", { scope: "col", class: "num" }, "Score"),
          h("th", { scope: "col", class: "num" }, "Built"),
          h("th", { scope: "col", class: "num" }, "Lost"),
          h("th", { scope: "col", class: "num" }, "Kills"),
        ),
      ),
      h(
        "tbody",
        {},
        ...armies.map((army) => {
          const general = (army.general ?? {}) as Record<string, unknown>;
          const side = faction(army.faction);
          const defeated = army.Defeated !== undefined && army.Defeated !== null;
          return h(
            "tr",
            {},
            h(
              "td",
              {},
              h("span", { class: `faction-dot faction-${side?.key ?? "none"}`, title: side?.name ?? "" }),
              h("span", {}, text(army.name) || "?"),
              " ",
              h("span", { class: "dim" }, text(army.type)),
              defeated ? h("span", { class: "chip tiny tone-bad" }, "defeated") : null,
            ),
            h("td", { class: "num" }, num(general.score)),
            h("td", { class: "num" }, num(count(general.built))),
            h("td", { class: "num" }, num(count(general.lost))),
            h("td", { class: "num" }, num(count(general.kills))),
          );
        }),
      ),
    ),
  );
}

/** The entry's title line and optional body for one event. */
function describe(event: ServerEvent, context: EventContext): { title: Child[]; body?: Child; tone?: string } {
  const who = context.nameOf(event.uid);
  switch (event.event) {
    case "joined":
      return { title: [h("b", {}, who), " joined"] };
    case "left":
      return { title: [h("b", {}, who), " left"] };
    case "away":
      return { title: [h("b", {}, who), " went quiet"] };
    case "back":
      return { title: [h("b", {}, who), " is back"] };
    case "host":
      return { title: [h("b", {}, who), " is the host"] };
    case "ready":
      return event.ready === false
        ? { title: [h("b", {}, who), " is not ready"], tone: "warn" }
        : { title: [h("b", {}, who), " is ready"] };
    case "substitute":
      return { title: [h("b", {}, text(event.name) || "?"), " takes the seat of ", h("b", {}, who)] };
    case "launched": {
      const by = text(event.by);
      const reason = by === "ready" ? "everyone is ready" : by === "operator" ? "by the operator" : by === "host" ? "by the host" : by;
      return { title: ["Game launched", reason === "" ? "" : ` (${reason})`] };
    }
    case "game_started":
      return { title: ["Game started", isNumber(event.beat) ? ` at ${clock(event.beat)}` : ""] };
    case "game_ended": {
      const ended = event.ended === true;
      const error = text(event.error);
      const stoppedBy = text(event.stopped_by);
      return {
        title: [
          ended ? "Game ended" : "Game stopped",
          isNumber(event.beats) ? ` after ${clock(event.beats)}` : "",
          stoppedBy === "" ? "" : ` (${stoppedBy})`,
        ],
        body: h("div", {}, error === "" ? null : h("p", { class: "error-text" }, error), resultsTable(context.results)),
        tone: error !== "" ? "bad" : "accent",
      };
    }
    case "options":
      return { title: ["Options set"], body: h("code", { class: "inline-code" }, text(event.options)) };
    case "countdown":
      return { title: ["Start countdown: ", h("b", {}, isNumber(event.seconds) ? `${Math.ceil(event.seconds)} s` : "?")] };
    case "countdown_cancelled":
      return { title: ["Countdown cancelled", text(event.reason) === "" ? "" : `: ${text(event.reason)}`] };
    case "result": {
      const result = text(event.result);
      return {
        title: [h("b", {}, text(event.name) || `Army ${text(event.army)}`), ` (army ${text(event.army)}) `, h("span", { class: `result-chip tone-${resultTone(result)}` }, result)],
        tone: resultTone(result) === "bad" ? "bad" : "ok",
      };
    }
    case "stats":
      return { title: ["Army stats at the end of the game"], body: statsTable(event.stats) };
    case "content": {
      const content = text(event.content);
      const mods = text(event.mods);
      const uiMods = Array.isArray(event.ui_mods) ? event.ui_mods.map(text) : [];
      const bad = (content !== "" && content !== "same") || (mods !== "" && mods !== "allowed");
      return {
        title: [h("b", {}, text(event.name) || who), ": content ", h("b", {}, content || "?"), ", mods ", h("b", {}, mods || "?")],
        body: uiMods.length === 0 ? undefined : h("ul", { class: "chips" }, ...uiMods.map((mod) => h("li", { class: "chip" }, mod))),
        tone: bad ? "warn" : "neutral",
      };
    }
    case "observer_request":
      return { title: ["Observer request from ", h("b", {}, text(event.from) || "?")], body: h("code", { class: "inline-code" }, `token ${text(event.token)}`) };
    case "log":
      return { title: [h("span", { class: "log-text" }, text(event.text))] };
    default: {
      const { event: _name, ...fields } = event;
      return { title: [h("b", {}, event.event)], body: h("code", { class: "inline-code" }, JSON.stringify(fields)) };
    }
  }
}

/** One timeline entry for an event, tagged with its category for filtering. */
export function eventItem(event: ServerEvent, context: EventContext, at: Date): HTMLLIElement {
  const kind = kindOf(event.event);
  const { title, body, tone } = describe(event, context);
  const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const item = h(
    "li",
    { class: `ev tone-${tone ?? kind.tone}${event.event === "log" ? " ev-log" : ""}`, "data-cat": kind.category, "data-kind": event.event },
    h("span", { class: "ev-icon" }, icon(kind.icon)),
    h(
      "div",
      { class: "ev-main" },
      h("div", { class: "ev-line" }, h("span", { class: "ev-title" }, ...title), h("time", { class: "ev-time", datetime: at.toISOString() }, time)),
      body === undefined || body === null || body === false ? null : h("div", { class: "ev-body" }, body),
    ),
  );
  return item;
}
