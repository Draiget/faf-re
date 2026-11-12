// Lobbies: every lobby on the host as a table (map, kind, state, players, CPUs and node, live use, when it started),
// filtered by kind or state, with Open, Stop and Remove. `lobbyTable` also draws the overview's running lobbies.

import type { Lobby } from "../api.ts";
import { byId, clock, h, icon, isNumber, type Child } from "../dom.ts";
import { mapArt } from "../maps.ts";
import { cpuChips, emptyState, forgetLobby, kindChip, stateChip, stopLobby, swatch, timeOf, usageLine } from "../plane/parts.ts";
import { ageSeconds, displayName, duration, isPoolLobby, kindOf, LIVE, on, plural, RUNNING, store } from "../plane/store.ts";
import { hostPreview, knownMap, pageHead, type View } from "./common.ts";

function players(lobby: Lobby): string {
  const seats = lobby.seats ?? [];
  const humans = seats.filter((seat) => seat.kind === "human").length;
  const bots = seats.length - humans;
  const observers = (lobby.observers ?? []).length;
  return `${plural(humans, "player")}${bots > 0 ? ` + ${plural(bots, "AI", "AIs")}` : ""}${observers > 0 ? ` · ${plural(observers, "observer")}` : ""}`;
}

function cell(label: string, ...children: Child[]): HTMLTableCellElement {
  return h("td", { "data-label": label }, ...children);
}

/** The lobbies as table rows; `compact` leaves out the less needed columns (the overview). */
export function lobbyTable(lobbies: Lobby[], compact = false): HTMLElement {
  const head = ["Lobby", "State", "Map", "Players", "CPUs", "Use now", ...(compact ? [] : ["Started", ""])];
  return h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: `grid-table lobby-table${compact ? " compact" : ""}` },
      h("thead", {}, h("tr", {}, ...head.map((text) => h("th", { scope: "col" }, text)))),
      h(
        "tbody",
        {},
        ...lobbies.map((lobby) => {
          const href = `#/lobby/${encodeURIComponent(lobby.id)}`;
          const map = knownMap(lobby.map?.id);
          const thumb = map === undefined ? h("span", { class: "map-art tiny no-preview" }, h("span", { class: "map-art-size" }, isNumber(lobby.map?.km) ? `${lobby.map.km}` : "?")) : mapArt(map, hostPreview);
          thumb.classList.add("tiny");
          const cpus = (lobby.cpus ?? []).filter(isNumber);
          const nodes = (lobby.nodes ?? []).filter(isNumber);
          const actions = h("div", { class: "row-actions" });
          if (LIVE.has(lobby.state)) actions.append(h("a", { class: "btn small primary", href }, "Open"));
          if (RUNNING.has(lobby.state)) {
            const stop = h("button", { type: "button", class: "btn small danger" }, "Stop…");
            stop.addEventListener("click", () => void stopLobby(lobby.id, stop));
            actions.append(stop);
          }
          if (lobby.state === "stopped" || lobby.state === "failed") {
            actions.append(h("a", { class: "btn small", href }, "Details"));
            const forget = h("button", { type: "button", class: "btn small ghost", title: "Take it off the list" }, "Remove");
            forget.addEventListener("click", () => void forgetLobby(lobby.id, forget));
            actions.append(forget);
          }
          const started = ageSeconds(lobby.started_at ?? lobby.created);
          return h(
            "tr",
            { "data-state": lobby.state },
            cell(
              "Lobby",
              h(
                "div",
                { class: "lobby-name-cell" },
                thumb,
                h("div", { class: "lobby-name-text" }, h("a", { class: "lobby-link", href }, swatch(lobby.id), displayName(lobby)), h("span", { class: "chips" }, kindChip(lobby))),
              ),
            ),
            cell("State", h("div", { class: "state-cell" }, stateChip(lobby.state), lobby.phase === "game" && isNumber(lobby.beat) ? h("span", { class: "game-clock" }, clock(lobby.beat)) : null, lobby.state === "failed" && lobby.exit ? h("span", { class: "small bad-text" }, lobby.exit) : null)),
            cell("Map", h("span", {}, lobby.map?.name ?? lobby.map?.id ?? "–", isNumber(lobby.map?.km) ? h("span", { class: "dim" }, ` · ${lobby.map.km} km`) : null)),
            cell("Players", players(lobby)),
            cell("CPUs", cpus.length === 0 ? h("span", { class: "dim" }, "–") : h("div", { class: "cpu-cell" }, cpuChips(cpus, lobby.id), h("span", { class: "dim small" }, nodes.length === 0 ? "" : `node ${nodes.join(", ")}${isPoolLobby(lobby) ? " · pool" : ""}`))),
            cell("Use now", RUNNING.has(lobby.state) ? usageLine(cpus.length, lobby.usage) : h("span", { class: "dim" }, "–")),
            ...(compact ? [] : [cell("Started", h("div", { class: "state-cell" }, h("span", {}, timeOf(lobby.started_at ?? lobby.created)), started === null ? null : h("span", { class: "dim small" }, `${duration(started)} ago${lobby.queued_at ? ", queued first" : ""}`))), cell("", actions)]),
          );
        }),
      ),
    ),
  );
}

type Filter = "all" | "running" | "tournament" | "custom" | "requests" | "ended";
const FILTERS: [Filter, string][] = [
  ["running", "Running"],
  ["tournament", "Tournament"],
  ["custom", "Custom"],
  ["requests", "Player requests"],
  ["ended", "Ended"],
  ["all", "All"],
];

export function lobbiesView(): View {
  const root = byId<HTMLElement>("view-lobbies");
  let filter: Filter = "running";
  let off: (() => void) | null = null;
  const chips = h("div", { class: "seg-chips", role: "group", "aria-label": "Show" });
  const body = h("div", {});
  const sub = h("span", {});
  root.replaceChildren(pageHead("Lobbies", sub, h("a", { class: "btn primary", href: "#/create" }, icon("plus", "icon"), "Create lobby")), h("section", { class: "card" }, h("div", { class: "card-head" }, chips), body));

  function matches(lobby: Lobby): boolean {
    switch (filter) {
      case "running":
        return RUNNING.has(lobby.state);
      case "tournament":
        return kindOf(lobby) === "tournament";
      case "custom":
        return kindOf(lobby) === "custom" && !isPoolLobby(lobby);
      case "requests":
        return isPoolLobby(lobby);
      case "ended":
        return !RUNNING.has(lobby.state);
      default:
        return true;
    }
  }

  function render(): void {
    const all = store.lobbies;
    chips.replaceChildren(
      ...FILTERS.map(([id, text]) => {
        const count = all.filter((lobby) => {
          const keep = filter;
          filter = id;
          const ok = matches(lobby);
          filter = keep;
          return ok;
        }).length;
        const button = h("button", { type: "button", class: "seg-chip", "aria-pressed": String(filter === id) }, text, h("span", { class: "seg-count" }, String(count)));
        button.addEventListener("click", () => {
          filter = id;
          render();
        });
        return button;
      }),
    );
    const running = all.filter((lobby) => RUNNING.has(lobby.state));
    sub.textContent = `${plural(running.length, "lobby", "lobbies")} running: ${running.filter((lobby) => kindOf(lobby) === "tournament").length} tournament, ${running.filter((lobby) => kindOf(lobby) === "custom" && !isPoolLobby(lobby)).length} custom, ${running.filter(isPoolLobby).length} from player requests`;
    const shown = all.filter(matches).sort((a, b) => Number(!RUNNING.has(a.state)) - Number(!RUNNING.has(b.state)) || String(b.started_at ?? b.created ?? "").localeCompare(String(a.started_at ?? a.created ?? "")));
    body.replaceChildren(shown.length === 0 ? emptyState(filter === "running" ? "Nothing is running" : "No lobbies here", filter === "running" ? "Create a lobby, or turn on player hosting so players can ask for one." : "Another filter may show some.", filter === "running" ? h("a", { class: "btn primary", href: "#/create" }, "Create lobby") : null) : lobbyTable(shown));
  }

  return {
    show(): void {
      off ??= on("lists", render);
      render();
    },
    hide(): void {
      off?.();
      off = null;
    },
  };
}
