// Lobbies: every lobby as a table (map, kind, state, players, CPUs and node, live use, when it started), filtered by
// kind or state, with Open, Stop and Remove. Through the control service: every host's lobbies with their host, where
// the viewer has a place, and Stop only where their role allows it; a host filter narrows them. `lobbyTable` also draws
// the overviews' running lobbies.

import type { Lobby, MapInfo } from "../api.ts";
import { topRole } from "../control.ts";
import { byId, clock, h, icon, isNumber, type Child } from "../dom.ts";
import { mapArt } from "../maps.ts";
import { cpuChips, emptyState, forgetLobby, kindChip, stateChip, stopLobby, swatch, timeOf, usageLine } from "../plane/parts.ts";
import { ageSeconds, displayName, duration, isPoolLobby, kindOf, LIVE, on, plural, RUNNING, store } from "../plane/store.ts";
import { service } from "../service.ts";
import { hostPreview, knownMap, pageHead, type View } from "./common.ts";
import { hostChips } from "./service.ts";

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

/** The map's thumbnail: the host's preview when the page may load it (one host, or organisers through the service). */
function thumbOf(lobby: Lobby): HTMLElement {
  const placeholder = (): HTMLElement => h("span", { class: "map-art tiny no-preview" }, h("span", { class: "map-art-size" }, isNumber(lobby.map?.km) ? `${lobby.map.km}` : "?"));
  if (store.mode === "service") {
    const view = lobby.service;
    const id = lobby.map?.id;
    if (view === undefined || view === null || id === undefined || topRole(service.me) === "player" || store.api === null) return placeholder();
    const map: MapInfo = { id, name: lobby.map?.name ?? id, km: lobby.map?.km ?? null, preview: `/api/v1/maps/${encodeURIComponent(id)}/preview.png` };
    const host = store.api.lobbyHost(lobby.id);
    const art = mapArt(map, (item) => Promise.resolve(host.previewUrl(item)));
    art.classList.add("tiny");
    return art;
  }
  const map = knownMap(lobby.map?.id);
  if (map === undefined) return placeholder();
  const art = mapArt(map, hostPreview);
  art.classList.add("tiny");
  return art;
}

/** Through the service: the viewer's place in the lobby, if any. */
function yourPlace(lobby: Lobby): Child {
  const you = lobby.service?.you;
  if (you === undefined || you === null) return null;
  if (isNumber(you.seat) && you.seat > 0) return h("span", { class: "chip tiny tone-accent", title: "You play in it: your join line is on its page" }, `your seat ${you.seat}`);
  if (typeof you.watch === "string" && you.watch !== "") return h("span", { class: "chip tiny tone-info", title: "You watch it: your watch line is on its page" }, "you watch");
  return null;
}

/** The lobbies as table rows; `compact` leaves out the less needed columns (the overview). */
export function lobbyTable(lobbies: Lobby[], compact = false): HTMLElement {
  const viaService = store.mode === "service";
  const head = viaService ? ["Lobby", "Host", "State", "Map", "Players", ...(compact ? [] : ["Started", ""])] : ["Lobby", "State", "Map", "Players", "CPUs", "Use now", ...(compact ? [] : ["Started", ""])];
  return h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: `grid-table lobby-table${compact ? " compact" : ""}${viaService ? " via-service" : ""}` },
      h("thead", {}, h("tr", {}, ...head.map((text) => h("th", { scope: "col" }, text)))),
      h(
        "tbody",
        {},
        ...lobbies.map((lobby) => {
          const href = `#/lobby/${encodeURIComponent(lobby.id)}`;
          const view = lobby.service ?? null;
          const cpus = (lobby.cpus ?? []).filter(isNumber);
          const nodes = (lobby.nodes ?? []).filter(isNumber);
          const actions = h("div", { class: "row-actions" });
          if (LIVE.has(lobby.state)) actions.append(h("a", { class: "btn small primary", href }, "Open"));
          if (RUNNING.has(lobby.state) && (view === null || view.can_stop)) {
            const stop = h("button", { type: "button", class: "btn small danger" }, "Stop…");
            stop.addEventListener("click", () => void stopLobby(lobby.id, stop));
            actions.append(stop);
          }
          if (lobby.state === "stopped" || lobby.state === "failed") {
            actions.append(h("a", { class: "btn small", href }, "Details"));
            if (view === null) {
              const forget = h("button", { type: "button", class: "btn small ghost", title: "Take it off the list" }, "Remove");
              forget.addEventListener("click", () => void forgetLobby(lobby.id, forget));
              actions.append(forget);
            }
          }
          const started = ageSeconds(lobby.started_at ?? lobby.created);
          const nameCell = cell(
            "Lobby",
            h(
              "div",
              { class: "lobby-name-cell" },
              thumbOf(lobby),
              h("div", { class: "lobby-name-text" }, h("a", { class: "lobby-link", href }, swatch(lobby.id), displayName(lobby)), h("span", { class: "chips" }, kindChip(lobby), yourPlace(lobby))),
            ),
          );
          const stateCell = cell(
            "State",
            h(
              "div",
              { class: "state-cell" },
              stateChip(lobby.state),
              lobby.phase === "game" && isNumber(lobby.beat) ? h("span", { class: "game-clock" }, clock(lobby.beat)) : null,
              lobby.state === "failed" && lobby.exit ? h("span", { class: "small bad-text" }, lobby.exit) : null,
              view?.stale === true ? h("span", { class: "small warn-text", title: "Its host didn't answer at the service's last look" }, "host not answering") : null,
            ),
          );
          const mapCell = cell("Map", h("span", {}, lobby.map?.name ?? lobby.map?.id ?? "–", isNumber(lobby.map?.km) ? h("span", { class: "dim" }, ` · ${lobby.map.km} km`) : null));
          const startedCell = cell("Started", h("div", { class: "state-cell" }, h("span", {}, timeOf(lobby.started_at ?? lobby.created)), started === null ? null : h("span", { class: "dim small" }, `${duration(started)} ago${lobby.queued_at ? ", queued first" : ""}`)));
          if (view !== null) {
            return h("tr", { "data-state": lobby.state }, nameCell, cell("Host", h("span", { class: "host-cell" }, icon("server", "icon tiny"), view.host)), stateCell, mapCell, cell("Players", players(lobby)), ...(compact ? [] : [startedCell, cell("", actions)]));
          }
          return h(
            "tr",
            { "data-state": lobby.state },
            nameCell,
            stateCell,
            mapCell,
            cell("Players", players(lobby)),
            cell("CPUs", cpus.length === 0 ? h("span", { class: "dim" }, "–") : h("div", { class: "cpu-cell" }, cpuChips(cpus, lobby.id), h("span", { class: "dim small" }, nodes.length === 0 ? "" : `node ${nodes.join(", ")}${isPoolLobby(lobby) ? " · pool" : ""}`))),
            cell("Use now", RUNNING.has(lobby.state) ? usageLine(cpus.length, lobby.usage) : h("span", { class: "dim" }, "–")),
            ...(compact ? [] : [startedCell, cell("", actions)]),
          );
        }),
      ),
    ),
  );
}

type Filter = "all" | "running" | "tournament" | "custom" | "requests" | "ended" | "mine";
const FILTERS: [Filter, string][] = [
  ["running", "Running"],
  ["tournament", "Tournament"],
  ["custom", "Custom"],
  ["requests", "Player requests"],
  ["ended", "Ended"],
  ["all", "All"],
];
const SERVICE_FILTERS: [Filter, string][] = [
  ["running", "Running"],
  ["mine", "With a place for you"],
  ["tournament", "Organised"],
  ["requests", "Player games"],
  ["custom", "Made on a host"],
  ["ended", "Ended"],
  ["all", "All"],
];

export function lobbiesView(): View {
  const root = byId<HTMLElement>("view-lobbies");
  let filter: Filter = "running";
  let off: (() => void)[] = [];
  const chips = h("div", { class: "seg-chips", role: "group", "aria-label": "Show" });
  const hostsBox = h("div", {});
  const body = h("div", {});
  const sub = h("span", {});
  const createLink = h("a", { class: "btn primary", href: "#/create", "data-needs": "organiser" }, icon("plus", "icon"), "Create lobby");
  root.replaceChildren(pageHead("Lobbies", sub, createLink), h("section", { class: "card" }, h("div", { class: "card-head wrap" }, chips), hostsBox, body));

  function matches(lobby: Lobby, which: Filter = filter): boolean {
    const view = lobby.service;
    if (view !== undefined && view !== null) {
      switch (which) {
        case "running":
          return RUNNING.has(lobby.state);
        case "mine":
          return (view.you !== undefined && view.you !== null) || (view.origin === "hosted" && view.can_stop);
        case "tournament":
          return view.origin === "organised";
        case "requests":
          return view.origin === "hosted";
        case "custom":
          return view.origin === "host";
        case "ended":
          return !RUNNING.has(lobby.state);
        default:
          return true;
      }
    }
    switch (which) {
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
    const viaService = store.mode === "service";
    const all = store.lobbies.filter((lobby) => !viaService || service.hostFilter === "" || lobby.service?.host === service.hostFilter);
    chips.replaceChildren(
      ...(viaService ? SERVICE_FILTERS : FILTERS).map(([id, text]) => {
        const count = all.filter((lobby) => matches(lobby, id)).length;
        const button = h("button", { type: "button", class: "seg-chip", "aria-pressed": String(filter === id) }, text, h("span", { class: "seg-count" }, String(count)));
        button.addEventListener("click", () => {
          filter = id;
          render();
        });
        return button;
      }),
    );
    hostsBox.replaceChildren(viaService && service.hosts.length > 1 ? h("div", { class: "card-subhead" }, h("span", { class: "dim small" }, "Host"), hostChips(render)) : "");
    const running = all.filter((lobby) => RUNNING.has(lobby.state));
    sub.textContent = viaService
      ? `${plural(running.length, "lobby", "lobbies")} running${service.hostFilter === "" ? ` on ${plural(service.hosts.length, "host")}` : ` on ${service.hostFilter}`}: ${running.filter((lobby) => lobby.service?.origin === "organised").length} organised, ${running.filter((lobby) => lobby.service?.origin === "hosted").length} player games, ${running.filter((lobby) => lobby.service?.origin === "host").length} made on a host`
      : `${plural(running.length, "lobby", "lobbies")} running: ${running.filter((lobby) => kindOf(lobby) === "tournament").length} tournament, ${running.filter((lobby) => kindOf(lobby) === "custom" && !isPoolLobby(lobby)).length} custom, ${running.filter(isPoolLobby).length} from player requests`;
    const shown = all.filter((lobby) => matches(lobby)).sort((a, b) => Number(!RUNNING.has(a.state)) - Number(!RUNNING.has(b.state)) || String(b.started_at ?? b.created ?? "").localeCompare(String(a.started_at ?? a.created ?? "")));
    const organiser = !viaService || topRole(service.me) !== "player";
    body.replaceChildren(
      shown.length === 0
        ? emptyState(
            filter === "running" ? "Nothing is running" : "No lobbies here",
            filter === "running" ? (viaService ? (organiser ? "Create a lobby, or wait for players' games." : "Lobbies show here as they start.") : "Create a lobby, or turn on player hosting so players can ask for one.") : "Another filter may show some.",
            filter === "running" && organiser ? h("a", { class: "btn primary", href: "#/create" }, "Create lobby") : null,
          )
        : lobbyTable(shown),
    );
  }

  return {
    show(): void {
      if (off.length === 0) off = [on("lists", render), on("service", render)];
      render();
    },
    hide(): void {
      for (const stop of off) stop();
      off = [];
    },
  };
}
