// Logs: the host's own log and any lobby's server log (running or ended), live, with a text and level filter. The
// sources are listed on the left; `#/logs/<lobby id>` opens a lobby's.

import { byId, h, icon } from "../dom.ts";
import { followHostLog, followLobbyLog, LogView } from "../logview.ts";
import { stateChip, swatch } from "../plane/parts.ts";
import { displayName, LIVE, lobbyById, on, RUNNING, store } from "../plane/store.ts";
import { pageHead, type View } from "./common.ts";

export function logsView(): View {
  const root = byId<HTMLElement>("view-logs");
  const sources = h("nav", { class: "log-sources", "aria-label": "Log sources" });
  const title = h("h2", {});
  const meta = h("span", { class: "card-meta" });
  const view = new LogView({ tall: true });
  root.replaceChildren(pageHead("Logs", "The host's own log and each lobby's server log, also after the lobby ended."), h("div", { class: "logs-layout" }, h("section", { class: "card log-source-card" }, h("h2", {}, "Sources"), sources), h("section", { class: "card log-card" }, h("div", { class: "card-head" }, title, meta), view.root)));
  let source = "host";
  let stop: (() => void) | null = null;
  let off: (() => void) | null = null;

  function open(next: string): void {
    stop?.();
    stop = null;
    source = next;
    const api = store.api;
    renderSources();
    if (api === null) return;
    if (source === "host") {
      title.textContent = "Host log";
      meta.textContent = "server-host itself: lobbies starting and ending, the queue, the pool";
      stop = followHostLog(api, view);
      return;
    }
    const lobby = lobbyById(source);
    title.replaceChildren(swatch(source), lobby === undefined ? source : displayName(lobby));
    meta.replaceChildren(lobby === undefined ? "" : stateChip(lobby.state), " ", h("a", { href: `#/lobby/${encodeURIComponent(source)}` }, "Open the lobby"));
    const id = source;
    stop = followLobbyLog(api, id, view, () => RUNNING.has(lobbyById(id)?.state ?? "") || LIVE.has(lobbyById(id)?.state ?? ""));
  }

  function renderSources(): void {
    const lobbies = [...store.lobbies].sort((a, b) => Number(!RUNNING.has(a.state)) - Number(!RUNNING.has(b.state)) || String(b.started_at ?? b.created ?? "").localeCompare(String(a.started_at ?? a.created ?? "")));
    const link = (id: string, label: Node | string, extra: Node | null): HTMLElement => h("a", { class: `log-source${source === id ? " current" : ""}`, href: id === "host" ? "#/logs" : `#/logs/${encodeURIComponent(id)}`, "aria-current": source === id ? "page" : null }, label, extra);
    sources.replaceChildren(
      link("host", h("span", { class: "log-source-name" }, icon("server", "icon"), "Host"), null),
      h("p", { class: "log-source-group" }, "Lobbies"),
      ...lobbies.map((lobby) => link(lobby.id, h("span", { class: "log-source-name" }, swatch(lobby.id), displayName(lobby)), stateChip(lobby.state))),
    );
  }

  return {
    show(arg): void {
      off ??= on("lists", renderSources);
      const next = arg === null || arg === "" ? "host" : arg;
      if (next !== source || stop === null) open(next);
      else renderSources();
    },
    hide(): void {
      off?.();
      off = null;
      stop?.();
      stop = null;
    },
  };
}
