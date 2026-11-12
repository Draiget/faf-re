// Small pieces several views share: a lobby's state and kind chips, placement warnings, the join and watch lines with
// copy buttons, CPU chips, the use line, facts, and stopping or forgetting a lobby.

import type { Lobby, PlacementWarning } from "../api.ts";
import { h, icon, isNumber, num, type Child } from "../dom.ts";
import { confirmAction, copyButton, toast } from "../ui.ts";
import { actions, colour, displayName, kindOf, plural, store } from "./store.ts";

const GAME_EXE = "main_x64.exe /init init_faf.lua";

const LOBBY_STATE: Record<string, [string, string]> = {
  starting: ["Starting", "info"],
  lobby: ["In lobby", "accent"],
  game: ["In game", "ok"],
  ended: ["Ended", "neutral"],
  failed: ["Failed", "bad"],
  stopped: ["Stopped", "muted"],
};

export function stateChip(state: string): HTMLElement {
  const [label, tone] = LOBBY_STATE[state] ?? [state, "neutral"];
  return h("span", { class: `chip state-chip tone-${tone}${state === "starting" ? " spinning" : ""}` }, h("span", { class: "chip-dot", "aria-hidden": "true" }), label);
}

export function kindChip(lobby: Lobby): HTMLElement {
  const kind = kindOf(lobby);
  if (typeof lobby.request === "string" && lobby.request !== "") return h("span", { class: "chip kind-chip kind-request", title: `Asked for by a player (request ${lobby.request})` }, icon("users", "icon tiny"), "Player request");
  return kind === "tournament"
    ? h("span", { class: "chip kind-chip kind-tournament", title: "The organiser sets everything; nobody hosts" }, icon("trophy", "icon tiny"), "Tournament")
    : h("span", { class: "chip kind-chip kind-custom", title: "Seat 1 hosts it in their own lobby screen" }, icon("crown", "icon tiny"), "Custom");
}

const SEVERITY_ICON: Record<string, string> = { error: "ban", warn: "warn", info: "info" };
const SEVERITY_TONE: Record<string, string> = { error: "bad", warn: "warn", info: "info" };

/** Placement warnings, most severe first, one line per code with the rest of the same code folded under it. */
export function warningList(warnings: PlacementWarning[]): HTMLElement {
  const order: Record<string, number> = { error: 0, warn: 1, info: 2 };
  const sorted = [...warnings].sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
  const byCode = new Map<string, PlacementWarning[]>();
  for (const warning of sorted) byCode.set(`${warning.severity}:${warning.code}`, [...(byCode.get(`${warning.severity}:${warning.code}`) ?? []), warning]);
  return h(
    "ul",
    { class: "warnings" },
    ...[...byCode.values()].map((group) => {
      const [first, ...more] = group;
      if (first === undefined) return null;
      return h(
        "li",
        { class: `warning tone-${SEVERITY_TONE[first.severity] ?? "neutral"}`, "data-code": first.code },
        icon(SEVERITY_ICON[first.severity] ?? "info", "icon tiny"),
        h(
          "div",
          { class: "warning-text" },
          h("span", { class: "sr-only" }, `${first.severity}: `),
          h("span", {}, first.text),
          more.length === 0 ? null : h("details", { class: "more-warnings" }, h("summary", {}, `${more.length} more like this`), h("ul", {}, ...more.map((warning) => h("li", {}, warning.text)))),
        ),
      );
    }),
  );
}

/** A compact warnings line that opens to the list. */
export function warningSummary(warnings: PlacementWarning[]): HTMLElement | null {
  if (warnings.length === 0) return null;
  const errors = warnings.filter((warning) => warning.severity === "error").length;
  const warns = warnings.filter((warning) => warning.severity === "warn").length;
  const tone = errors > 0 ? "bad" : warns > 0 ? "warn" : "info";
  const parts = [errors > 0 ? plural(errors, "error") : "", warns > 0 ? plural(warns, "warning") : "", warnings.length - errors - warns > 0 ? plural(warnings.length - errors - warns, "note") : ""].filter((part) => part !== "");
  return h("details", { class: `warn-details tone-${tone}` }, h("summary", {}, icon(SEVERITY_ICON[errors > 0 ? "error" : warns > 0 ? "warn" : "info"] ?? "info", "icon tiny"), `Placement: ${parts.join(", ")}`), warningList(warnings));
}

/** Each human seat's join switches, with a copy button. */
export function joinBlock(lobby: { seats?: Lobby["seats"] }): HTMLElement {
  const humans = (lobby.seats ?? []).filter((seat) => seat.kind === "human");
  if (humans.length === 0) return h("p", { class: "dim join-help" }, "No human seats: nobody joins this lobby from a game.");
  return h(
    "div",
    { class: "join" },
    h("p", { class: "join-help" }, "Each player starts the game (our engine) with their own line to join:"),
    h(
      "ul",
      { class: "join-list" },
      ...humans.map((seat) => {
        const who = seat.name || `Seat ${seat.seat}`;
        const command = typeof seat.join === "string" && seat.join !== "" ? seat.join : null;
        return h(
          "li",
          { class: "join-row" },
          h("div", { class: "join-who" }, h("strong", {}, who), h("span", { class: "dim" }, ` · start spot ${seat.seat}${isNumber(seat.uid) ? ` · uid ${seat.uid}` : ""}`)),
          h("div", { class: "join-cmd" }, h("code", { class: "cmd" }, command ?? "not given out yet"), command === null ? null : copyButton(command, `Copy the join switches for ${who}`)),
        );
      }),
    ),
  );
}

/** Each observer's watch line (a live replay of the lobby's game), with copy buttons for it and the whole command. */
export function watchBlock(lobby: Lobby): HTMLElement {
  const list = lobby.observers ?? [];
  const delay = isNumber(lobby.observer_delay_seconds) ? lobby.observer_delay_seconds : 0;
  return h(
    "div",
    { class: "join watch" },
    h("p", { class: "join-help" }, "Observers open the game with their line to watch", delay > 0 ? `; they see it ${delay} s late, referees live.` : "."),
    h(
      "ul",
      { class: "join-list" },
      ...list.map((observer, index) => {
        const who = observer.name || `Observer ${index + 1}`;
        const watch = typeof observer.watch === "string" && observer.watch !== "" ? observer.watch : null;
        return h(
          "li",
          { class: "join-row" },
          h("div", { class: "join-who" }, h("strong", {}, who), " ", observer.referee === true ? h("span", { class: "chip tiny tone-accent" }, "Referee · live") : delay > 0 ? h("span", { class: "dim" }, `· ${delay} s behind`) : null),
          h(
            "div",
            { class: "join-cmd" },
            h("code", { class: "cmd" }, watch ?? "not given out yet"),
            watch === null ? null : copyButton(watch, `Copy the watch switches for ${who}`),
            watch === null ? null : copyButton(`${GAME_EXE} ${watch}`, `Copy the whole start command for ${who}`, "Command"),
          ),
        );
      }),
    ),
  );
}

export function cpuChips(cpus: number[], id: string): Child {
  if (cpus.length === 0) return h("span", { class: "dim" }, "–");
  const box = h("span", { class: "cpu-chips" }, ...cpus.map((cpu) => h("span", { class: "cpu-chip" }, String(cpu))));
  box.style.setProperty("--c", colour(id));
  return box;
}

/** A small bar: the lobby's CPU use against its CPUs, with cores and memory. */
export function usageLine(cpus: number, usage: Lobby["usage"]): Child {
  const cores = usage?.cpu_cores;
  const rss = usage?.rss_mb;
  if (!isNumber(cores) && !isNumber(rss)) return h("span", { class: "dim" }, "–");
  const ratio = isNumber(cores) ? cores / Math.max(1, cpus) : 0;
  const fillEl = h("span", { class: "fill" });
  fillEl.style.width = `${Math.min(100, ratio * 100).toFixed(1)}%`;
  return h(
    "span",
    { class: "usage" },
    h("span", { class: `bar tiny-bar${ratio > 0.9 ? " tone-bad" : ratio > 0.7 ? " tone-warn" : ""}`, role: "meter", "aria-label": "CPU use", "aria-valuemin": 0, "aria-valuemax": Math.max(1, cpus), "aria-valuenow": isNumber(cores) ? cores : 0 }, fillEl),
    h("span", { class: "usage-text" }, isNumber(cores) ? `${num(cores, 2)} cores` : "–", h("span", { class: "dim" }, ` · ${isNumber(rss) ? `${num(rss)} MB` : "–"}`)),
  );
}

export function fact(label: string, value: Child, wide = false): HTMLElement {
  return h("div", { class: `fact-item${wide ? " wide" : ""}` }, h("dt", {}, label), h("dd", {}, value));
}

/** A coloured square in the lobby's colour (the one its CPUs carry on the machine map). */
export function swatch(id: string): HTMLElement {
  const node = h("span", { class: "swatch", "aria-hidden": "true" });
  node.style.setProperty("--swatch", colour(id));
  return node;
}

export async function stopLobby(id: string, button: HTMLButtonElement): Promise<void> {
  const lobby = store.lobbies.find((candidate) => candidate.id === id);
  const api = store.api;
  if (lobby === undefined || api === null) return;
  const ok = await confirmAction(
    `Stop ${displayName(lobby)}?`,
    `Its server stops${lobby.state === "game" ? " in the middle of the game" : ""}, and everyone in it is disconnected. Its CPUs are free again; it stays listed as stopped until you forget it.`,
    "Stop the lobby",
  );
  if (!ok) return;
  button.disabled = true;
  button.classList.add("busy");
  try {
    await api.stopLobby(id);
    toast("ok", `Stopped ${displayName(lobby)}`);
  } catch (error) {
    toast("bad", `Couldn't stop ${displayName(lobby)}`, error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
    button.classList.remove("busy");
  }
  actions.refresh();
}

export async function forgetLobby(id: string, button: HTMLButtonElement): Promise<boolean> {
  const api = store.api;
  if (api === null) return false;
  button.disabled = true;
  try {
    await api.forgetLobby(id);
    toast("ok", "Removed the lobby from the list");
    actions.refresh();
    return true;
  } catch (error) {
    toast("bad", "Couldn't remove the lobby", error instanceof Error ? error.message : String(error));
    return false;
  } finally {
    button.disabled = false;
  }
}

/** A host address only this machine can reach (players elsewhere can't use a link to it). */
export function loopback(base: string): boolean {
  try {
    const name = new URL(base).hostname.replace(/^\[|\]$/g, "");
    return name === "localhost" || name === "::1" || /^127\./.test(name);
  } catch {
    return false;
  }
}

/** KB/s for people. */
export function rate(kbs: unknown): string {
  if (!isNumber(kbs)) return "–";
  if (kbs >= 1000) return `${(kbs / 1000).toFixed(kbs >= 10000 ? 0 : 1)} MB/s`;
  return `${kbs.toFixed(kbs < 10 ? 1 : 0)} KB/s`;
}

export function gb(mb: number): string {
  return `${(mb / 1024).toFixed(mb >= 100 * 1024 ? 0 : 1)} GB`;
}

export function meter(label: string, value: number, max: number, text: string, tone = ""): HTMLElement {
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  const fillEl = h("span", { class: "fill" });
  fillEl.style.width = `${(ratio * 100).toFixed(1)}%`;
  return h("div", { class: `bar${tone === "" ? "" : ` tone-${tone}`}`, role: "meter", "aria-label": label, "aria-valuemin": 0, "aria-valuemax": max, "aria-valuenow": Math.round(value), "aria-valuetext": text }, fillEl);
}

/** The time of day of an ISO time, or "–". */
export function timeOf(time: string | null | undefined): string {
  if (typeof time !== "string" || time === "") return "–";
  const at = new Date(time);
  return Number.isNaN(at.getTime()) ? "–" : at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** The page-wide empty state: a title, a line, and maybe a button. */
export function emptyState(title: string, text: string, action?: HTMLElement | null): HTMLElement {
  return h("div", { class: "empty big-empty" }, h("p", { class: "empty-title" }, title), h("p", { class: "dim" }, text), action ?? null);
}
