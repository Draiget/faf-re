// The two kinds of capacity use (plan WP17.18, WP17.19): the operator's tournament lobbies and the open slots players
// host on, each with its state, CPUs, nodes, placement warnings and live use; stop, forget, free.

import type { Lobby, PlacementWarning, Slot } from "../api.ts";
import { byId, clock, fill, h, icon, isNumber, num, type Child } from "../dom.ts";
import { confirmAction, copyButton, toast } from "../ui.ts";
import { actions, colour, displayName, on, plural, RUNNING, SLOT_HOLDING, store } from "./store.ts";

const lobbyList = byId<HTMLElement>("plane-lobbies");
const lobbyEmpty = byId<HTMLElement>("plane-lobbies-empty");
const lobbyMeta = byId<HTMLElement>("plane-lobbies-meta");
const slotList = byId<HTMLElement>("plane-slots");
const slotEmpty = byId<HTMLElement>("plane-slots-empty");
const slotMeta = byId<HTMLElement>("plane-slots-meta");
const slotsMissing = byId<HTMLElement>("plane-slots-missing");

for (const button of document.querySelectorAll<HTMLButtonElement>("[data-configure]")) {
  button.addEventListener("click", () => actions.configure(button.dataset.configure === "slots" ? "slots" : "lobby"));
}

const GAME_EXE = "main_x64.exe /init init_faf.lua";

const LOBBY_STATE: Record<string, [string, string]> = {
  starting: ["Starting", "info"],
  lobby: ["Lobby", "accent"],
  game: ["In game", "ok"],
  ended: ["Ended", "neutral"],
  failed: ["Failed", "bad"],
  stopped: ["Stopped", "muted"],
};
const SLOT_STATE: Record<string, [string, string]> = {
  open: ["Open", "info"],
  claimed: ["Claimed", "accent"],
  lobby: ["Lobby", "accent"],
  game: ["In game", "ok"],
  ended: ["Ended", "neutral"],
};

export function stateChip(state: string, slot = false): HTMLElement {
  const [label, tone] = (slot ? SLOT_STATE : LOBBY_STATE)[state] ?? [state, "neutral"];
  return h("span", { class: `chip state-chip tone-${tone}${state === "starting" ? " spinning" : ""}` }, h("span", { class: "chip-dot", "aria-hidden": "true" }), label);
}

const SEVERITY_ICON: Record<string, string> = { error: "ban", warn: "warn", info: "info" };
const SEVERITY_TONE: Record<string, string> = { error: "bad", warn: "warn", info: "info" };

/** Placement warnings, most severe first, each with its severity and the host's text. */
export function warningList(warnings: PlacementWarning[]): HTMLElement {
  const order: Record<string, number> = { error: 0, warn: 1, info: 2 };
  const sorted = [...warnings].sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
  // One line per code: the first warning shown, the rest of the same code (one per CPU, say) folded under it.
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
function warningSummary(warnings: PlacementWarning[]): HTMLElement | null {
  if (warnings.length === 0) return null;
  const errors = warnings.filter((warning) => warning.severity === "error").length;
  const warns = warnings.filter((warning) => warning.severity === "warn").length;
  const tone = errors > 0 ? "bad" : warns > 0 ? "warn" : "info";
  const parts = [errors > 0 ? plural(errors, "error") : "", warns > 0 ? plural(warns, "warning") : "", warnings.length - errors - warns > 0 ? plural(warnings.length - errors - warns, "note") : ""].filter((part) => part !== "");
  return h("details", { class: `warn-details tone-${tone}` }, h("summary", {}, icon(SEVERITY_ICON[errors > 0 ? "error" : warns > 0 ? "warn" : "info"] ?? "info", "icon tiny"), `Placement: ${parts.join(", ")}`), warningList(warnings));
}

/** Each human seat's join switches, with a copy button. */
export function joinBlock(lobby: Lobby): HTMLElement {
  const humans = (lobby.seats ?? []).filter((seat) => seat.kind === "human");
  if (humans.length === 0) return h("p", { class: "dim join-help" }, "No human seats: nobody joins this lobby from a game.");
  return h(
    "div",
    { class: "join" },
    h("p", { class: "join-help" }, "Start the game (our engine) with these switches to join:"),
    h(
      "ul",
      { class: "join-list" },
      ...humans.map((seat) => {
        const who = seat.name || `Seat ${seat.seat}`;
        const command = typeof seat.join === "string" && seat.join !== "" ? seat.join : null;
        return h(
          "li",
          { class: "join-row" },
          h("div", { class: "join-who" }, h("strong", {}, who), h("span", { class: "dim" }, ` · seat ${seat.seat}${isNumber(seat.uid) ? ` · uid ${seat.uid}` : ""}`)),
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
    h("p", { class: "join-help" }, "Open the game with these switches to watch:"),
    h(
      "p",
      { class: "join-help small" },
      "Start command: ",
      h("code", { class: "inline-code" }, `${GAME_EXE} <watch line>`),
      delay > 0 ? `. Observers see the game ${delay} s late; referees see it live.` : ".",
    ),
    h(
      "ul",
      { class: "join-list" },
      ...list.map((observer, index) => {
        const who = observer.name || `Observer ${index + 1}`;
        const watch = typeof observer.watch === "string" && observer.watch !== "" ? observer.watch : null;
        return h(
          "li",
          { class: "join-row" },
          h(
            "div",
            { class: "join-who" },
            h("strong", {}, who),
            " ",
            observer.referee === true ? h("span", { class: "chip tiny tone-accent referee-chip" }, "Referee · no delay") : delay > 0 ? h("span", { class: "dim" }, `· ${delay} s behind`) : null,
          ),
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

function cpuChips(cpus: number[], id: string): Child {
  if (cpus.length === 0) return h("span", { class: "dim" }, "–");
  const box = h("span", { class: "cpu-chips" }, ...cpus.map((cpu) => h("span", { class: "cpu-chip" }, String(cpu))));
  box.style.setProperty("--c", colour(id));
  return box;
}

function usageLine(cpus: number, usage: Lobby["usage"]): Child {
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
    h("span", {}, isNumber(cores) ? `${num(cores, 2)} cores` : "–", h("span", { class: "dim" }, ` · ${isNumber(rss) ? `${rss} MB` : "–"}`)),
  );
}

/**
 * The page a player opens to claim a slot: this dashboard's claim.html next to this page, with the host's address and
 * the code in the query.
 */
export function claimLink(hostBase: string, code: string): string {
  const url = new URL("claim.html", window.location.href);
  url.search = new URLSearchParams({ host: hostBase, code }).toString();
  url.hash = "";
  return url.toString();
}

/** A host address only this machine can reach (players elsewhere can't use a link to it). */
function loopback(base: string): boolean {
  try {
    const name = new URL(base).hostname.replace(/^\[|\]$/g, "");
    return name === "localhost" || name === "::1" || /^127\./.test(name);
  } catch {
    return false;
  }
}

function fact(label: string, value: Child, wide = false): HTMLElement {
  return h("div", { class: `fact-item${wide ? " wide" : ""}` }, h("dt", {}, label), h("dd", {}, value));
}

// ---------------------------------------------------------------- lobby items

interface Item {
  root: HTMLElement;
  update(): void;
}

const lobbyItems = new Map<string, Item>();
const slotItems = new Map<string, Item>();

function lobbyItem(id: string): Item {
  const title = h("h3", { class: "use-name", id: `use-${id}` });
  const chip = h("span", { class: "use-chip" });
  const clockText = h("span", { class: "use-clock" });
  const meta = h("p", { class: "use-meta" });
  const facts = h("dl", { class: "use-facts" });
  const warnings = h("div", { class: "use-warnings" });
  const exit = h("p", { class: "lobby-exit", hidden: true });
  const connectSummary = h("summary", {}, "Join and watch lines");
  const connectBody = h("div", { class: "join-body" });
  const connect = h("details", { class: "join-details" }, connectSummary, connectBody);
  const open = h("a", { class: "btn primary small", href: `#/lobby/${encodeURIComponent(id)}` }, "Open");
  const stop = h("button", { type: "button", class: "btn danger small" }, "Stop…");
  const forget = h("button", { type: "button", class: "btn ghost small" }, "Forget");
  let connectSignature = "";
  let warnSignature = "";
  stop.addEventListener("click", () => void stopLobby(id, stop));
  forget.addEventListener("click", () => void forgetLobby(id, forget));
  const swatch = h("span", { class: "swatch", "aria-hidden": "true" });
  swatch.style.setProperty("--swatch", colour(id));
  const root = h(
    "article",
    { class: "use-item", "aria-labelledby": `use-${id}` },
    h("div", { class: "use-head" }, swatch, title, chip, clockText),
    meta,
    facts,
    warnings,
    exit,
    connect,
    h("div", { class: "lobby-actions" }, open, stop, forget),
  );
  root.style.setProperty("--c", colour(id));

  function update(): void {
    const lobby = store.lobbies.find((candidate) => candidate.id === id);
    if (lobby === undefined) return;
    title.textContent = displayName(lobby);
    chip.replaceChildren(stateChip(lobby.state));
    root.dataset.state = lobby.state;
    clockText.textContent = lobby.phase === "game" && isNumber(lobby.beat) ? clock(lobby.beat) : "";
    const map = lobby.map;
    const seats = lobby.seats ?? [];
    const humans = seats.filter((seat) => seat.kind === "human").length;
    const observers = lobby.observers ?? [];
    fill(
      meta,
      icon("map", "icon tiny"),
      h("span", {}, map?.name ?? map?.id ?? "map unknown"),
      h(
        "span",
        { class: "dim" },
        [isNumber(map?.km) ? ` · ${map.km} km` : "", ` · ${plural(humans, "player")}`, seats.length > humans ? ` + ${plural(seats.length - humans, "AI", "AIs")}` : "", observers.length > 0 ? ` · ${plural(observers.length, "observer")}` : ""].join(""),
      ),
    );
    const cpus = (lobby.cpus ?? []).filter(isNumber);
    const nodes = (lobby.nodes ?? []).filter(isNumber);
    facts.replaceChildren(
      fact("CPUs", cpuChips(cpus, id)),
      fact(nodes.length > 1 ? "Nodes" : "Node", nodes.length === 0 ? "–" : nodes.join(", ")),
      fact("Use", RUNNING.has(lobby.state) ? usageLine(cpus.length, lobby.usage) : h("span", { class: "dim" }, "–"), true),
      fact("Control", lobby.control === "organiser" ? "organiser" : lobby.control === "player" ? "player hosts" : "–"),
    );
    const list = lobby.warnings ?? [];
    const sig = JSON.stringify(list);
    if (sig !== warnSignature) {
      warnSignature = sig;
      fill(warnings, warningSummary(list));
    }
    exit.hidden = !lobby.exit;
    exit.textContent = lobby.exit ? `Exit: ${lobby.exit}` : "";
    const running = RUNNING.has(lobby.state);
    open.hidden = !running;
    stop.hidden = !running;
    forget.hidden = lobby.state !== "stopped" && lobby.state !== "failed";
    const hasHumans = seats.some((seat) => seat.kind === "human");
    connect.hidden = !running || (!hasHumans && observers.length === 0);
    connectSummary.textContent = observers.length > 0 ? `Join and watch lines (${humans} + ${observers.length})` : `Join lines (${humans})`;
    const csig = JSON.stringify([seats.map((seat) => seat.join), observers.map((observer) => [observer.name, observer.referee, observer.watch]), lobby.observer_delay_seconds]);
    if (csig !== connectSignature) {
      connectSignature = csig;
      fill(connectBody, joinBlock(lobby), observers.length > 0 ? watchBlock(lobby) : null);
    }
  }
  update();
  return { root, update };
}

async function stopLobby(id: string, button: HTMLButtonElement): Promise<void> {
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

async function forgetLobby(id: string, button: HTMLButtonElement): Promise<void> {
  const api = store.api;
  if (api === null) return;
  button.disabled = true;
  try {
    await api.forgetLobby(id);
    toast("ok", "Forgot the lobby");
  } catch (error) {
    toast("bad", "Couldn't forget the lobby", error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
  }
  actions.refresh();
}

// ---------------------------------------------------------------- slot items

function slotItem(id: string): Item {
  const title = h("h3", { class: "use-name", id: `use-${id}` });
  const chip = h("span", { class: "use-chip" });
  const meta = h("p", { class: "use-meta" });
  const code = h("div", { class: "claim" });
  const facts = h("dl", { class: "use-facts" });
  const warnings = h("div", { class: "use-warnings" });
  const open = h("a", { class: "btn primary small", hidden: true }, "Open");
  const free = h("button", { type: "button", class: "btn danger small" }, "Free…");
  let codeSignature = "";
  let warnSignature = "";
  free.addEventListener("click", () => void freeSlot(id, free));
  const swatch = h("span", { class: "swatch slot", "aria-hidden": "true" });
  swatch.style.setProperty("--swatch", colour(id));
  const root = h("article", { class: "use-item slot", "aria-labelledby": `use-${id}` }, h("div", { class: "use-head" }, swatch, title, chip), meta, code, facts, warnings, h("div", { class: "lobby-actions" }, open, free));
  root.style.setProperty("--c", colour(id));

  function update(): void {
    const slot = store.slots.find((candidate) => candidate.id === id);
    if (slot === undefined) return;
    title.textContent = displayName(slot);
    chip.replaceChildren(stateChip(slot.state, true));
    root.dataset.state = slot.state;
    const lobby = typeof slot.lobby === "string" ? store.lobbies.find((candidate) => candidate.id === slot.lobby) : undefined;
    fill(
      meta,
      icon("users", "icon tiny"),
      h("span", {}, `up to ${isNumber(slot.max_players) ? slot.max_players : "?"} players`),
      isNumber(slot.km) ? h("span", { class: "dim" }, ` · maps up to ${slot.km} km`) : null,
      slot.host_player ? h("span", { class: "dim" }, ` · hosted by `, h("b", {}, slot.host_player)) : null,
      lobby?.map ? h("span", { class: "dim" }, ` · ${lobby.map.name ?? lobby.map.id ?? ""}`) : null,
      lobby?.phase === "game" && isNumber(lobby.beat) ? h("span", { class: "dim" }, ` · ${clock(lobby.beat)}`) : null,
    );
    const claim = typeof slot.claim_code === "string" && slot.claim_code !== "" ? slot.claim_code : null;
    const hostBase = store.api?.base ?? "";
    const csig = `${slot.state}|${claim ?? ""}|${hostBase}`;
    if (csig !== codeSignature) {
      codeSignature = csig;
      const shown = claim !== null && (slot.state === "open" || slot.state === "claimed");
      const link = shown && hostBase !== "" ? claimLink(hostBase, claim) : null;
      fill(
        code,
        shown
          ? h(
              "div",
              { class: "join-cmd" },
              h("span", { class: "claim-label small" }, "Claim code"),
              h("code", { class: "cmd" }, claim),
              copyButton(claim, `Copy the claim code of ${displayName(slot)}`),
            )
          : null,
        link === null
          ? null
          : h(
              "div",
              { class: "join-cmd claim-link" },
              h("span", { class: "claim-label small" }, "Claim link"),
              h("a", { class: "cmd", href: link, target: "_blank", rel: "noopener" }, link),
              copyButton(link, `Copy the claim link of ${displayName(slot)}`),
            ),
        link !== null && loopback(hostBase) ? h("p", { class: "claim-note" }, `The link points at ${new URL(hostBase).host}, which only this machine reaches: connect with the host's public address to hand it out.`) : null,
      );
    }
    const cpus = (slot.cpus ?? []).filter(isNumber);
    const nodes = (slot.nodes ?? []).filter(isNumber);
    facts.replaceChildren(
      fact("CPUs", cpuChips(cpus, id)),
      fact(nodes.length > 1 ? "Nodes" : "Node", nodes.length === 0 ? "–" : nodes.join(", ")),
      fact("Use", lobby !== undefined ? usageLine(cpus.length, lobby.usage) : h("span", { class: "dim" }, "held, not claimed"), true),
      fact("Games", isNumber(slot.games) ? String(slot.games) : "–"),
      fact("After a game", slot.reopen === false ? "ends" : slot.reopen === true ? "reopens" : "–"),
    );
    const list = slot.warnings ?? [];
    const sig = JSON.stringify(list);
    if (sig !== warnSignature) {
      warnSignature = sig;
      fill(warnings, warningSummary(list));
    }
    open.hidden = lobby === undefined || !RUNNING.has(lobby.state);
    if (lobby !== undefined) open.setAttribute("href", `#/lobby/${encodeURIComponent(lobby.id)}`);
    free.textContent = slot.lobby ? "Stop the game…" : "Free…";
  }
  update();
  return { root, update };
}

async function freeSlot(id: string, button: HTMLButtonElement): Promise<void> {
  const slot = store.slots.find((candidate) => candidate.id === id);
  const api = store.api;
  if (slot === undefined || api === null) return;
  const claimed = typeof slot.lobby === "string";
  const ok = await confirmAction(
    claimed ? `Stop the game on ${displayName(slot)}?` : `Free ${displayName(slot)}?`,
    claimed
      ? `${slot.host_player ?? "A player"} hosts on it: its server stops and everyone in it is disconnected, and its CPUs are free again.`
      : "Its CPUs are free again, and its claim code stops working.",
    claimed ? "Stop the game" : "Free the slot",
  );
  if (!ok) return;
  button.disabled = true;
  button.classList.add("busy");
  try {
    await api.deleteSlot(id);
    toast("ok", claimed ? `Stopped the game on ${displayName(slot)}` : `Freed ${displayName(slot)}`);
  } catch (error) {
    toast("bad", `Couldn't free ${displayName(slot)}`, error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
    button.classList.remove("busy");
  }
  actions.refresh();
}

// ---------------------------------------------------------------- lists

function sync(container: HTMLElement, items: Map<string, Item>, ids: string[], make: (id: string) => Item): void {
  const wanted: HTMLElement[] = [];
  for (const id of ids) {
    let item = items.get(id);
    if (item === undefined) {
      item = make(id);
      items.set(id, item);
    } else {
      item.update();
    }
    wanted.push(item.root);
  }
  for (const id of [...items.keys()]) if (!ids.includes(id)) items.delete(id);
  const current = [...container.children];
  if (current.length !== wanted.length || current.some((node, index) => node !== wanted[index])) container.replaceChildren(...wanted);
}

function renderLists(): void {
  // A claimed slot's lobby is listed with the slot, not among the tournament lobbies.
  const slotLobbies = new Set(store.slots.map((slot) => slot.lobby).filter((id): id is string => typeof id === "string"));
  const lobbies = store.lobbies
    .filter((lobby) => !slotLobbies.has(lobby.id))
    .sort((a, b) => Number(!RUNNING.has(a.state)) - Number(!RUNNING.has(b.state)) || String(b.created ?? "").localeCompare(String(a.created ?? "")));
  sync(lobbyList, lobbyItems, lobbies.map((lobby) => lobby.id), lobbyItem);
  const running = lobbies.filter((lobby) => RUNNING.has(lobby.state)).length;
  lobbyEmpty.hidden = lobbies.length > 0;
  lobbyMeta.textContent = lobbies.length === 0 ? "" : `${running} running · ${lobbies.length} listed`;

  slotsMissing.hidden = store.slotsSupported;
  const slots: Slot[] = store.slotsSupported ? store.slots : [];
  sync(slotList, slotItems, slots.map((slot) => slot.id), slotItem);
  slotEmpty.hidden = !store.slotsSupported || slots.length > 0;
  const open = slots.filter((slot) => slot.state === "open").length;
  const held = slots.filter((slot) => SLOT_HOLDING.has(slot.state)).length;
  slotMeta.textContent = slots.length === 0 ? "" : `${open} open · ${held - open} in use`;
}

on("lists", renderLists);

export function resetLists(): void {
  lobbyItems.clear();
  slotItems.clear();
  lobbyList.replaceChildren();
  slotList.replaceChildren();
}
