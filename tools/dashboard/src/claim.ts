// The player's page for an open slot (plan WP17.18): a server's operator holds capacity as open slots and hands out
// a claim code (or a link to this page with `?host=<url>&code=<code>`). The player opens it, sees the slot, and sets
// up their own game: their name, the map (with its size and start spots), the seats with AIs, factions and teams, and
// FAF's game settings starting from the slot's picks, plus the map's own options for adaptive maps. Claiming starts
// the game's lobby on the slot's CPUs; the page then shows every human seat's join line to copy and hand out, and
// follows the lobby every 3 s. The claim code is the credential: no admin token, no Authorization header.

import "./style.css";
import "./host.css";
import "./claim.css";
import { ApiError, ClaimApi, type ClaimLobby, type ClaimSeat, type ClaimView, type LobbySeat, type MapInfo, type SettingKey, type Settings } from "./api.ts";
import { byId, clock, faction, fill, h, icon, isNumber, type Child } from "./dom.ts";
import { countChanges, FALLBACK_OPTIONS, filterOptions, renderOptions, sameKey } from "./plane/options.ts";
import { copyButton, toast } from "./ui.ts";

const POLL_MS = 3000;
/** While the slot is open and the player fills the form: only to notice it was claimed elsewhere or went away. */
const OPEN_POLL_MS = 15000;
const REQUEST_MS = 8000;
const MAX_MAP_ITEMS = 150;
const MAX_NAME = 40;
const STORE_PLAYER = "faf-dashboard.claim-player";
const STORE_THEME = "faf-dashboard.theme";
const GAME_EXE = "main_x64.exe /init init_faf.lua";
const ENDED = new Set(["ended", "failed", "stopped"]);
const FALLBACK_AI = ["easy", "medium", "adaptive", "rush", "turtle", "tech", "random"];

function readStore(key: string): string {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function writeStore(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // private window or blocked storage: the page works without it
  }
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------- elements

const connection = byId<HTMLElement>("connection");
const connectionText = byId<HTMLElement>("connection-text");
const themeButton = byId<HTMLButtonElement>("theme");
const connectForm = byId<HTMLFormElement>("claim-connect-form");
const connectToggle = byId<HTMLButtonElement>("claim-connect-toggle");
const connectSummary = byId<HTMLElement>("claim-connect-summary");
const connectError = byId<HTMLElement>("claim-connect-error");
const hostInput = byId<HTMLInputElement>("claim-host");
const codeInput = byId<HTMLInputElement>("claim-code");
const openButton = byId<HTMLButtonElement>("claim-open");
const goneBox = byId<HTMLElement>("claim-gone");
const slotBox = byId<HTMLElement>("claim-slot");
const slotEyebrow = byId<HTMLElement>("claim-slot-eyebrow");
const slotName = byId<HTMLElement>("claim-slot-name");
const slotState = byId<HTMLElement>("claim-slot-state");
const slotTiles = byId<HTMLElement>("claim-slot-tiles");
const form = byId<HTMLFormElement>("claim-form");
const formMeta = byId<HTMLElement>("claim-form-meta");
const playerInput = byId<HTMLInputElement>("claim-player");
const mapSearch = byId<HTMLInputElement>("claim-map-search");
const mapFit = byId<HTMLInputElement>("claim-map-fit");
const mapFitText = byId<HTMLElement>("claim-map-fit-text");
const mapList = byId<HTMLElement>("claim-map-list");
const mapCount = byId<HTMLElement>("claim-map-count");
const mapSelected = byId<HTMLElement>("claim-map-selected");
const seatRows = byId<HTMLElement>("claim-seats");
const seatAdd = byId<HTMLButtonElement>("claim-seat-add");
const seatCount = byId<HTMLElement>("claim-seat-count");
const settingsBox = byId<HTMLElement>("claim-settings");
const settingsMeta = byId<HTMLElement>("claim-settings-meta");
const settingsNote = byId<HTMLElement>("claim-settings-note");
const settingsFilter = byId<HTMLInputElement>("claim-settings-filter");
const settingsReset = byId<HTMLButtonElement>("claim-settings-reset");
const submitButton = byId<HTMLButtonElement>("claim-submit");
const submitNote = byId<HTMLElement>("claim-submit-note");
const claimError = byId<HTMLElement>("claim-error");
const lobbyBox = byId<HTMLElement>("claim-lobby");

// ---------------------------------------------------------------- theme (the dashboard's, shared through storage)

type Theme = "auto" | "light" | "dark";
const THEME_NEXT: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
const THEME_LABEL: Record<Theme, string> = { auto: "automatic", light: "light", dark: "dark" };
const THEME_ICON: Record<Theme, string> = { auto: "auto", light: "sun", dark: "moon" };

function applyTheme(theme: Theme): void {
  if (theme === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  themeButton.replaceChildren(icon(THEME_ICON[theme]));
  const label = `Theme: ${THEME_LABEL[theme]} (switch to ${THEME_LABEL[THEME_NEXT[theme]]})`;
  themeButton.setAttribute("aria-label", label);
  themeButton.title = label;
  themeButton.dataset.theme = theme;
}

{
  const stored = readStore(STORE_THEME);
  applyTheme(stored === "light" || stored === "dark" ? stored : "auto");
}
themeButton.addEventListener("click", () => {
  const next = THEME_NEXT[(themeButton.dataset.theme as Theme | undefined) ?? "auto"];
  applyTheme(next);
  writeStore(STORE_THEME, next);
});

// ---------------------------------------------------------------- state

let api: ClaimApi | null = null;
let view: ClaimView | null = null;
/** This page has seen the slot's lobby: a 404 afterwards means its game is over, not a mistyped code. */
let sawLobby = false;
let lastLobby: ClaimLobby | null = null;
/** Bumped on every open: answers for an earlier code are dropped. */
let generation = 0;
let timer: number | undefined;
let polling = false;
let submitting = false;

let maps: MapInfo[] | null = null;
let mapsLoading = false;
let mapId = "";
const settingsCache = new Map<string, Settings>();
let settings: Settings | null = null;
let settingsSupported = true;
/** The player's values that differ from FAF's defaults (seeded with the slot's picks). */
const chosen = new Map<string, SettingKey>();
/** The slot's picks (the operator's defaults for games on it). */
let preset = new Map<string, SettingKey>();
/** Options whose slot pick was already put into `chosen`: a later map change doesn't undo the player's own change. */
const seeded = new Set<string>();

interface SeatDraft {
  kind: "human" | "ai";
  name: string;
  ai: string;
  faction: number;
  team: number;
}
let seats: SeatDraft[] = [];

type ConnState = "idle" | "busy" | "ok" | "bad";

function setConnection(state: ConnState, text: string, detail = text): void {
  connection.className = `pill pill-${state}`;
  connectionText.textContent = text;
  connection.title = detail;
}

function setFormOpen(open: boolean): void {
  connectForm.hidden = !open;
  connectToggle.setAttribute("aria-expanded", String(open));
  connectToggle.textContent = open ? "Hide" : "Change";
}

connectToggle.addEventListener("click", () => {
  setFormOpen(connectForm.hidden !== false);
  if (!connectForm.hidden) codeInput.focus();
});

function setConnectError(text: string): void {
  connectError.hidden = text === "";
  connectError.textContent = text;
}

// ---------------------------------------------------------------- the slot

function slot(): ClaimView["slot"] | null {
  return view?.slot ?? null;
}

function maxPlayers(): number {
  const max = slot()?.max_players;
  return isNumber(max) && max > 0 ? max : 16;
}

function slotKm(): number | null {
  const km = slot()?.km;
  return isNumber(km) && km > 0 ? km : null;
}

const SLOT_STATE: Record<string, [string, string]> = {
  open: ["Open", "info"],
  claiming: ["Being claimed", "accent"],
  claimed: ["Starting", "accent"],
  lobby: ["Lobby", "accent"],
  game: ["In game", "ok"],
  ended: ["Ended", "neutral"],
  starting: ["Starting", "info"],
  failed: ["Failed", "bad"],
  stopped: ["Stopped", "muted"],
};

function stateChip(state: string): HTMLElement {
  const [label, tone] = SLOT_STATE[state] ?? [state, "neutral"];
  return h("span", { class: `chip state-chip tone-${tone}${state === "starting" || state === "claimed" ? " spinning" : ""}` }, h("span", { class: "chip-dot", "aria-hidden": "true" }), label);
}

function tile(label: string, value: Child, sub?: string): HTMLElement {
  return h("div", { class: "tile" }, h("dt", {}, label), h("dd", {}, value), sub === undefined ? null : h("p", { class: "tile-sub dim small" }, sub));
}

function renderSlot(): void {
  const current = slot();
  if (current === null) {
    slotBox.hidden = true;
    return;
  }
  slotBox.hidden = false;
  const lobby = view?.lobby ?? null;
  slotBox.dataset.phase = lobby === null ? "" : lobby.phase === "game" ? "game" : "lobby";
  slotEyebrow.textContent = lobby === null ? "Open slot" : "Your game on this slot";
  slotName.textContent = current.name || current.id;
  slotState.replaceChildren(stateChip(lobby?.state === "starting" ? "claimed" : current.state));
  const km = slotKm();
  const cores = current.cores;
  fill(
    slotTiles,
    tile("Players", `up to ${maxPlayers()}`, "you and your friends, or AIs"),
    tile("Map size", km === null ? "any" : `up to ${km} km`, "what the slot was sized for"),
    tile("CPU", isNumber(cores) ? plural(cores, "core") : "–", "held for this game"),
    tile("Lobby open", isNumber(current.lobby_minutes) ? `${current.lobby_minutes} min` : "–", "for everyone to join"),
  );
  document.title = `${current.name || "Open slot"} · Host a game · FAF Server`;
}

// ---------------------------------------------------------------- open a code

function showGone(): void {
  window.clearTimeout(timer);
  api = null;
  const before = lastLobby;
  form.hidden = true;
  lobbyBox.hidden = true;
  slotBox.hidden = true;
  view = null;
  setConnection("bad", sawLobby ? "Game over" : "Unknown code", sawLobby ? "the claim code stopped working" : "no slot has this claim code");
  fill(
    goneBox,
    h("p", { class: "empty-title" }, sawLobby ? "This game is over" : "No open slot has this code"),
    sawLobby
      ? h(
          "p",
          { class: "dim" },
          `${before?.name ? `${before.name} has ended` : "Your game has ended"}, so its claim code no longer works: the slot opened again with a new code, or the server's operator freed it. Ask them for a new link to host another game.`,
        )
      : h("p", { class: "dim" }, "Check the code is typed right. A slot's code changes after every game hosted on it, and stops working when the server's operator frees the slot: ask them for a fresh link."),
  );
  goneBox.hidden = false;
  setFormOpen(true);
  connectSummary.textContent = "Enter a new claim code";
}

function schedule(): void {
  window.clearTimeout(timer);
  if (api === null) return;
  const lobby = view?.lobby ?? null;
  timer = window.setTimeout(() => void poll(), lobby !== null || slot()?.state !== "open" ? POLL_MS : OPEN_POLL_MS);
}

async function poll(): Promise<void> {
  const current = api;
  if (current === null || polling) return;
  const gen = generation;
  polling = true;
  try {
    const next = await current.view(AbortSignal.timeout(REQUEST_MS));
    if (gen !== generation) return;
    setConnection("ok", "Connected", `connected to ${current.base}`);
    useView(next);
  } catch (error) {
    if (gen !== generation) return;
    if (error instanceof ApiError && error.status === 404) {
      showGone();
      return;
    }
    setConnection("bad", "No answer", `no answer from ${current.base}: ${message(error)}`);
  } finally {
    polling = false;
    // showGone drops the code (api null): nothing more to follow.
    if (gen === generation && api === current) schedule();
  }
}

/** Shows what the host said about the code: the slot, then the form while it is open, or the lobby once claimed. */
function useView(next: ClaimView): void {
  const wasOpen = view !== null && view.lobby === null && view.slot.state === "open";
  const presetChanged = JSON.stringify(view?.slot.options ?? {}) !== JSON.stringify(next.slot.options ?? {});
  view = next;
  goneBox.hidden = true;
  renderSlot();
  if (next.lobby !== null) {
    if (!sawLobby && wasOpen && !submitting) toast("info", "The slot was claimed", "Someone with this code set up the game meanwhile; its lobby is shown below.");
    sawLobby = true;
    lastLobby = next.lobby;
    form.hidden = true;
    renderLobby(next.lobby);
    return;
  }
  lobbyBox.hidden = true;
  if (next.slot.state === "open") {
    if (presetChanged) {
      preset = new Map(Object.entries(next.slot.options ?? {}));
      if (settings !== null) useSettings(settings);
    }
    if (form.hidden) showForm();
  } else {
    form.hidden = true;
    fill(goneBox, h("p", { class: "dim" }, next.slot.state === "ended" ? "This slot has ended: its operator made it for one game, and that game is over." : "The slot is being set up by whoever claimed it; its lobby shows here in a moment."));
    goneBox.hidden = false;
  }
}

async function open(): Promise<void> {
  const host = hostInput.value.trim();
  const code = codeInput.value.trim();
  if (!/^https?:\/\/.+/.test(host)) {
    setConnectError("The server address starts with http:// or https://.");
    hostInput.focus();
    return;
  }
  if (code === "") {
    setConnectError("Enter the claim code.");
    codeInput.focus();
    return;
  }
  setConnectError("");
  window.clearTimeout(timer);
  const gen = ++generation;
  const current = new ClaimApi(host, code);
  api = current;
  view = null;
  sawLobby = false;
  lastLobby = null;
  resetForm();
  goneBox.hidden = true;
  lobbyBox.hidden = true;
  form.hidden = true;
  slotBox.hidden = true;
  try {
    const url = new URL(window.location.href);
    url.search = new URLSearchParams({ host: current.base, code: current.code }).toString();
    window.history.replaceState(null, "", url);
  } catch {
    // a page opened from a file: the address bar stays as it is
  }
  openButton.disabled = true;
  openButton.classList.add("busy");
  setConnection("busy", "Opening…", `asking ${current.base} about the code`);
  try {
    const next = await current.view(AbortSignal.timeout(REQUEST_MS));
    if (gen !== generation) return;
    setConnection("ok", "Connected", `connected to ${current.base}`);
    connectSummary.textContent = `Code ${current.code} on ${current.base.replace(/^https?:\/\//, "")}`;
    connectToggle.hidden = false;
    setFormOpen(false);
    useView(next);
    schedule();
  } catch (error) {
    if (gen !== generation) return;
    if (error instanceof ApiError && error.status === 404) {
      showGone();
    } else {
      const why =
        error instanceof DOMException && error.name === "TimeoutError"
          ? `No answer from ${current.base} within ${REQUEST_MS / 1000} s.`
          : error instanceof ApiError
            ? error.message
            : `No answer from ${current.base}: check the address, and that this page's address is the one the server allows (its --cors-origin).`;
      setConnection("bad", "No answer", why);
      setConnectError(why);
      api = null;
    }
  } finally {
    if (gen === generation) {
      openButton.disabled = false;
      openButton.classList.remove("busy");
    }
  }
}

connectForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void open();
});

// ---------------------------------------------------------------- the form

function resetForm(): void {
  maps = null;
  mapsLoading = false;
  mapId = "";
  settingsCache.clear();
  settings = null;
  settingsSupported = true;
  chosen.clear();
  preset = new Map();
  seeded.clear();
  seats = [];
  settingsBox.replaceChildren();
  mapList.replaceChildren();
  claimError.hidden = true;
}

function showForm(): void {
  const current = slot();
  if (current === null) return;
  preset = new Map(Object.entries(current.options ?? {}));
  if (seats.length === 0) seats = [newSeat(0, "human"), ...(maxPlayers() >= 2 ? [newSeat(1, "ai")] : [])];
  if (playerInput.value.trim() === "") playerInput.value = readStore(STORE_PLAYER);
  const km = slotKm();
  mapFitText.textContent = km === null ? "Only maps with enough start spots" : `Only maps up to ${km} km with enough start spots`;
  formMeta.textContent = `up to ${plural(maxPlayers(), "player")}`;
  form.hidden = false;
  renderSeats();
  renderSubmit();
  void loadMaps();
  void loadSettings();
}

playerInput.addEventListener("input", () => {
  renderSeats();
  renderSubmit();
});

// ---------------------------------------------------------------- maps

function selectedMap(): MapInfo | undefined {
  return maps?.find((map) => map.id === mapId);
}

/** Why a map doesn't suit the game as set up: too few start spots, or larger than the slot was sized for. */
function mapProblems(map: MapInfo): { spots: boolean; size: boolean } {
  const km = slotKm();
  return {
    spots: isNumber(map.players) && map.players < seats.length,
    size: km !== null && isNumber(map.km) && map.km > km,
  };
}

function fits(map: MapInfo): boolean {
  const problems = mapProblems(map);
  return !problems.spots && !problems.size;
}

async function loadMaps(): Promise<void> {
  const current = api;
  if (current === null || mapsLoading || maps !== null) return;
  const gen = generation;
  mapsLoading = true;
  mapList.replaceChildren(h("p", { class: "empty" }, "Loading the server's maps…"));
  try {
    const list = await current.maps(AbortSignal.timeout(REQUEST_MS * 2));
    if (gen !== generation) return;
    maps = list;
    if (mapId === "" && list.length > 0) {
      const pick = list.find((map) => fits(map) && isNumber(map.players) && map.players >= Math.max(2, seats.length)) ?? list.find(fits) ?? list[0];
      if (pick !== undefined) mapId = pick.id;
    }
    renderMaps();
    onMapChanged();
  } catch (error) {
    if (gen !== generation) return;
    if (error instanceof ApiError && error.status === 404) {
      showGone();
      return;
    }
    const retry = h("button", { type: "button", class: "btn small" }, "Try again");
    retry.addEventListener("click", () => void loadMaps());
    mapList.replaceChildren(h("div", { class: "empty" }, h("p", {}, `The server's maps didn't load: ${message(error)}`), retry));
  } finally {
    if (gen === generation) mapsLoading = false;
  }
}

function renderMaps(): void {
  if (maps === null) return;
  const query = mapSearch.value.trim().toLowerCase();
  const matching = maps.filter((map) => (query === "" || `${map.name ?? ""} ${map.id}`.toLowerCase().includes(query)) && (!mapFit.checked || fits(map)));
  const shown = matching.slice(0, MAX_MAP_ITEMS);
  const current = selectedMap();
  if (current !== undefined && !shown.includes(current)) shown.unshift(current);
  mapCount.textContent = matching.length === maps.length ? plural(maps.length, "map") : `${matching.length} of ${plural(maps.length, "map")}`;
  if (shown.length === 0) {
    mapList.replaceChildren(h("p", { class: "empty" }, mapFit.checked ? "No map fits: untick “Only maps that fit”, or search for another." : "No map matches the search."));
    return;
  }
  mapList.replaceChildren(
    ...shown.map((map) => {
      const radio = h("input", { type: "radio", name: "claim-map", value: map.id, class: "sr-only" });
      radio.checked = map.id === mapId;
      radio.addEventListener("change", () => {
        if (!radio.checked) return;
        mapId = map.id;
        for (const item of mapList.querySelectorAll(".map-item")) item.classList.toggle("selected", item.contains(radio));
        onMapChanged();
      });
      const problems = mapProblems(map);
      const source = map.source === "vault" ? "Vault" : map.source === "fa" ? "FA" : (map.source ?? "");
      return h(
        "label",
        { class: `map-item${map.id === mapId ? " selected" : ""}${problems.spots || problems.size ? " misfit" : ""}` },
        radio,
        h("span", { class: "map-thumb", "aria-hidden": "true" }, isNumber(map.km) ? `${map.km}` : "?"),
        h("span", { class: "map-text" }, h("span", { class: "map-name" }, map.name ?? map.id), h("span", { class: "map-id" }, map.id)),
        h(
          "span",
          { class: "map-meta" },
          h("span", { class: problems.size ? "tone-warn misfit-text" : "" }, isNumber(map.km) ? `${map.km} km` : "– km"),
          h("span", { class: problems.spots ? "tone-warn misfit-text" : "" }, isNumber(map.players) ? plural(map.players, "spot") : "– spots"),
          source === "" ? null : h("span", { class: `source source-${map.source ?? "other"}` }, source),
        ),
      );
    }),
    matching.length > MAX_MAP_ITEMS ? h("p", { class: "dim small map-more" }, `Showing ${MAX_MAP_ITEMS} of ${matching.length}; search to narrow it.`) : "",
  );
}

mapSearch.addEventListener("input", renderMaps);
mapFit.addEventListener("change", renderMaps);

function mapWarnings(map: MapInfo): HTMLElement | null {
  const problems = mapProblems(map);
  const km = slotKm();
  const lines: string[] = [];
  if (problems.spots) lines.push(`${map.name ?? map.id} has ${plural(map.players ?? 0, "start spot")} for ${plural(seats.length, "seat")}: remove seats or pick a larger map.`);
  if (problems.size) lines.push(`${map.name ?? map.id} is ${map.km} km, larger than the ${km} km this slot was sized for: the game may run slow.`);
  if (lines.length === 0) return null;
  return h("ul", { class: "warnings" }, ...lines.map((line) => h("li", { class: "warning tone-warn" }, icon("warn", "icon tiny"), h("div", { class: "warning-text" }, h("span", {}, line)))));
}

function renderSelectedMap(): void {
  const map = selectedMap();
  if (map === undefined) {
    mapSelected.replaceChildren(h("span", { class: "dim" }, maps === null ? "" : "No map picked yet."));
    return;
  }
  fill(
    mapSelected,
    h("strong", {}, map.name ?? map.id),
    h("span", { class: "dim" }, ` · ${isNumber(map.km) ? `${map.km} km` : "size unknown"} · ${isNumber(map.players) ? plural(map.players, "start spot") : "? start spots"}`),
    map.description ? h("p", { class: "map-description" }, map.description) : null,
    mapWarnings(map),
  );
}

function onMapChanged(): void {
  renderSelectedMap();
  renderSubmit();
  void loadSettings();
}

// ---------------------------------------------------------------- settings

async function loadSettings(): Promise<void> {
  const current = api;
  if (current === null) return;
  const key = mapId;
  const cached = settingsCache.get(key);
  if (cached !== undefined) {
    useSettings(cached);
    return;
  }
  if (!settingsSupported) {
    useSettings({ options: FALLBACK_OPTIONS, ai: [], map_options: [] });
    return;
  }
  const gen = generation;
  settingsMeta.textContent = "loading…";
  try {
    let answer: Settings;
    try {
      answer = await current.settings(key === "" ? undefined : key, AbortSignal.timeout(REQUEST_MS));
    } catch (error) {
      // A map the settings don't know: its own options are left out, the game's are still there.
      if (!(error instanceof ApiError && error.status === 404 && key !== "" && /no map/i.test(error.message))) throw error;
      answer = await current.settings(undefined, AbortSignal.timeout(REQUEST_MS));
    }
    if (gen !== generation) return;
    settingsCache.set(key, answer);
    if (key === mapId) useSettings(answer);
  } catch (error) {
    if (gen !== generation) return;
    if (error instanceof ApiError && error.status === 404) {
      if (/claim code/i.test(error.message)) {
        showGone();
        return;
      }
      settingsSupported = false;
      useSettings({ options: FALLBACK_OPTIONS, ai: [], map_options: [] });
      return;
    }
    settingsMeta.textContent = "";
    fill(settingsBox, h("p", { class: "empty" }, `The settings didn't load: ${message(error)}. The game uses the slot's picks and FAF's defaults.`));
  }
}

function useSettings(next: Settings): void {
  settings = next;
  // The slot's picks are the starting values, once each: what the player changed afterwards stays theirs.
  for (const option of [...next.options, ...next.map_options]) {
    const value = preset.get(option.key);
    if (value === undefined || seeded.has(option.key)) continue;
    seeded.add(option.key);
    if (option.values.some((candidate) => sameKey(candidate.key, value)) && !sameKey(value, option.default)) chosen.set(option.key, value);
  }
  // Only values these settings can't show go. Another map's options stay chosen while this map lacks them, so going
  // back to that map keeps the player's (or the slot's) pick; claimOptions sends only the shown map's.
  for (const option of [...next.options, ...next.map_options]) {
    const value = chosen.get(option.key);
    if (value !== undefined && !option.values.some((candidate) => sameKey(candidate.key, value))) chosen.delete(option.key);
  }
  settingsNote.hidden = settingsSupported;
  renderSettings();
  renderSeats();
}

function renderSettings(): void {
  if (settings === null) return;
  renderOptions(settingsBox, settings, selectedMap()?.name ?? "this map", { chosen, preset, presetLabel: "slot", onChange: renderSettingsCounts });
  renderSettingsCounts();
  filterOptions(settingsBox, settingsFilter.value);
}

function renderSettingsCounts(): void {
  const total = countChanges(settingsBox);
  const count = (settings?.options.length ?? 0) + (settings?.map_options.length ?? 0);
  settingsMeta.textContent = total === 0 ? `${count} settings, all default` : `${count} settings · ${total} not default`;
  settingsReset.hidden = total === 0;
}

settingsFilter.addEventListener("input", () => filterOptions(settingsBox, settingsFilter.value));
settingsReset.addEventListener("click", () => {
  chosen.clear();
  renderSettings();
});

/**
 * The options the claim sends: every value the player has that isn't FAF's default, and every slot pick (also one
 * put back to the default, which has to be sent, or the slot's value would win).
 */
function claimOptions(): Record<string, SettingKey> {
  const out: Record<string, SettingKey> = {};
  const all = settings === null ? [] : [...settings.options, ...settings.map_options];
  for (const option of all) {
    const value = chosen.get(option.key);
    if (value !== undefined) out[option.key] = value;
    else if (preset.has(option.key) && option.default !== null && option.default !== undefined) out[option.key] = option.default;
  }
  return out;
}

// ---------------------------------------------------------------- seats

const FACTIONS: [number, string][] = [
  [1, "UEF"],
  [2, "Aeon"],
  [3, "Cybran"],
  [4, "Seraphim"],
  [5, "Random"],
];
const TEAMS: [string, string][] = [["1", "No team"], ...[1, 2, 3, 4, 5, 6, 7, 8].map((t): [string, string] => [String(t + 1), `Team ${t}`])];

function aiChoices(): [string, string][] {
  const catalog = settings?.ai ?? [];
  if (catalog.length > 0) return catalog.map((ai): [string, string] => [ai.key, `${ai.name ?? ai.key}${isNumber(ai.rating) && ai.rating > 0 ? ` · ${ai.rating}` : ""}`]);
  return FALLBACK_AI.map((name): [string, string] => [name, name]);
}

function newSeat(index: number, kind: "human" | "ai"): SeatDraft {
  const ai = aiChoices().map(([key]) => key);
  return { kind, name: "", ai: ai.includes("adaptive") ? "adaptive" : (ai[0] ?? "adaptive"), faction: 5, team: 2 + (index % 2) };
}

function selectField(id: string, label: string, choices: [string, string][], value: string, onChange: (value: string) => void): HTMLElement {
  const node = h("select", { id }, ...choices.map(([choice, text]) => h("option", { value: choice }, text)));
  node.value = choices.some(([choice]) => choice === value) ? value : (choices[0]?.[0] ?? "");
  node.addEventListener("change", () => onChange(node.value));
  return h("div", { class: "field" }, h("label", { for: id }, label), node);
}

function seatsChanged(): void {
  renderSeats();
  renderMaps();
  renderSelectedMap();
  renderSubmit();
}

function renderSeats(): void {
  const ais = aiChoices();
  const limit = maxPlayers();
  const player = playerInput.value.trim();
  seatRows.replaceChildren(
    ...seats.map((seat, index) => {
      const n = index + 1;
      if (seat.kind === "ai" && !ais.some(([key]) => key === seat.ai)) seat.ai = ais[0]?.[0] ?? seat.ai;
      const host = index === 0;
      const who: HTMLElement[] = [];
      if (host) {
        who.push(
          h("div", { class: "field" }, h("span", { class: "field-label" }, "Kind"), h("span", { class: "fixed-value" }, "Human")),
          h("div", { class: "field grow" }, h("span", { class: "field-label" }, "Name"), h("span", { class: `fixed-value${player === "" ? " dim" : ""}` }, player === "" ? "your name, above" : player)),
        );
      } else {
        who.push(
          selectField(`claim-seat-${n}-kind`, "Kind", [["human", "Human"], ["ai", "AI"]], seat.kind, (value) => {
            seat.kind = value === "ai" ? "ai" : "human";
            renderSeats();
          }),
        );
        if (seat.kind === "human") {
          const name = h("input", { id: `claim-seat-${n}-name`, maxlength: MAX_NAME, placeholder: `Player ${n}`, spellcheck: "false", autocomplete: "off" });
          name.value = seat.name;
          name.addEventListener("input", () => (seat.name = name.value));
          who.push(h("div", { class: "field grow" }, h("label", { for: `claim-seat-${n}-name` }, "Name ", h("span", { class: "dim" }, "(optional)")), name));
        } else {
          const personality = selectField(`claim-seat-${n}-ai`, "AI", ais, seat.ai, (value) => (seat.ai = value));
          personality.classList.add("grow");
          who.push(personality);
        }
      }
      const remove = h("button", { type: "button", class: "btn ghost small seat-remove", "aria-label": `Remove seat ${n}`, title: "Remove this seat" }, icon("trash", "icon tiny"));
      remove.hidden = host;
      remove.addEventListener("click", () => {
        seats.splice(index, 1);
        seatsChanged();
        (document.getElementById(`claim-seat-${Math.min(n, seats.length)}-kind`) ?? seatAdd).focus();
      });
      return h(
        "fieldset",
        { class: `seat-row kind-${seat.kind}${host ? " host-seat" : ""}` },
        h("legend", {}, `Seat ${n}`, h("span", { class: "dim" }, host ? " · you, the host" : ` · start spot ${n}`)),
        h(
          "div",
          { class: "seat-fields" },
          ...who,
          selectField(`claim-seat-${n}-faction`, "Faction", FACTIONS.map(([value, label]): [string, string] => [String(value), label]), String(seat.faction), (value) => (seat.faction = Number(value))),
          selectField(`claim-seat-${n}-team`, "Team", TEAMS, String(seat.team), (value) => (seat.team = Number(value))),
        ),
        remove,
      );
    }),
  );
  seatCount.textContent = `${seats.length} of ${limit}`;
  seatAdd.disabled = seats.length >= limit;
}

seatAdd.addEventListener("click", () => {
  if (seats.length >= maxPlayers()) return;
  // Seat 1 is always the host, a human; the ones added after it start as AIs.
  seats.push(newSeat(seats.length, seats.length === 0 ? "human" : "ai"));
  seatsChanged();
  document.getElementById(`claim-seat-${seats.length}-kind`)?.focus();
});

// ---------------------------------------------------------------- submit

/** What keeps the claim from being sent, or "" when it can go. */
function blocker(): string {
  const player = playerInput.value.trim();
  if (player === "") return "Enter your name.";
  if (player.length > MAX_NAME) return `Your name is longer than ${MAX_NAME} characters.`;
  const map = selectedMap();
  if (map === undefined) return maps === null ? "Loading the maps…" : "Pick a map.";
  if (seats.length > maxPlayers()) return `This slot takes up to ${plural(maxPlayers(), "player")}.`;
  if (mapProblems(map).spots) return `${map.name ?? map.id} has ${plural(map.players ?? 0, "start spot")}: remove seats or pick another map.`;
  return "";
}

function renderSubmit(): void {
  const why = blocker();
  submitButton.disabled = submitting || why !== "";
  submitNote.textContent = submitting ? "Setting up your game…" : why;
}

function showClaimError(text: string): void {
  claimError.hidden = text === "";
  claimError.textContent = text;
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void submit();
});

async function submit(): Promise<void> {
  const current = api;
  if (current === null || submitting) return;
  const why = blocker();
  if (why !== "") {
    showClaimError(why);
    return;
  }
  const map = selectedMap();
  if (map === undefined) return;
  const player = playerInput.value.trim();
  const body: ClaimSeat[] = seats.map((seat, index): ClaimSeat => {
    if (index === 0) return { kind: "human", name: player, faction: seat.faction, team: seat.team };
    if (seat.kind === "ai") return { kind: "ai", ai: seat.ai, faction: seat.faction, team: seat.team };
    const name = seat.name.trim();
    return name === "" ? { kind: "human", faction: seat.faction, team: seat.team } : { kind: "human", name, faction: seat.faction, team: seat.team };
  });
  const gen = generation;
  submitting = true;
  showClaimError("");
  submitButton.classList.add("busy");
  renderSubmit();
  writeStore(STORE_PLAYER, player);
  try {
    const next = await current.claim({ player, map: map.id, seats: body, options: claimOptions(), start_when_ready: 0 });
    if (gen !== generation) return;
    sawLobby = true;
    toast("ok", "Your game is set up", "Start the game with your join line; hand the others theirs.");
    useView(next);
    schedule();
    lobbyBox.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    if (gen !== generation) return;
    if (error instanceof ApiError && error.status === 404) {
      showGone();
    } else if (error instanceof ApiError && error.status === 409) {
      // Already claimed (by this player in another tab, or by someone else with the code): show its lobby if it has one.
      let shown = false;
      try {
        const now = await current.view(AbortSignal.timeout(REQUEST_MS));
        if (gen !== generation) return;
        if (now.lobby !== null) {
          sawLobby = true;
          useView(now);
          schedule();
          toast("info", "This slot is already claimed", "Its game is shown below.");
          shown = true;
        }
      } catch {
        // the refusal's own text is shown below
      }
      if (!shown) showClaimError(`The server refused the claim: ${error.message}`);
    } else if (error instanceof ApiError) {
      showClaimError(error.status === 400 ? `The server didn't accept the game: ${error.message}` : `The server refused the claim (HTTP ${error.status}): ${error.message}`);
    } else {
      showClaimError(`No answer from the server: ${message(error)}`);
    }
  } finally {
    if (gen === generation) {
      submitting = false;
      submitButton.classList.remove("busy");
      renderSubmit();
    }
  }
}

// ---------------------------------------------------------------- the lobby

const LOBBY_PHRASE: Record<string, string> = {
  starting: "is starting",
  lobby: "is open",
  game: "is in game",
  ended: "has ended",
  failed: "failed",
  stopped: "was stopped",
};

function seatLine(seat: LobbySeat, host: boolean): HTMLElement {
  const name = seat.name || (seat.kind === "ai" ? `AI: ${seat.ai ?? "?"}` : `Seat ${seat.seat}`);
  const side = [faction(seat.faction)?.name ?? "", isNumber(seat.team) ? (seat.team <= 1 ? "no team" : `team ${seat.team - 1}`) : ""].filter((part) => part !== "").join(" · ");
  const command = seat.kind === "human" && typeof seat.join === "string" && seat.join !== "" ? seat.join : null;
  return h(
    "li",
    { class: `join-row claim-seat kind-${seat.kind}${host ? " host" : ""}` },
    h(
      "div",
      { class: "join-who" },
      h("strong", {}, name),
      host ? h("span", { class: "chip tiny tone-accent" }, "you") : null,
      h("span", { class: "dim" }, ` · seat ${seat.seat}${side === "" ? "" : ` · ${side}`}`),
      seat.kind === "human" && !host ? h("span", { class: "dim" }, " · hand this line to the friend who plays here") : null,
    ),
    seat.kind === "ai"
      ? h("p", { class: "dim small ai-line" }, "An AI plays here: nobody joins this seat.")
      : h(
          "div",
          { class: "join-cmd" },
          h("code", { class: "cmd" }, command ?? "not given out yet"),
          command === null ? null : copyButton(command, `Copy the join switches for ${name}`),
          command === null ? null : copyButton(`${GAME_EXE} ${command}`, `Copy the whole start command for ${name}`, "Command"),
        ),
  );
}

function renderLobby(lobby: ClaimLobby): void {
  const seatsList = lobby.seats ?? [];
  const signature = JSON.stringify([lobby.state, lobby.phase, lobby.name, lobby.map, seatsList, lobby.phase === "game" ? Math.floor((lobby.beat ?? 0) / 10) : 0]);
  lobbyBox.hidden = false;
  if (lobbyBox.dataset.signature === signature) return;
  lobbyBox.dataset.signature = signature;
  const ended = ENDED.has(lobby.state);
  const map = lobby.map;
  const humans = seatsList.filter((seat) => seat.kind === "human").length;
  const minutes = slot()?.lobby_minutes;
  fill(
    lobbyBox,
    h(
      "div",
      { class: "created-head" },
      h("span", { class: `created-icon${ended ? " ended" : ""}` }, icon(ended ? "stop" : "check")),
      h(
        "div",
        {},
        h("strong", {}, `${lobby.name || "Your game"} ${LOBBY_PHRASE[lobby.state] ?? `is ${lobby.state}`}`),
        h(
          "span",
          { class: "dim" },
          ` · ${map?.name ?? map?.id ?? "map ?"}${isNumber(map?.km) ? ` · ${map.km} km` : ""} · ${plural(humans, "player")}${seatsList.length > humans ? ` + ${plural(seatsList.length - humans, "AI", "AIs")}` : ""}`,
        ),
      ),
      h("div", { class: "lobby-state" }, stateChip(lobby.state), lobby.phase === "game" && isNumber(lobby.beat) ? h("span", { class: "use-clock" }, clock(lobby.beat)) : null),
    ),
    ended
      ? h("p", { class: "form-error" }, "The game's server has stopped: these join lines no longer work.")
      : h(
          "div",
          { class: "claim-steps" },
          h(
            "ol",
            {},
            h("li", {}, "Start the game (our engine) with ", h("strong", {}, "your"), " join line: you host this game."),
            h("li", {}, "Hand every other human seat its own line; each friend starts the game with theirs."),
            h("li", {}, "In your game's lobby screen you can still change the game options, ", h("strong", {}, "not the map"), ". Press Launch once everyone is in."),
          ),
          h("p", { class: "dim small" }, "Start command: ", h("code", { class: "inline-code" }, `${GAME_EXE} <join line>`), isNumber(minutes) ? `. The lobby stays open ${minutes} min for everyone to join.` : "."),
        ),
    h("ul", { class: "join-list claim-seats" }, ...seatsList.map((seat, index) => seatLine(seat, index === 0 || seat.seat === 1))),
  );
}

// ---------------------------------------------------------------- start

{
  const params = new URLSearchParams(window.location.search);
  const host = params.get("host") ?? "";
  const code = params.get("code") ?? "";
  hostInput.value = host;
  codeInput.value = code;
  playerInput.value = readStore(STORE_PLAYER);
  if (host !== "" && code !== "") void open();
  else (host === "" ? hostInput : codeInput).focus();
}
