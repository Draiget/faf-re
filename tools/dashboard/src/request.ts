// The public request page (request.html?host=<host url>): a player asks the server for a game of their own. The form:
// their name (and the access code when the server asks for one), the map from a gallery of previews, the map's start
// spots with who plays where (spot 1 is the player, who hosts; friends, AIs), and the game settings starting from the
// server's defaults. Then the request's live state: its place in the queue, starting, the lobby with every player's
// join line, the game, or why it was refused. The request's key (its credential) is kept in this browser, so a reload
// follows it again. The public API only; no admin token.

import "./style.css";
import "./app.css";
import { ApiError, RequestApi, type GameRequest, type MapInfo, type PublicPool, type SettingKey, type Settings } from "./api.ts";
import { byId, clock, h, icon, isNumber } from "./dom.ts";
import { MapGallery, MapPreview, mapArt, mapFacts, spotsOf } from "./maps.ts";
import { countChanges, filterOptions, pruneChosen, renderOptions, sameKey } from "./plane/options.ts";
import { joinBlock } from "./plane/parts.ts";
import { SlotsEditor } from "./slots.ts";
import { confirmAction, toast } from "./ui.ts";

const STORE_KEY = "faf-request.current";
const STORE_NAME = "faf-request.player";
const STORE_THEME = "faf-dashboard.theme";
const FOLLOW_MS = 3000;

const main = byId<HTMLElement>("main");
const hostLine = byId<HTMLElement>("host-line");
const poolPill = byId<HTMLElement>("pool-pill");
const poolText = byId<HTMLElement>("pool-text");
const themeButton = byId<HTMLButtonElement>("theme");

function readStore(key: string): string {
  try {
    return localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function writeStore(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // private window or blocked storage: the page works without it
  }
}

// ---------------------------------------------------------------- theme (shared with the dashboard)

type Theme = "auto" | "light" | "dark";
const THEME_NEXT: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
function applyTheme(theme: Theme): void {
  if (theme === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  themeButton.replaceChildren(icon(theme === "auto" ? "auto" : theme === "light" ? "sun" : "moon"));
  themeButton.dataset.theme = theme;
  themeButton.title = `Theme: ${theme === "auto" ? "automatic" : theme}`;
  themeButton.setAttribute("aria-label", themeButton.title);
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

// ---------------------------------------------------------------- the host

/** The server's address: `?host=`, else the dev server's default, else this page's own origin. */
function hostBase(): string {
  const fromQuery = new URLSearchParams(location.search).get("host")?.trim() ?? "";
  if (fromQuery !== "") return fromQuery;
  const fromEnv = (import.meta.env.VITE_HOST_URL ?? "").trim();
  return fromEnv !== "" ? fromEnv : location.origin;
}

const api = new RequestApi(hostBase());
hostLine.textContent = api.base.replace(/^https?:\/\//, "");

function setPill(tone: "ok" | "bad" | "idle" | "busy", text: string): void {
  poolPill.className = `pill pill-${tone}`;
  poolText.textContent = text;
}

// ---------------------------------------------------------------- following a request

interface Followed {
  host: string;
  id: string;
  key: string;
  /** What was asked for, to show beside its state: the map and a line about the seats. */
  map?: string;
  summary?: string;
}

function followed(): Followed | null {
  try {
    const value = JSON.parse(readStore(STORE_KEY)) as Partial<Followed>;
    if (value.host === api.base && typeof value.id === "string" && typeof value.key === "string") return { host: value.host, id: value.id, key: value.key, map: value.map, summary: value.summary };
  } catch {
    // nothing stored
  }
  return null;
}

let followTimer: number | undefined;

const STATE_TEXT: Record<string, [string, string, string]> = {
  queued: ["Waiting in the queue", "warn", "Every game place is taken: yours starts by itself when one is free. Keep this page open, or come back to it."],
  starting: ["Starting your server", "info", "The server is starting your lobby; the join lines come in a moment."],
  lobby: ["Your lobby is open", "ok", "Start the game with your join line and launch it from your lobby screen. Hand the other lines to your friends."],
  game: ["In game", "ok", "Have a good game."],
  ended: ["The game has ended", "neutral", "Thanks for playing."],
  refused: ["Not taken", "bad", ""],
  cancelled: ["Cancelled", "neutral", ""],
};

function renderRequest(request: GameRequest, follow: Followed): void {
  const [title, tone, text] = STATE_TEXT[request.state] ?? [request.state, "neutral", ""];
  const live = ["queued", "starting", "lobby"].includes(request.state);
  const cancel = h("button", { type: "button", class: "btn danger" }, "Cancel my request…");
  cancel.addEventListener("click", () => void cancelRequest(follow, cancel));
  const again = h("button", { type: "button", class: "btn primary" }, icon("plus", "icon"), "Ask for another game");
  again.addEventListener("click", () => {
    writeStore(STORE_KEY, null);
    void showForm();
  });
  const lobby = request.lobby ?? null;
  setPill(tone === "bad" ? "bad" : live ? "busy" : "ok", title);
  main.replaceChildren(
    h(
      "div",
      { class: "request-state-wrap" },
      h(
        "section",
        { class: `card request-state tone-${tone}` },
        h("p", { class: "eyebrow" }, `Request ${request.id}${typeof request.player === "string" ? ` · ${request.player}` : ""}`),
        follow.summary === undefined ? null : h("div", { class: "asked" }, askedArt(follow.map), h("span", {}, h("span", { class: "dim small" }, "You asked for "), h("b", {}, follow.summary))),
        h("h1", { class: "state-title" }, request.state === "queued" || request.state === "starting" ? h("span", { class: "spinner", "aria-hidden": "true" }) : null, title),
        request.state === "queued" && isNumber(request.position) ? h("p", { class: "queue-position" }, h("span", { class: "big-number" }, `#${request.position}`), h("span", { class: "dim" }, request.position === 1 ? " next in the queue" : ` in the queue: ${request.position - 1} ${request.position === 2 ? "game" : "games"} before yours`)) : null,
        text === "" ? null : h("p", {}, text),
        request.reason ? h("p", { class: "form-error" }, request.reason) : null,
        lobby === null
          ? null
          : h(
              "div",
              { class: "request-lobby" },
              h("h2", {}, lobby.name ?? "Your lobby", h("span", { class: "dim small" }, ` · ${lobby.map?.name ?? lobby.map?.id ?? ""}${isNumber(lobby.map?.km) ? ` · ${lobby.map.km} km` : ""}${lobby.phase === "game" && isNumber(lobby.beat) ? ` · ${clock(lobby.beat)}` : ""}`)),
              joinBlock(lobby),
              h("p", { class: "dim small" }, "The game is our engine: start it with ", h("code", { class: "inline-code" }, "main_x64.exe /init init_faf.lua"), " and the join line."),
            ),
        h("div", { class: "request-actions" }, live ? cancel : null, live ? null : again),
        live ? h("p", { class: "dim small" }, "This page follows your request every few seconds.") : null,
      ),
    ),
  );
  document.title = `${title} · FAF`;
}

function askedArt(id: string | undefined): HTMLElement | null {
  const map = maps.find((item) => item.id === id);
  if (map === undefined) return null;
  const art = mapArt(map, previewSource, true);
  art.classList.add("tiny");
  return art;
}

async function follow(state: Followed): Promise<void> {
  window.clearTimeout(followTimer);
  try {
    const request = await api.get(state.id, state.key, AbortSignal.timeout(8000));
    renderRequest(request, state);
    if (["queued", "starting", "lobby", "game"].includes(request.state)) followTimer = window.setTimeout(() => void follow(state), FOLLOW_MS);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      writeStore(STORE_KEY, null);
      toast("info", "That request is gone", "The server no longer knows it (it may have restarted). Ask again.");
      void showForm();
      return;
    }
    setPill("bad", "No answer");
    followTimer = window.setTimeout(() => void follow(state), FOLLOW_MS * 2);
  }
}

async function cancelRequest(state: Followed, button: HTMLButtonElement): Promise<void> {
  if (!(await confirmAction("Cancel your request?", "Your place in the queue, or your lobby, is given up.", "Cancel it"))) return;
  button.disabled = true;
  try {
    const request = await api.cancel(state.id, state.key);
    renderRequest(request, state);
  } catch (error) {
    toast("bad", "Couldn't cancel it", error instanceof Error ? error.message : String(error));
    button.disabled = false;
  }
}

// ---------------------------------------------------------------- the form

let pool: PublicPool | null = null;
let maps: MapInfo[] = [];
let mapId = "";
const settingsCache = new Map<string, Settings>();
let settings: Settings | null = null;
const chosen = new Map<string, SettingKey>();
let sending = false;

const previewSource = (map: MapInfo): Promise<string | null> => Promise.resolve(api.previewUrl(map));

const nameInput = h("input", { id: "req-name", maxlength: 40, autocomplete: "nickname", spellcheck: "false", placeholder: "Your FAF name" });
nameInput.value = readStore(STORE_NAME);
const codeInput = h("input", { id: "req-code", autocomplete: "off", spellcheck: "false", placeholder: "From the server's organiser" });
const codeField = h("div", { class: "field" }, h("label", { for: "req-code" }, "Access code"), codeInput);
const slots = new SlotsEditor({
  ais: () => {
    const catalog = settings?.ai ?? [];
    return catalog.length > 0 ? catalog.map((ai): [string, string] => [ai.key, ai.name ?? ai.key]) : [["adaptive", "AI: Adaptive"]];
  },
  hostName: () => nameInput.value.trim(),
  maxSeats: () => pool?.max_players ?? 16,
  onChange: () => renderPicked(),
});
const preview = new MapPreview(previewSource, (spot) => slots.focusSpot(spot));
const gallery = new MapGallery({ source: previewSource, onSelect: (map) => selectMap(map.id), minSpots: () => Math.max(1, slots.filled()) });
const settingsBox = h("div", { class: "settings-form wide" });
const settingsMeta = h("span", { class: "dim small" });
const settingsFilter = h("input", { type: "search", placeholder: "Filter settings", spellcheck: "false", "aria-label": "Filter settings" });
settingsFilter.addEventListener("input", () => filterOptions(settingsBox, settingsFilter.value));
const submit = h("button", { type: "submit", class: "btn primary big" }, icon("rocket", "icon"), "Ask for a server");
const submitNote = h("p", { class: "dim small" });
const queueLine = h("p", { class: "queue-line" });
nameInput.addEventListener("input", () => {
  slots.render();
  renderPicked();
});

const form = h(
  "form",
  { class: "request-form", novalidate: true },
  h(
    "div",
    { class: "request-col" },
    h("section", { class: "card" }, h("h2", {}, "You"), h("div", { class: "form-grid" }, h("div", { class: "field" }, h("label", { for: "req-name" }, "Your name ", h("span", { class: "dim" }, "(you host the game: spot 1)")), nameInput), codeField)),
    h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Map")), gallery.root),
  ),
  h(
    "div",
    { class: "request-col" },
    h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Who plays where")), h("div", { class: "request-slots" }, preview.root, h("div", {}, h("p", { class: "dim small section-help" }, "A player without a name is an open seat: whoever gets its join line takes it. Click a spot on the map to edit it."), slots.root))),
    h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Game settings"), settingsMeta), h("p", { class: "dim small section-help" }, "They start at this server's defaults (marked “server”). You can change them again in your lobby."), h("div", { class: "settings-tools" }, settingsFilter), settingsBox),
    h("section", { class: "card request-submit" }, queueLine, submit, submitNote),
  ),
);
form.addEventListener("submit", (event) => {
  event.preventDefault();
  void send();
});

function selectedMap(): MapInfo | undefined {
  return maps.find((map) => map.id === mapId);
}

function selectMap(id: string): void {
  mapId = id;
  const map = selectedMap();
  slots.slots = [];
  slots.setSpots(map === undefined ? 0 : spotsOf(map).length, (index) => (index === 0 ? "human" : index === 1 ? "ai" : "empty"));
  if (slots.slots[1] !== undefined) slots.slots[1].team = 3;
  if (slots.slots[0] !== undefined) slots.slots[0].team = 2;
  slots.render();
  void loadSettings();
  renderPicked();
}

function renderPicked(): void {
  const map = selectedMap();
  preview.update(map, slots.marks());
  gallery.refreshFit();
  const problem = problemText();
  submit.disabled = sending || problem !== "";
  submitNote.textContent = problem !== "" ? problem : map === undefined ? "" : `${map.name ?? map.id} · ${mapFacts(map)} · ${slots.filled()} seats`;
  submitNote.classList.toggle("bad-text", problem !== "");
}

function problemText(): string {
  if (nameInput.value.trim() === "") return "Type your name.";
  if (pool?.access === "code" && codeInput.value.trim() === "") return "Type the access code.";
  if (selectedMap() === undefined) return "Pick a map.";
  return slots.problem();
}

async function loadSettings(): Promise<void> {
  const key = mapId;
  let answer = settingsCache.get(key);
  if (answer === undefined) {
    try {
      answer = await api.settings(key, AbortSignal.timeout(8000));
      settingsCache.set(key, answer);
    } catch (error) {
      settingsBox.replaceChildren(h("p", { class: "dim" }, `The settings didn't load: ${error instanceof Error ? error.message : String(error)}`));
      return;
    }
  }
  if (key !== mapId) return;
  settings = answer;
  // The server's defaults are where the form starts; the player's own changes stay where they still mean something.
  for (const [option, value] of Object.entries(pool?.options ?? {})) if (!chosen.has(option)) chosen.set(option, value);
  pruneChosen(chosen, answer);
  for (const option of [...answer.options, ...answer.map_options]) if (sameKey(chosen.get(option.key), option.default)) chosen.delete(option.key);
  renderOptions(settingsBox, answer, selectedMap()?.name ?? "this map", {
    chosen,
    preset: new Map(Object.entries(pool?.options ?? {})),
    presetLabel: "server",
    idPrefix: "req-set-",
    onChange: () => (settingsMeta.textContent = `${countChanges(settingsBox)} not at FAF's default`),
  });
  settingsMeta.textContent = `${countChanges(settingsBox)} not at FAF's default`;
  filterOptions(settingsBox, settingsFilter.value);
  slots.render();
  renderPicked();
}

async function send(): Promise<void> {
  const map = selectedMap();
  const problem = problemText();
  if (problem !== "" || map === undefined || sending) {
    if (problem !== "") toast("bad", "Not yet", problem);
    return;
  }
  sending = true;
  submit.classList.add("busy");
  renderPicked();
  const player = nameInput.value.trim();
  writeStore(STORE_NAME, player);
  try {
    const request = await api.create({ player, map: map.id, seats: slots.seats(), options: Object.fromEntries(chosen), ...(pool?.access === "code" ? { code: codeInput.value.trim() } : {}) });
    if (typeof request.key !== "string" || request.key === "") throw new Error("the server's answer has no key to follow the request with");
    const humans = slots.seats().filter((seat) => seat.kind === "human").length;
    const bots = slots.seats().length - humans;
    const state: Followed = { host: api.base, id: request.id, key: request.key, map: map.id, summary: `${map.name ?? map.id} (${map.km ?? "?"} km), ${humans} ${humans === 1 ? "player" : "players"}${bots > 0 ? ` and ${bots} ${bots === 1 ? "AI" : "AIs"}` : ""}` };
    writeStore(STORE_KEY, JSON.stringify(state));
    renderRequest(request, state);
    void follow(state);
  } catch (error) {
    toast("bad", error instanceof ApiError && error.status === 429 ? "Too many requests" : "The server didn't take it", error instanceof Error ? error.message : String(error));
  } finally {
    sending = false;
    submit.classList.remove("busy");
    renderPicked();
  }
}

function renderQueueLine(): void {
  if (pool === null) return;
  const q = pool.queue;
  queueLine.replaceChildren(
    icon(q.games >= q.max_games && q.max_games > 0 ? "timer" : "check", "icon"),
    q.max_games > 0 && q.games >= q.max_games ? `All ${q.max_games} game places are taken${q.length > 0 ? ` and ${q.length} ${q.length === 1 ? "game waits" : "games wait"}` : ""}: yours will wait its turn.` : `${q.max_games - q.games} of ${q.max_games} game places free: yours should start right away.`,
  );
}

async function showForm(): Promise<void> {
  window.clearTimeout(followTimer);
  document.title = "Ask for a game server · FAF";
  main.replaceChildren(h("p", { class: "dim request-loading" }, "Loading…"));
  try {
    pool = await api.pool(AbortSignal.timeout(8000));
  } catch (error) {
    setPill("bad", "No answer");
    const retry = h("button", { type: "button", class: "btn primary" }, "Try again");
    retry.addEventListener("click", () => void showForm());
    main.replaceChildren(h("div", { class: "request-state-wrap" }, h("section", { class: "card request-state tone-bad" }, h("h1", { class: "state-title" }, "The server doesn't answer"), h("p", {}, `${api.base}: ${error instanceof Error ? error.message : String(error)}`), h("p", { class: "dim" }, "Check the link you were given; the server may be down for a moment."), retry)));
    return;
  }
  if (!pool.enabled) {
    setPill("idle", "Not taking requests");
    main.replaceChildren(h("div", { class: "request-state-wrap" }, h("section", { class: "card request-state tone-neutral" }, h("h1", { class: "state-title" }, "This server isn't taking requests now"), h("p", {}, "Its organiser has turned player games off. Try again later."))));
    return;
  }
  setPill("ok", `${pool.queue.games} of ${pool.queue.max_games} games running${pool.queue.length > 0 ? ` · ${pool.queue.length} waiting` : ""}`);
  codeField.hidden = pool.access !== "code";
  renderQueueLine();
  main.replaceChildren(form);
  if (maps.length === 0) {
    try {
      maps = (await api.maps(AbortSignal.timeout(15000))).sort((a, b) => (a.name ?? a.id).localeCompare(b.name ?? b.id));
    } catch (error) {
      gallery.root.replaceChildren(h("p", { class: "form-error" }, `The maps didn't load: ${error instanceof Error ? error.message : String(error)}`));
      return;
    }
  }
  if (mapId === "" && maps.length > 0) {
    const preferred = maps.find((map) => map.preview && (map.players ?? 0) >= 2 && (map.players ?? 0) <= Math.max(2, pool?.max_players ?? 8)) ?? maps[0];
    if (preferred !== undefined) mapId = preferred.id;
  }
  gallery.setMaps(maps, mapId);
  selectMap(mapId);
}

const state = followed();
if (state !== null) void follow(state);
else void showForm();
