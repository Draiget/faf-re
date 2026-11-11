// The dashboard's page (plan WP17.4, WP17.13): connect to a machine's server-host or to one server with the admin
// token. A host shows its CPUs, its lobbies and the form that starts one (host.ts); a lobby, or a single server, shows
// the lobby or game (seats, countdown, the armies of a running game), the control ops and the event stream.

import "./style.css";
import { ApiError, HostApi, ServerApi, type Answer, type HostInfo, type Lobby, type Seat, type ServerEvent, type Status } from "./api.ts";
import { renderArmies } from "./armies.ts";
import { byId, clock, h, icon, initials, isNumber, type Child } from "./dom.ts";
import { CATEGORIES, eventItem, kindOf, type Category, type EventContext } from "./events.ts";
import { lobbyById, lobbyHue, startHost, stateChip, stopHost } from "./host.ts";
import { confirmAction, toast } from "./ui.ts";

const STORE_URL = "faf-dashboard.url";
const STORE_TOKEN = "faf-dashboard.token";
const STORE_THEME = "faf-dashboard.theme";
const MAX_EVENTS = 300;
const CONNECT_TIME_MS = 5000;
const POLL_MS = 2000;

function readStore(storage: () => Storage, key: string): string {
  try {
    return storage().getItem(key) ?? "";
  } catch {
    return "";
  }
}

function writeStore(storage: () => Storage, key: string, value: string): void {
  try {
    storage().setItem(key, value);
  } catch {
    // private window or blocked storage: the page works without it
  }
}

const session = (): Storage => sessionStorage;
const local = (): Storage => localStorage;

// ---------------------------------------------------------------- elements

const urlInput = byId<HTMLInputElement>("url");
const tokenInput = byId<HTMLInputElement>("token");
const connectForm = byId<HTMLFormElement>("connect-form");
const connectButton = byId<HTMLButtonElement>("connect");
const connectToggle = byId<HTMLButtonElement>("connect-toggle");
const connectSummary = byId<HTMLElement>("connect-summary");
const connectError = byId<HTMLElement>("connect-error");
const connection = byId<HTMLElement>("connection");
const connectionText = byId<HTMLElement>("connection-text");
const streamPill = byId<HTMLElement>("stream-pill");
const streamText = byId<HTMLElement>("stream-text");
const brandSub = byId<HTMLElement>("brand-sub");
const themeButton = byId<HTMLButtonElement>("theme");

const hero = byId<HTMLElement>("hero");
const heroEyebrow = byId<HTMLElement>("hero-eyebrow");
const heroTitle = byId<HTMLElement>("hero-title");
const heroBadges = byId<HTMLElement>("hero-badges");
const heroTiles = byId<HTMLElement>("hero-tiles");
const clockBlock = byId<HTMLElement>("clock-block");
const clockText = byId<HTMLElement>("clock");
const countdownBox = byId<HTMLElement>("countdown");
const countdownValue = byId<HTMLElement>("countdown-value");
const countdownRing = byId<HTMLElement>("countdown-ring");
const countdownAnnounce = byId<HTMLElement>("countdown-announce");

const armiesCard = byId<HTMLElement>("armies-card");
const armiesBox = byId<HTMLElement>("armies");
const armiesMeta = byId<HTMLElement>("armies-meta");

const seatsBox = byId<HTMLElement>("seats");
const seatsMeta = byId<HTMLElement>("seats-meta");
const seatsEmpty = byId<HTMLElement>("seats-empty");

const controls = byId<HTMLFieldSetElement>("controls");
const controlsMeta = byId<HTMLElement>("controls-meta");
const seatPick = byId<HTMLSelectElement>("seat-pick");
const playerUid = byId<HTMLInputElement>("player-uid");

const eventsList = byId<HTMLOListElement>("events");
const eventsEmpty = byId<HTMLElement>("events-empty");
const eventFilters = byId<HTMLElement>("event-filters");
const eventSearch = byId<HTMLInputElement>("event-search");
const eventsClear = byId<HTMLButtonElement>("events-clear");

const hostView = byId<HTMLElement>("host-view");
const serverView = byId<HTMLElement>("server-view");
const lobbyBar = byId<HTMLElement>("lobby-bar");
const lobbyBarName = byId<HTMLElement>("lobby-bar-name");
const lobbyBarMeta = byId<HTMLElement>("lobby-bar-meta");
const lobbyBarState = byId<HTMLElement>("lobby-bar-state");

// ---------------------------------------------------------------- state

let api: ServerApi | null = null;
/** "host": a server-host with lobbies; "single": one server; null before connecting. */
let mode: "host" | "single" | null = null;
let hostApi: HostApi | null = null;
/** The lobby the server view shows, in host mode. */
let lobbyId: string | null = null;
let refresh: number | undefined;
let stream: AbortController | null = null;
let lastStatus: Status | null = null;
let polling = false;
let pollAgain = false;
let armiesSupported = true;
let armiesBusy = false;
let gameEnded = false;
let selectedUid: number | null = null;
const results = new Map<number, { name: string; result: string }>();
const seatNames = new Map<number, string>();

// ---------------------------------------------------------------- theme

type Theme = "auto" | "light" | "dark";
const THEME_NEXT: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
const THEME_LABEL: Record<Theme, string> = { auto: "automatic", light: "light", dark: "dark" };
const THEME_ICON: Record<Theme, string> = { auto: "auto", light: "sun", dark: "moon" };

function applyTheme(theme: Theme): void {
  if (theme === "auto") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
  themeButton.replaceChildren(icon(THEME_ICON[theme]));
  const label = `Theme: ${THEME_LABEL[theme]} (switch to ${THEME_LABEL[THEME_NEXT[theme]]})`;
  themeButton.setAttribute("aria-label", label);
  themeButton.title = label;
  themeButton.dataset.theme = theme;
}

{
  const stored = readStore(local, STORE_THEME);
  applyTheme(stored === "light" || stored === "dark" ? stored : "auto");
}
themeButton.addEventListener("click", () => {
  const next = THEME_NEXT[(themeButton.dataset.theme as Theme | undefined) ?? "auto"];
  applyTheme(next);
  writeStore(local, STORE_THEME, next);
});

// ---------------------------------------------------------------- connection state

type ConnState = "idle" | "busy" | "ok" | "bad";

function setConnection(state: ConnState, text: string, detail = text): void {
  connection.className = `pill pill-${state}`;
  connectionText.textContent = text;
  connection.title = detail;
}

function setStream(live: boolean | null): void {
  streamPill.hidden = live === null;
  streamPill.classList.toggle("live", live === true);
  streamText.textContent = live ? "Events live" : "Events reconnecting";
}

function setConnectError(text: string): void {
  connectError.textContent = text;
  connectError.hidden = text === "";
}

function setFormOpen(open: boolean): void {
  connectForm.hidden = !open;
  connectToggle.setAttribute("aria-expanded", String(open));
  connectToggle.textContent = open ? "Hide" : "Change";
}

connectToggle.addEventListener("click", () => {
  const open = connectForm.hidden !== false;
  setFormOpen(open);
  if (open) urlInput.focus();
});

// ---------------------------------------------------------------- seats

function nameOf(uid: unknown): string {
  if (!isNumber(uid)) return "?";
  const name = seatNames.get(uid);
  return name === undefined || name === "" ? `uid ${uid}` : name;
}

type SeatState = { key: string; label: string; tone: string };

function seatState(seat: Seat, phase: string): SeatState {
  if (seat.gone) return { key: "gone", label: "Gone", tone: "neutral" };
  if (seat.lost) return { key: "lost", label: "Lost", tone: "bad" };
  if (seat.away) return { key: "away", label: "Away", tone: "warn" };
  if (!seat.joined) return { key: "absent", label: "Not joined", tone: "muted" };
  if (phase === "game" && seat.loaded === false) {
    const load = seat.load === "rules" ? "Loading rules" : "Loading";
    return { key: "loading", label: load, tone: "info" };
  }
  return { key: "here", label: "Here", tone: "ok" };
}

function pingTone(ping: number): string {
  return ping <= 80 ? "ok" : ping <= 160 ? "warn" : "bad";
}

function seatContent(seat: Seat, status: Status): Child[] {
  const state = seatState(seat, status.phase);
  const isHost = status.host === seat.uid;
  const hue = (Math.abs(seat.uid) * 47) % 360;
  const avatar = h("span", { class: "avatar", "aria-hidden": "true" }, initials(seat.name || String(seat.uid)));
  avatar.style.setProperty("--hue", String(hue));
  const chips: Child[] = [h("span", { class: `chip state tone-${state.tone}` }, h("span", { class: "chip-dot", "aria-hidden": "true" }), state.label)];
  if (status.phase !== "game") {
    if (seat.ready === "yes") chips.push(h("span", { class: "chip tone-ok" }, icon("check", "icon tiny"), "Ready"));
    else if (seat.ready === "no") chips.push(h("span", { class: "chip tone-muted" }, "Not ready"));
  }
  if (seat.content === "differs" || seat.content === "missing") chips.push(h("span", { class: "chip tone-warn" }, `content ${seat.content}`));
  if (seat.mods === "outside" || seat.mods === "missing") chips.push(h("span", { class: "chip tone-warn" }, `mods ${seat.mods}`));

  const facts: Child[] = [];
  const ping = seat.ping_ms;
  if (seat.joined && !seat.gone && isNumber(ping)) {
    facts.push(h("span", { class: `fact ping tone-${pingTone(ping)}` }, h("span", { class: "ping-dot", "aria-hidden": "true" }), `${ping} ms`));
  } else {
    facts.push(h("span", { class: "fact dim" }, "ping –"));
  }
  if (isNumber(seat.slot) && seat.slot > 0) facts.push(h("span", { class: "fact" }, `slot ${seat.slot}`));
  if (isNumber(seat.speed_limit)) facts.push(h("span", { class: "fact" }, `speed ≤ ${seat.speed_limit > 0 ? "+" : ""}${seat.speed_limit}`));
  if (isNumber(seat.backlog_kb) && seat.backlog_kb > 0) facts.push(h("span", { class: `fact${seat.backlog_kb > 256 ? " tone-warn" : ""}` }, `backlog ${seat.backlog_kb} KB`));
  if (isNumber(seat.behind_beats) && seat.behind_beats > 5) facts.push(h("span", { class: "fact tone-warn" }, `${seat.behind_beats} beats behind`));

  return [
    h(
      "span",
      { class: "seat-top" },
      avatar,
      h(
        "span",
        { class: "seat-id" },
        h("span", { class: "seat-name" }, seat.name || "(no name)", isHost ? h("span", { class: "host-mark", title: "Host" }, icon("crown", "icon tiny"), h("span", { class: "sr-only" }, " (host)")) : null),
        h("span", { class: "seat-uid" }, `uid ${seat.uid}`),
      ),
    ),
    h("span", { class: "chips" }, ...chips),
    h("span", { class: "facts" }, ...facts),
  ];
}

const seatCards = new Map<number, HTMLButtonElement>();

function renderSeats(status: Status): void {
  const seats = status.seats ?? [];
  seatsEmpty.hidden = seats.length > 0;
  seatsEmpty.textContent = "This server has no seats.";
  const wanted: HTMLButtonElement[] = [];
  const present = new Set<number>();
  for (const seat of seats) {
    present.add(seat.uid);
    let card = seatCards.get(seat.uid);
    if (card === undefined) {
      card = h("button", { type: "button", class: "seat-card" });
      const uid = seat.uid;
      card.addEventListener("click", () => selectSeat(uid));
      seatCards.set(seat.uid, card);
    }
    const state = seatState(seat, status.phase);
    card.className = `seat-card state-${state.key}${selectedUid === seat.uid ? " selected" : ""}`;
    card.setAttribute("aria-pressed", String(selectedUid === seat.uid));
    card.setAttribute("aria-label", `${seat.name || "no name"}, uid ${seat.uid}, ${state.label}${status.host === seat.uid ? ", host" : ""}`);
    card.replaceChildren(...seatContent(seat, status).filter((child): child is Node => child instanceof Node));
    wanted.push(card);
  }
  for (const uid of [...seatCards.keys()]) {
    if (!present.has(uid)) seatCards.delete(uid);
  }
  // Reorder only when needed, so a focused card keeps its focus across polls.
  const current = [...seatsBox.children];
  if (current.length !== wanted.length || current.some((node, index) => node !== wanted[index])) {
    seatsBox.replaceChildren(...wanted);
  }
  const joined = seats.filter((seat) => seat.joined && !seat.gone).length;
  seatsMeta.textContent = seats.length === 0 ? "" : `${joined} of ${seats.length} joined`;
  renderSeatPicker(seats);
}

function renderSeatPicker(seats: Seat[]): void {
  const signature = seats.map((seat) => `${seat.uid}:${seat.name}`).join("|");
  if (seatPick.dataset.signature !== signature) {
    seatPick.dataset.signature = signature;
    seatPick.replaceChildren(
      h("option", { value: "" }, seats.length === 0 ? "No seats" : "Choose a seat"),
      ...seats.map((seat) => h("option", { value: String(seat.uid) }, `${seat.name || "(no name)"} · uid ${seat.uid}`)),
    );
  }
  seatPick.value = selectedUid !== null && seats.some((seat) => seat.uid === selectedUid) ? String(selectedUid) : "";
}

function selectSeat(uid: number | null): void {
  selectedUid = uid;
  seatPick.value = uid === null ? "" : String(uid);
  if (uid !== null) playerUid.value = String(uid);
  for (const [cardUid, card] of seatCards) {
    card.classList.toggle("selected", cardUid === uid);
    card.setAttribute("aria-pressed", String(cardUid === uid));
  }
}

seatPick.addEventListener("change", () => {
  selectSeat(seatPick.value === "" ? null : Number(seatPick.value));
});
playerUid.addEventListener("input", () => {
  const uid = Number(playerUid.value);
  const known = playerUid.value !== "" && seatCards.has(uid);
  selectedUid = known ? uid : null;
  seatPick.value = known ? String(uid) : "";
  for (const [cardUid, card] of seatCards) {
    card.classList.toggle("selected", cardUid === selectedUid);
    card.setAttribute("aria-pressed", String(cardUid === selectedUid));
  }
});

// ---------------------------------------------------------------- countdown

let countdownDeadline = 0;
let countdownTotal = 0;
let countdownTimer: number | undefined;
let countdownShown = -1;
const RING = 2 * Math.PI * 52;
countdownRing.style.strokeDasharray = String(RING);

function startCountdown(seconds: number): void {
  const deadline = performance.now() + seconds * 1000;
  // Polls and events both report it: follow the server, but don't jitter on small differences.
  if (countdownTimer === undefined || Math.abs(deadline - countdownDeadline) > 750) {
    countdownDeadline = deadline;
  }
  const configured = lastStatus?.start_when_ready_seconds;
  countdownTotal = Math.max(countdownTotal, seconds, isNumber(configured) ? configured : 0);
  if (countdownTimer === undefined) {
    countdownShown = -1;
    countdownTimer = window.setInterval(tickCountdown, 200);
    countdownAnnounce.textContent = `The game starts in ${Math.ceil(seconds)} seconds`;
  }
  countdownBox.hidden = false;
  hero.classList.add("counting");
  tickCountdown();
}

function stopCountdown(): void {
  window.clearInterval(countdownTimer);
  countdownTimer = undefined;
  countdownTotal = 0;
  countdownShown = -1;
  countdownAnnounce.textContent = "";
  countdownBox.hidden = true;
  hero.classList.remove("counting");
}

function tickCountdown(): void {
  const left = Math.max(0, (countdownDeadline - performance.now()) / 1000);
  const shown = Math.ceil(left);
  if (shown !== countdownShown) {
    countdownShown = shown;
    countdownValue.textContent = String(shown);
    if (shown > 0 && (shown <= 5 || shown % 10 === 0)) {
      countdownAnnounce.textContent = `${shown} seconds to start`;
    }
  }
  const ratio = countdownTotal > 0 ? left / countdownTotal : 0;
  countdownRing.style.strokeDashoffset = String(RING * (1 - Math.min(1, ratio)));
  countdownBox.classList.toggle("urgent", left <= 5);
}

// ---------------------------------------------------------------- hero

function tile(label: string, value: Child, tone = ""): HTMLElement {
  return h("div", { class: `tile${tone === "" ? "" : ` tone-${tone}`}` }, h("dt", {}, label), h("dd", {}, value));
}

function badge(text: string, tone: string, iconName?: string): HTMLElement {
  return h("span", { class: `badge tone-${tone}` }, iconName === undefined ? null : icon(iconName, "icon tiny"), text);
}

function renderHero(status: Status): void {
  const seats = status.seats ?? [];
  const inGame = status.phase === "game";
  hero.dataset.phase = inGame ? "game" : status.phase === "lobby" ? "lobby" : "other";
  heroEyebrow.textContent = inGame ? "Game" : status.phase === "lobby" ? "Lobby" : status.phase;

  const joined = seats.filter((seat) => seat.joined && !seat.gone);
  const ready = seats.filter((seat) => seat.ready === "yes").length;
  const badges: HTMLElement[] = [];
  if (inGame) {
    heroTitle.textContent = gameEnded ? "Game over" : status.paused ? "Paused" : status.started === false ? "Starting" : "In progress";
    if (gameEnded) badges.push(badge("Ended", "neutral", "stop"));
    else if (status.paused) badges.push(badge("Paused", "warn", "pause"));
    else badges.push(badge("Running", "ok", "play"));
  } else if (status.phase === "lobby") {
    heroTitle.textContent = seats.length === 0 ? "Open lobby" : joined.length < seats.length ? "Waiting for players" : ready === seats.length ? "Everyone is ready" : "Waiting for ready";
    badges.push(badge("Lobby", "accent", "users"));
  } else {
    heroTitle.textContent = status.phase;
  }
  const lost = seats.filter((seat) => seat.lost).length;
  const away = seats.filter((seat) => seat.away && !seat.lost && !seat.gone).length;
  if (lost > 0) badges.push(badge(`${lost} lost`, "bad"));
  if (away > 0) badges.push(badge(`${away} away`, "warn"));
  heroBadges.replaceChildren(...badges);

  clockBlock.hidden = !inGame || !isNumber(status.beat);
  if (isNumber(status.beat)) {
    clockText.textContent = clock(status.beat);
    clockBlock.classList.toggle("paused", status.paused === true);
  }

  const swr = status.start_when_ready_seconds;
  const tiles: HTMLElement[] = [tile("Players", `${joined.length} / ${seats.length}`)];
  if (!inGame) tiles.push(tile("Ready", `${ready} / ${seats.length}`, seats.length > 0 && ready === seats.length ? "ok" : ""));
  tiles.push(tile("Host", status.host === undefined ? "–" : nameOf(status.host)));
  tiles.push(tile("Start when ready", isNumber(swr) && swr > 0 ? `${swr} s` : "off"));
  if (inGame && isNumber(status.beat)) tiles.push(tile("Beat", status.beat.toLocaleString()));
  heroTiles.replaceChildren(...tiles);

  if (isNumber(status.countdown_seconds)) {
    startCountdown(status.countdown_seconds);
  } else if (countdownTimer !== undefined) {
    stopCountdown();
  }
}

function renderIdle(text: string): void {
  hero.dataset.phase = "none";
  heroEyebrow.textContent = "Status";
  heroTitle.textContent = text;
  heroBadges.replaceChildren();
  heroTiles.replaceChildren();
  clockBlock.hidden = true;
  stopCountdown();
}

function showStatus(status: Status): void {
  lastStatus = status;
  seatNames.clear();
  for (const seat of status.seats ?? []) seatNames.set(seat.uid, seat.name);
  document.body.classList.remove("stale");
  renderHero(status);
  renderSeats(status);
  for (const group of controls.querySelectorAll<HTMLElement>(".group[data-phase]")) {
    group.classList.toggle("off-phase", group.dataset.phase !== status.phase);
  }
  controlsMeta.textContent = status.phase === "game" ? "in game" : status.phase === "lobby" ? "in the lobby" : status.phase;
  if (status.phase !== "game") {
    armiesCard.hidden = true;
  }
}

// ---------------------------------------------------------------- polling

async function pollArmies(current: ServerApi): Promise<void> {
  if (!armiesSupported || armiesBusy) return;
  armiesBusy = true;
  try {
    const answer = await current.armies(AbortSignal.timeout(CONNECT_TIME_MS));
    if (api !== current || lastStatus?.phase !== "game") return;
    renderArmies(armiesBox, answer.armies);
    armiesMeta.textContent = `${answer.armies.length} ${answer.armies.length === 1 ? "army" : "armies"}${isNumber(answer.beat) ? ` · at ${clock(answer.beat)}` : ""}`;
    armiesCard.hidden = answer.armies.length === 0;
  } catch (error) {
    // A server without the endpoint, the lobby, or a hiccup: the panel goes, quietly.
    if (error instanceof ApiError && error.status === 404) armiesSupported = false;
    if (api === current) armiesCard.hidden = true;
  } finally {
    armiesBusy = false;
  }
}

async function poll(): Promise<void> {
  const current = api;
  if (current === null) return;
  if (polling) {
    pollAgain = true; // one more right after, for an event that came meanwhile
    return;
  }
  polling = true;
  try {
    const status = await current.status(AbortSignal.timeout(CONNECT_TIME_MS));
    if (api !== current) return;
    showStatus(status);
    if (mode === "single") setConnection("ok", "Connected", `connected to ${current.base}`);
    if (status.phase === "game") void pollArmies(current);
  } catch (error) {
    if (api !== current) return;
    document.body.classList.add("stale");
    if (mode === "host") {
      // The host knows why: a lobby still starting, stopped, or failed with its exit.
      const lobby = lobbyId === null ? undefined : lobbyById(lobbyId);
      if (lobby?.state === "failed") {
        renderIdle(`The lobby's server failed${lobby.exit ? `: ${lobby.exit}` : ""}`);
      } else if (lobby?.state === "stopped") {
        renderIdle("The lobby was stopped");
      } else if (lastStatus === null) {
        renderIdle(lobby?.state === "starting" ? "The lobby's server is starting…" : "The lobby's server isn't answering");
      }
      return;
    }
    if (error instanceof ApiError && error.status === 401) {
      setConnection("bad", "Token refused", "the admin token was refused");
    } else {
      setConnection("bad", "No answer", `no answer from ${current.base}`);
    }
  } finally {
    polling = false;
    if (pollAgain) {
      pollAgain = false;
      void poll();
    }
  }
}

// ---------------------------------------------------------------- events

const activeCategories = new Set<Category>(CATEGORIES.map((category) => category.id).filter((id) => id !== "console"));
const categoryCounts = new Map<Category, number>();
const filterButtons = new Map<Category, HTMLButtonElement>();

const context: EventContext = { nameOf, results };

function matchesFilter(item: HTMLElement): boolean {
  const category = item.dataset.cat as Category;
  if (!activeCategories.has(category)) return false;
  const query = eventSearch.value.trim().toLowerCase();
  return query === "" || (item.textContent ?? "").toLowerCase().includes(query);
}

function applyFilters(): void {
  let visible = 0;
  for (const item of eventsList.children) {
    const show = matchesFilter(item as HTMLElement);
    (item as HTMLElement).hidden = !show;
    if (show) visible += 1;
  }
  eventsEmpty.hidden = visible > 0;
  eventsEmpty.textContent = eventsList.children.length === 0 ? "No events yet." : "No events match the filter.";
}

function renderFilterCounts(): void {
  for (const [id, button] of filterButtons) {
    const count = button.querySelector(".count");
    if (count !== null) count.textContent = String(categoryCounts.get(id) ?? 0);
  }
}

for (const category of CATEGORIES) {
  const button = h(
    "button",
    { type: "button", class: `filter cat-${category.id}`, "aria-pressed": String(activeCategories.has(category.id)) },
    category.id === "console" ? "Console lines" : category.label,
    h("span", { class: "count", "aria-label": "events" }, "0"),
  );
  button.addEventListener("click", () => {
    if (activeCategories.has(category.id)) activeCategories.delete(category.id);
    else activeCategories.add(category.id);
    button.setAttribute("aria-pressed", String(activeCategories.has(category.id)));
    applyFilters();
  });
  filterButtons.set(category.id, button);
  eventFilters.append(button);
}
eventSearch.addEventListener("input", applyFilters);
eventsClear.addEventListener("click", () => {
  eventsList.replaceChildren();
  categoryCounts.clear();
  renderFilterCounts();
  applyFilters();
});

function addEvent(event: ServerEvent): void {
  const name = event.event;
  switch (name) {
    case "game_started":
    case "launched":
      results.clear();
      gameEnded = false;
      armiesSupported = true;
      stopCountdown();
      break;
    case "result":
      if (isNumber(event.army)) results.set(event.army, { name: String(event.name ?? ""), result: String(event.result ?? "") });
      break;
    case "game_ended":
      gameEnded = true;
      break;
    case "countdown":
      if (isNumber(event.seconds)) startCountdown(event.seconds);
      break;
    case "countdown_cancelled":
      stopCountdown();
      countdownAnnounce.textContent = "The start countdown was cancelled";
      toast("warn", "Countdown cancelled", String(event.reason ?? ""));
      break;
  }
  const item = eventItem(event, context, new Date());
  const category = kindOf(name).category;
  categoryCounts.set(category, (categoryCounts.get(category) ?? 0) + 1);
  item.hidden = !matchesFilter(item);
  eventsList.prepend(item);
  while (eventsList.children.length > MAX_EVENTS) {
    const last = eventsList.lastElementChild as HTMLElement | null;
    if (last === null) break;
    const lastCategory = last.dataset.cat as Category;
    categoryCounts.set(lastCategory, Math.max(0, (categoryCounts.get(lastCategory) ?? 1) - 1));
    last.remove();
  }
  renderFilterCounts();
  if (!item.hidden) eventsEmpty.hidden = true;
  if (name !== "log") {
    void poll(); // something changed: the page follows at once
  }
}

function follow(current: ServerApi): void {
  stream?.abort();
  const controller = new AbortController();
  stream = controller;
  setStream(false);
  current
    .events(addEvent, controller.signal, () => {
      if (stream === controller) setStream(true);
    })
    .then(
      () => retry(),
      () => retry(),
    );
  function retry(): void {
    if (controller.signal.aborted || stream !== controller) return;
    setStream(false);
    window.setTimeout(() => {
      if (stream === controller) follow(current); // the server went away or closed it: try again
    }, 3000);
  }
}

// ---------------------------------------------------------------- connect

urlInput.value = readStore(session, STORE_URL) || "http://127.0.0.1:27180";
tokenInput.value = readStore(session, STORE_TOKEN);

function setConnecting(on: boolean, label: string): void {
  connectButton.disabled = on;
  connectButton.classList.toggle("busy", on);
  connectButton.textContent = label;
  urlInput.disabled = on;
  tokenInput.disabled = on;
}

connectForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void connect();
});

function resetView(): void {
  lastStatus = null;
  results.clear();
  gameEnded = false;
  armiesSupported = true;
  armiesCard.hidden = true;
  armiesBox.replaceChildren();
  seatCards.clear();
  seatsBox.replaceChildren();
  seatsMeta.textContent = "";
  seatsEmpty.hidden = false;
  seatsEmpty.textContent = "Connect to see the seats.";
  renderSeatPicker([]);
  selectSeat(null);
  controls.disabled = true;
  controlsMeta.textContent = "connect first";
  document.body.classList.remove("stale");
  eventsList.replaceChildren();
  categoryCounts.clear();
  renderFilterCounts();
  applyFilters();
  setStream(null);
  renderIdle("Not connected");
}

/** Shows `candidate` (one server, or a lobby through its host) in the server view; `status` is its first answer. */
function startServerView(candidate: ServerApi, status: Status | null): void {
  stopServerView();
  api = candidate;
  controls.disabled = false;
  if (status !== null) {
    showStatus(status);
  } else {
    renderIdle("Connecting to the lobby…");
  }
  refresh = window.setInterval(() => void poll(), POLL_MS);
  follow(candidate);
  if (status === null) void poll();
  else if (status.phase === "game") void pollArmies(candidate);
}

/** What the server view ran stops: one server's seats and events don't mix with another's. */
function stopServerView(): void {
  window.clearInterval(refresh);
  refresh = undefined;
  stream?.abort();
  stream = null;
  api = null;
  resetView();
}

function showView(view: "host" | "server"): void {
  hostView.hidden = view !== "host";
  serverView.hidden = view !== "server";
  lobbyBar.hidden = !(view === "server" && mode === "host");
}

/** Host mode: `#/lobby/<id>` shows that lobby in the server view, anything else the host overview. */
function route(): void {
  if (mode !== "host" || hostApi === null) return;
  const match = /^#\/lobby\/(.+)$/.exec(location.hash);
  const id = match?.[1] === undefined ? null : decodeURIComponent(match[1]);
  if (id === null) {
    if (lobbyId !== null) {
      stopServerView();
      lobbyId = null;
    }
    showView("host");
    document.title = "FAF Server Dashboard";
    return;
  }
  if (id !== lobbyId) {
    lobbyId = id;
    startServerView(hostApi.lobbyApi(id), null);
    window.scrollTo({ top: 0 });
  }
  showView("server");
  renderLobbyBar();
}

window.addEventListener("hashchange", route);

function renderLobbyBar(): void {
  if (lobbyId === null) return;
  const lobby: Lobby | undefined = lobbyById(lobbyId);
  lobbyBarName.textContent = lobby?.name || lobbyId;
  lobbyBar.style.setProperty("--lobby", `hsl(${lobbyHue(lobbyId)} 75% 52%)`);
  if (lobby === undefined) {
    lobbyBarMeta.textContent = " · not on the host's list";
    lobbyBarState.replaceChildren();
  } else {
    const cpus = (lobby.cpus ?? []).filter(isNumber);
    const map = lobby.map;
    lobbyBarMeta.textContent = ` · ${map?.name ?? map?.id ?? "map ?"}${cpus.length > 0 ? ` · CPU ${cpus.join(", ")}` : ""}`;
    lobbyBarState.replaceChildren(stateChip(lobby.state));
  }
  document.title = `${lobby?.name || lobbyId} · FAF Server Dashboard`;
}

function hostHealth(error: string | null, unauthorized: boolean): void {
  if (hostApi === null) return;
  if (error === null) {
    setConnection("ok", "Connected", `connected to the host at ${hostApi.base}`);
  } else {
    setConnection("bad", unauthorized ? "Token refused" : "No answer", error);
  }
}

function stopEverything(): void {
  stopServerView();
  stopHost();
  mode = null;
  hostApi = null;
  lobbyId = null;
  showView("server");
}

function connected(base: string, kind: string): void {
  setConnection("ok", "Connected", `connected to ${base}`);
  brandSub.textContent = `${kind} · ${base.replace(/^https?:\/\//, "")}`;
  connectSummary.textContent = `Connected to ${kind} at ${base}`;
  connectToggle.hidden = false;
  setFormOpen(false);
}

async function connect(): Promise<void> {
  if (connectButton.disabled) {
    return; // a connection attempt is under way
  }
  const url = urlInput.value.trim();
  const token = tokenInput.value.trim();
  if (!/^https?:\/\/.+/.test(url)) {
    setConnection("bad", "Not connected", "the address starts with http:// or https://");
    setConnectError("The address starts with http:// or https://.");
    urlInput.focus();
    return;
  }
  if (token === "") {
    setConnection("bad", "Not connected", "the admin token is empty");
    setConnectError("The admin token is empty.");
    tokenInput.focus();
    return;
  }
  stopEverything();
  renderIdle("Connecting…");
  writeStore(session, STORE_URL, url);
  writeStore(session, STORE_TOKEN, token);
  setConnectError("");
  setConnecting(true, "Connecting…");
  setConnection("busy", "Connecting…", `connecting to ${url}`);
  try {
    // A server-host answers /api/v1/host; a single server answers 404 there and is shown as before.
    const host = new HostApi(url, token);
    let info: HostInfo | null = null;
    try {
      info = await host.host(AbortSignal.timeout(CONNECT_TIME_MS));
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 404)) throw error;
    }
    if (info !== null) {
      mode = "host";
      hostApi = host;
      startHost(host, info, { onHealth: hostHealth, onLobbies: renderLobbyBar });
      connected(host.base, `host ${info.name ?? ""}`.trim());
      route();
    } else {
      const candidate = new ServerApi(url, token);
      const status = await candidate.status(AbortSignal.timeout(CONNECT_TIME_MS));
      mode = "single";
      showView("server");
      startServerView(candidate, status);
      connected(candidate.base, "the server");
    }
    setConnecting(false, "Reconnect");
  } catch (error) {
    stopEverything();
    let why = `No answer from ${url}: check the address and port, and that server-host (or a server with --rest) runs there.`;
    let short = "No answer";
    if (error instanceof ApiError && error.status === 401) {
      why = "The admin token was refused.";
      short = "Token refused";
    } else if (error instanceof DOMException && error.name === "TimeoutError") {
      why = `No answer from ${url} within ${CONNECT_TIME_MS / 1000} s.`;
    } else if (error instanceof ApiError) {
      why = error.message;
      short = "Refused";
    }
    setConnection("bad", short, why);
    setConnectError(why);
    renderIdle("Not connected");
    connectSummary.textContent = "Enter the address and admin token";
    setFormOpen(true);
    setConnecting(false, "Connect");
  }
}

// ---------------------------------------------------------------- control ops

const OP_LABEL: Record<string, string> = {
  force_start: "Start",
  pause: "Pause",
  resume: "Resume",
  eject: "Eject",
  set_options: "Set options",
  set_player: "Set player",
  allow: "Allow",
  disallow: "Disallow",
  substitute: "Substitute",
  extend_timeouts: "Extend timeouts",
  end: "End the game",
};

function value(id: string): string {
  return byId<HTMLInputElement>(id).value.trim();
}

function answerDetail(result: Answer): string {
  const { ok: _ok, id: _id, error: _error, ...rest } = result;
  return Object.keys(rest).length === 0 ? "" : JSON.stringify(rest);
}

async function run(op: string, fields: Record<string, unknown>, button: HTMLButtonElement): Promise<void> {
  const label = OP_LABEL[op] ?? op;
  const current = api;
  if (current === null) {
    toast("bad", `${label}: connect first`);
    return;
  }
  button.disabled = true;
  button.classList.add("busy");
  try {
    const result = await current.op(op, fields);
    if (result.ok) toast("ok", `${label}: done`, answerDetail(result));
    else toast("bad", `${label}: refused`, result.error ?? "no reason given");
  } catch (error) {
    toast("bad", `${label}: failed`, error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
    button.classList.remove("busy");
  }
  void poll();
}

/** The uid in the player controls, or null (with a toast) when there is none. */
function pickedUid(label: string): number | null {
  const raw = playerUid.value.trim();
  const uid = Number(raw);
  if (raw === "" || !Number.isInteger(uid)) {
    toast("bad", `${label}: pick a seat`, "Choose a seat (or click its card) or enter a uid.");
    playerUid.focus();
    return null;
  }
  return uid;
}

for (const radio of document.querySelectorAll<HTMLInputElement>('input[name="player-op"]')) {
  radio.addEventListener("change", () => {
    for (const panel of document.querySelectorAll<HTMLElement>(".op-panel")) {
      panel.hidden = panel.dataset.panel !== radio.value;
    }
  });
}

for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-op]")) {
  button.addEventListener("click", () => void onOp(button));
}

async function onOp(button: HTMLButtonElement): Promise<void> {
  const op = button.dataset.op ?? "";
  const label = OP_LABEL[op] ?? op;
  switch (op) {
    case "set_options":
      return run(op, { options: value("options") }, button);
    case "allow":
    case "disallow":
      return run(op, { address: value("address") }, button);
    case "eject": {
      const uid = pickedUid(label);
      if (uid === null) return;
      const reason = value("eject-reason");
      const ok = await confirmAction(`Eject ${nameOf(uid)}?`, `uid ${uid} leaves the ${lastStatus?.phase === "game" ? "game" : "lobby"}${reason === "" ? "" : `, with the reason "${reason}"`}.`, "Eject");
      if (ok) return run(op, { uid, reason }, button);
      return;
    }
    case "set_player": {
      const uid = pickedUid(label);
      if (uid === null) return;
      return run(op, { uid, options: value("player-options") }, button);
    }
    case "substitute": {
      const uid = pickedUid(label);
      if (uid === null) return;
      return run(op, { uid, token: value("sub-token"), name: value("sub-name") }, button);
    }
    case "extend_timeouts": {
      const uid = pickedUid(label);
      if (uid === null) return;
      const count = Number(value("timeouts-count") || "1");
      return run(op, { uid, count }, button);
    }
    case "end": {
      const outcome = value("results");
      const reason = value("end-reason");
      const ok = await confirmAction(
        "End the game?",
        outcome === "" ? "Without results the game counts as stopped, not ended." : `The game ends with the results ${outcome}.`,
        "End the game",
      );
      if (ok) return run(op, { results: outcome, reason }, button);
      return;
    }
    default:
      return run(op, {}, button);
  }
}

// ---------------------------------------------------------------- start

renderIdle("Not connected");
applyFilters();
setStream(null);
