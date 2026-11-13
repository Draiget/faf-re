// A lobby's page (`#/lobby/<id>[/log|/metrics]`), through the host's proxy to the lobby's own server: a bar with its
// name, kind, state, map and CPUs and three tabs. Game: the lobby or game (phase, countdown, game clock), the armies of
// a running game, the seats (joined, ready, ping), the lobby's facts with its join and watch lines, the event stream
// with filters, and the control ops (controls.ts). Server log: its server.log, live, filtered. Metrics: its CPU and
// memory over time.

import { ApiError, type Lobby, type Seat, type ServerApi, type ServerEvent, type Status } from "../api.ts";
import { renderArmies } from "../armies.ts";
import type { ServiceLobby } from "../control.ts";
import { byId, clock, fill, h, icon, initials, isNumber, type Child } from "../dom.ts";
import { CATEGORIES, eventItem, kindOf, type Category, type EventContext } from "../events.ts";
import { followLobbyLog, LogView } from "../logview.ts";
import { service } from "../service.ts";
import { toast } from "../ui.ts";
import { LobbyCharts } from "../views/metrics.ts";
import { bindControls, enableControls, followLobby, optionsChanged, renderSeatPicker, resetControls, showPhase, showSelection } from "./controls.ts";
import { cpuChips, fact, forgetLobby, joinBlock, kindChip, stateChip, stopLobby, timeOf, usageLine, warningSummary, watchBlock, yourBlock } from "./parts.ts";
import { colour, displayName, isPoolLobby, LIVE, lobbyById, on, plural, RUNNING, store } from "./store.ts";

const MAX_EVENTS = 300;
const REQUEST_MS = 5000;
const POLL_MS = 2000;

// ---------------------------------------------------------------- elements

const streamPill = byId<HTMLElement>("stream-pill");
const streamText = byId<HTMLElement>("stream-text");

const barName = byId<HTMLElement>("lobby-bar-name");
const barMeta = byId<HTMLElement>("lobby-bar-meta");
const barState = byId<HTMLElement>("lobby-bar-state");
const barSwatch = byId<HTMLElement>("lobby-bar-swatch");
const bar = byId<HTMLElement>("lobby-bar");
const barKind = byId<HTMLElement>("lobby-bar-kind");
const tabButtons = [...document.querySelectorAll<HTMLAnchorElement>("[data-lobby-tab]")];
const tabPanels = [...document.querySelectorAll<HTMLElement>("[data-lobby-panel]")];
const logBox = byId<HTMLElement>("lobby-log");
const metricsBox = byId<HTMLElement>("lobby-metrics");
const logView = new LogView({ tall: true });
const lobbyCharts = new LobbyCharts();
logBox.append(logView.root);
metricsBox.append(lobbyCharts.root);

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

const infoFacts = byId<HTMLElement>("lobby-facts");
const infoWarnings = byId<HTMLElement>("lobby-warnings");
const infoExit = byId<HTMLElement>("lobby-exit");
const infoLines = byId<HTMLElement>("lobby-lines");
const stopButton = byId<HTMLButtonElement>("lobby-stop");
const forgetButton = byId<HTMLButtonElement>("lobby-forget");

const eventsList = byId<HTMLOListElement>("events");
const eventsEmpty = byId<HTMLElement>("events-empty");
const eventFilters = byId<HTMLElement>("event-filters");
const eventSearch = byId<HTMLInputElement>("event-search");
const eventsClear = byId<HTMLButtonElement>("events-clear");

const view = byId<HTMLElement>("lobby-view");
const tabsNav = byId<HTMLElement>("lobby-tabs");
const controlsNote = byId<HTMLElement>("controls-note");
const controlsSet = byId<HTMLFieldSetElement>("controls");
const backLink = view.querySelector<HTMLAnchorElement>(".back-link");

// ---------------------------------------------------------------- state

let api: ServerApi | null = null;
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

export function openLobbyId(): string | null {
  return lobbyId;
}

function currentLobby(): Lobby | undefined {
  return lobbyId === null ? undefined : lobbyById(lobbyId);
}

// ---------------------------------------------------------------- through the control service: what the role allows

/** The service's view of the open lobby; null on one host's dashboard (or before the service lists it). */
function serviceView(): ServiceLobby | null {
  return currentLobby()?.service ?? null;
}

/** May the viewer run the lobby (its ops, its armies)? Always on one host's dashboard (the admin token). */
function mayRun(): boolean {
  return store.mode !== "service" || serviceView()?.can_operate === true;
}

/** Does the viewer see the lobby whole (every join line, the lobby server's events)? */
function seesAll(): boolean {
  if (store.mode !== "service") return true;
  const view = serviceView();
  return view !== null && view.host_record !== undefined && view.host_record !== null;
}

/** Why the viewer can't run this lobby, in plain words. */
function roleReason(view: ServiceLobby): Child[] {
  const tournament = service.me?.tournaments.find((item) => item.id === view.tournament)?.name ?? view.tournament;
  switch (view.origin) {
    case "organised":
      return [h("strong", {}, "Run by its organisers. "), `${tournament ? `The organisers of ${tournament}` : "Its organisers"} and admins start it, change its settings, pause, end the game and eject players. You see its seats and your own place.`];
    case "hosted":
      return view.can_stop
        ? [h("strong", {}, "Your game. "), "You run it from your own lobby screen in the game: start, settings and slots. Here you can stop it."]
        : [h("strong", {}, "A player's game. "), `${view.created_by?.name ?? "The player who asked for it"} runs it from their own lobby screen in the game.`];
    default:
      return [h("strong", {}, "Made on the host's own dashboard. "), "Only admins run it through the control service."];
  }
}

function renderRole(): void {
  const view = serviceView();
  const blocked = store.mode === "service" && view !== null && !view.can_operate;
  controlsSet.hidden = blocked;
  controlsNote.hidden = !blocked;
  if (blocked && view !== null) controlsNote.replaceChildren(icon("shield", "icon"), h("p", {}, ...roleReason(view)));
  tabsNav.hidden = store.mode === "service";
  if (backLink !== null) backLink.href = "#/lobbies";
}

function setStream(live: boolean | null): void {
  streamPill.hidden = live === null;
  streamPill.classList.toggle("live", live === true);
  streamText.textContent = live ? "Events live" : "Events reconnecting";
}

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
  seatsEmpty.textContent = "This lobby has no seats.";
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
  renderSeatPicker(seats, selectedUid);
}

function selectSeat(uid: number | null): void {
  selectedUid = uid;
  showSelection(uid);
  for (const [cardUid, card] of seatCards) {
    card.classList.toggle("selected", cardUid === uid);
    card.setAttribute("aria-pressed", String(cardUid === uid));
  }
}

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
  tiles.push(tile("Host", status.host === undefined ? "–" : status.host === 0 ? "nobody (the organiser runs it)" : nameOf(status.host)));
  // Through the control service a player's status leaves the countdown's setting out: the lobby's record may have it.
  const configured = isNumber(swr) ? swr : currentLobby()?.start_when_ready;
  if (isNumber(configured) || store.mode !== "service") tiles.push(tile("Start when ready", isNumber(configured) && configured > 0 ? `${configured} s` : "off"));
  if (inGame && isNumber(status.beat)) tiles.push(tile("Beat", status.beat.toLocaleString()));
  heroTiles.replaceChildren(...tiles);

  if (isNumber(status.countdown_seconds)) {
    startCountdown(status.countdown_seconds);
  } else if (countdownTimer !== undefined) {
    stopCountdown();
  }
}

function renderIdle(text: string, eyebrow = "Lobby"): void {
  hero.dataset.phase = "none";
  heroEyebrow.textContent = eyebrow;
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
  view.classList.remove("stale");
  renderHero(status);
  renderSeats(status);
  enableControls(mayRun(), "not yours to run");
  showPhase(status);
  if (status.phase !== "game") armiesCard.hidden = true;
}

// ---------------------------------------------------------------- polling

async function pollArmies(current: ServerApi): Promise<void> {
  if (!armiesSupported || armiesBusy) return;
  armiesBusy = true;
  try {
    const answer = await current.armies(AbortSignal.timeout(REQUEST_MS));
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
  // A lobby the host lists as stopped or failed has no server to ask: say so without a request.
  const known = currentLobby();
  if (known !== undefined && !LIVE.has(known.state)) {
    view.classList.add("stale");
    renderIdle(known.state === "failed" ? `The lobby's server failed${known.exit ? `: ${known.exit}` : ""}` : "The lobby was stopped");
    enableControls(false, "not running");
    setStream(null);
    return;
  }
  polling = true;
  try {
    const status = await current.status(AbortSignal.timeout(REQUEST_MS));
    if (api !== current) return;
    showStatus(status);
    if (status.phase === "game") void pollArmies(current);
  } catch (error) {
    if (api !== current) return;
    view.classList.add("stale");
    // The host knows why: a lobby still starting, stopped, or failed with its exit.
    const lobby = currentLobby();
    const viaService = store.mode === "service";
    if (lobby?.state === "failed") {
      renderIdle(`The lobby's server failed${lobby.exit ? `: ${lobby.exit}` : ""}`);
      enableControls(false, "not running");
    } else if (lobby?.state === "stopped") {
      renderIdle("The lobby was stopped");
      enableControls(false, "not running");
    } else if (lastStatus === null) {
      const unlisted = viaService ? (error instanceof ApiError && error.status === 404) || (lobby === undefined && store.lobbies.length > 0) : lobby === undefined && store.lobbies.length > 0;
      renderIdle(unlisted ? (viaService ? "The control service doesn't list this lobby (yet)" : "The host doesn't list this lobby") : lobby?.state === "starting" ? "The lobby's server is starting…" : viaService && lobby?.service?.stale ? `Its host ${lobby.service.host} isn't answering the control service` : "The lobby's server isn't answering");
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
  eventsEmpty.textContent =
    eventsList.children.length > 0 ? "No events match the filter." : seesAll() ? "No events yet." : "The lobby's own events (players joining, readiness, the game's log) go to those who run it. The seats above follow the lobby live.";
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
    case "options":
      if (typeof event.options === "string") optionsChanged(event.options);
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
  const known = currentLobby();
  if (known !== undefined && !LIVE.has(known.state)) {
    // Stopped or failed: no stream to open. Look again later, in case the list was behind.
    setStream(null);
    window.setTimeout(() => {
      if (stream === controller) follow(current);
    }, 5000);
    return;
  }
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

// ---------------------------------------------------------------- the bar, the host's summary, the lobby's facts

let linesSignature = "";
let warnSignature = "";

function renderInfo(lobby: Lobby | undefined): void {
  if (lobby === undefined) {
    infoFacts.replaceChildren(fact("State", store.api === null ? "–" : "not on the host's list"));
    infoWarnings.replaceChildren();
    infoLines.replaceChildren();
    infoExit.hidden = true;
    stopButton.hidden = true;
    forgetButton.hidden = true;
    linesSignature = "";
    warnSignature = "";
    return;
  }
  const map = lobby.map;
  const cpus = (lobby.cpus ?? []).filter(isNumber);
  const nodes = (lobby.nodes ?? []).filter(isNumber);
  const seats = lobby.seats ?? [];
  const humans = seats.filter((seat) => seat.kind === "human").length;
  const observers = lobby.observers ?? [];
  const host = seats.find((seat) => seat.seat === 1 && seat.kind === "human")?.name ?? "";
  const sv = lobby.service ?? null;
  if (sv !== null) {
    renderServiceInfo(lobby, sv);
    return;
  }
  fill(
    infoFacts,
    fact("Map", h("span", {}, map?.name ?? map?.id ?? "unknown", isNumber(map?.km) ? h("span", { class: "dim" }, ` · ${map.km} km`) : null)),
    fact("Seats", `${plural(humans, "player")}${seats.length > humans ? ` + ${plural(seats.length - humans, "AI", "AIs")}` : ""}${observers.length > 0 ? ` · ${plural(observers.length, "observer")}` : ""}`),
    fact("Who starts it", lobby.control === "organiser" ? "the organiser (nobody hosts)" : lobby.control === "player" ? `the host player${host === "" ? "" : ` (${host})`}` : "–"),
    fact("CPUs", cpuChips(cpus, lobby.id)),
    fact(nodes.length > 1 ? "Nodes" : "Node", nodes.length === 0 ? "–" : `${nodes.join(", ")}${isPoolLobby(lobby) ? " · player pool" : ""}`),
    fact("Use now", RUNNING.has(lobby.state) ? usageLine(cpus.length, lobby.usage) : h("span", { class: "dim" }, "–"), true),
    fact("Port", isNumber(lobby.port) ? String(lobby.port) : "–"),
    fact("Started", `${timeOf(lobby.started_at ?? lobby.created)}${lobby.queued_at ? ` · queued at ${timeOf(lobby.queued_at)}` : ""}`),
    isPoolLobby(lobby) ? fact("Player request", String(lobby.request)) : null,
  );
  const warnings = lobby.warnings ?? [];
  const wsig = JSON.stringify(warnings);
  if (wsig !== warnSignature) {
    warnSignature = wsig;
    fill(infoWarnings, warningSummary(warnings));
  }
  infoExit.hidden = !lobby.exit;
  infoExit.textContent = lobby.exit ? `Exit: ${lobby.exit}` : "";
  stopButton.hidden = !LIVE.has(lobby.state);
  forgetButton.hidden = lobby.state !== "stopped" && lobby.state !== "failed";
  const lsig = JSON.stringify([lobby.state, seats.map((seat) => [seat.name, seat.join]), observers.map((observer) => [observer.name, observer.referee, observer.watch]), lobby.observer_delay_seconds]);
  if (lsig !== linesSignature) {
    linesSignature = lsig;
    fill(infoLines, LIVE.has(lobby.state) ? joinBlock(lobby) : null, LIVE.has(lobby.state) && observers.length > 0 ? watchBlock(lobby) : null);
  }
}

/** Through the control service: the lobby's host, who made it and for what, and the lines the viewer may see. */
function renderServiceInfo(lobby: Lobby, sv: ServiceLobby): void {
  const map = lobby.map;
  const seats = lobby.seats ?? [];
  const humans = seats.filter((seat) => seat.kind === "human").length;
  const observers = lobby.observers ?? [];
  const cpus = (lobby.cpus ?? []).filter(isNumber);
  const tournament = service.me?.tournaments.find((item) => item.id === sv.tournament)?.name ?? sv.tournament;
  const origin = sv.origin === "organised" ? `organised${tournament ? ` for ${tournament}` : ", outside tournaments"}` : sv.origin === "hosted" ? "a player's game (asked for through the service)" : "made on the host's own dashboard";
  fill(
    infoFacts,
    fact("Host", h("span", {}, sv.host, sv.stale ? h("span", { class: "warn-text small" }, " · not answering") : null)),
    fact("Map", h("span", {}, map?.name ?? map?.id ?? "unknown", isNumber(map?.km) ? h("span", { class: "dim" }, ` · ${map.km} km`) : null)),
    fact("Seats", `${plural(humans, "player")}${seats.length > humans ? ` + ${plural(seats.length - humans, "AI", "AIs")}` : ""}${observers.length > 0 ? ` · ${plural(observers.length, "observer")}` : ""}`),
    fact("Made", origin),
    sv.created_by ? fact("By", sv.created_by.name || `FAF user ${sv.created_by.uid}`) : null,
    fact("Who starts it", lobby.control === "organiser" ? "the organiser (nobody hosts)" : lobby.control === "player" ? `the host player${seats.find((seat) => seat.seat === 1)?.name ? ` (${seats.find((seat) => seat.seat === 1)?.name ?? ""})` : ""}` : "–"),
    cpus.length > 0 ? fact("CPUs", cpuChips(cpus, lobby.id)) : null,
    RUNNING.has(lobby.state) && lobby.usage ? fact("Use now", usageLine(cpus.length, lobby.usage), true) : null,
    fact("Started", timeOf(lobby.started_at ?? lobby.created)),
  );
  const warnings = lobby.warnings ?? [];
  const wsig = JSON.stringify(warnings);
  if (wsig !== warnSignature) {
    warnSignature = wsig;
    fill(infoWarnings, warningSummary(warnings));
  }
  infoExit.hidden = !lobby.exit;
  infoExit.textContent = lobby.exit ? `Exit: ${lobby.exit}` : "";
  stopButton.hidden = !LIVE.has(lobby.state) || !sv.can_stop;
  forgetButton.hidden = true;
  const all = seesAll();
  const lsig = JSON.stringify([all, lobby.state, sv.you, seats.map((seat) => [seat.name, seat.join]), observers.map((observer) => [observer.name, observer.referee, observer.watch]), lobby.observer_delay_seconds]);
  if (lsig !== linesSignature) {
    linesSignature = lsig;
    if (!LIVE.has(lobby.state)) fill(infoLines);
    else if (all) fill(infoLines, joinBlock(lobby), observers.length > 0 ? watchBlock(lobby) : null);
    else fill(infoLines, yourBlock(lobby));
  }
  renderRole();
}

function renderBar(): void {
  if (lobbyId === null) return;
  const lobby = currentLobby();
  const name = lobby === undefined ? lobbyId : displayName(lobby);
  barName.textContent = name;
  const tint = colour(lobbyId);
  bar.style.setProperty("--lobby", tint);
  barSwatch.style.setProperty("--swatch", tint);
  if (lobby === undefined) {
    barMeta.textContent = store.api === null ? "" : store.mode === "service" ? "not on the control service's list" : "not on the host's list";
    barState.replaceChildren();
    barKind.replaceChildren();
  } else {
    const cpus = (lobby.cpus ?? []).filter(isNumber);
    const map = lobby.map;
    const where = lobby.service ? `on ${lobby.service.host} · ` : "";
    barMeta.textContent = `${where}${map?.name ?? map?.id ?? "map ?"}${isNumber(map?.km) ? ` · ${map.km} km` : ""}${cpus.length > 0 ? ` · CPU ${cpus.join(", ")}` : ""}${(lobby.nodes ?? []).length > 0 ? ` · node ${(lobby.nodes ?? []).join(", ")}` : ""}`;
    barState.replaceChildren(stateChip(lobby.state));
    barKind.replaceChildren(kindChip(lobby));
  }
  document.title = `${name} · FAF Server Dashboard`;
}

function renderFromHost(): void {
  if (lobbyId === null) return;
  const lobby = currentLobby();
  renderBar();
  renderInfo(lobby);
  renderRole();
  if (eventsList.children.length === 0) applyFilters();
  followLobby(lobbyId, lobby);
}

on("lists", renderFromHost);

stopButton.addEventListener("click", () => {
  if (lobbyId !== null) void stopLobby(lobbyId, stopButton);
});
forgetButton.addEventListener("click", () => {
  if (lobbyId === null) return;
  // Forgotten, it has no page: back to the overview (a refusal shows as a toast there).
  void forgetLobby(lobbyId, forgetButton).then((done) => {
    if (done) location.hash = "#/lobbies";
  });
});

// ---------------------------------------------------------------- open, close

bindControls({
  api: () => api,
  status: () => lastStatus,
  lobby: currentLobby,
  nameOf,
  poll: () => void poll(),
  selectSeat,
  hasSeat: (uid) => seatCards.has(uid),
});

function resetView(): void {
  lastStatus = null;
  results.clear();
  seatNames.clear(); // the next lobby's first events come before its first status: no names from this one
  pollAgain = false;
  gameEnded = false;
  armiesSupported = true;
  armiesCard.hidden = true;
  armiesBox.replaceChildren();
  seatCards.clear();
  seatsBox.replaceChildren();
  seatsMeta.textContent = "";
  seatsEmpty.hidden = false;
  seatsEmpty.textContent = "No seats yet.";
  selectedUid = null;
  resetControls();
  view.classList.remove("stale");
  eventsList.replaceChildren();
  categoryCounts.clear();
  renderFilterCounts();
  applyFilters();
  setStream(null);
  linesSignature = "";
  warnSignature = "";
  renderIdle("Opening the lobby…");
}

// ---------------------------------------------------------------- tabs

export type LobbyTab = "game" | "log" | "metrics";
let stopLog: (() => void) | null = null;

function showTab(tab: LobbyTab): void {
  for (const button of tabButtons) {
    const current = button.dataset.lobbyTab === tab;
    button.classList.toggle("current", current);
    if (current) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
    if (lobbyId !== null) button.href = `#/lobby/${encodeURIComponent(lobbyId)}${button.dataset.lobbyTab === "game" ? "" : `/${button.dataset.lobbyTab ?? ""}`}`;
  }
  for (const panel of tabPanels) panel.hidden = panel.dataset.lobbyPanel !== tab;
  const host = store.api;
  if (tab === "log" && stopLog === null && host !== null && lobbyId !== null) {
    const id = lobbyId;
    stopLog = followLobbyLog(host, id, logView, () => LIVE.has(lobbyById(id)?.state ?? ""));
  }
  if (tab === "metrics" && lobbyId !== null) lobbyCharts.open(lobbyId);
  else lobbyCharts.close();
}

/** Opens lobby `id` through the host (`store.api`) on a tab: polls its status every 2 s and follows its events. */
export function openLobby(id: string, tab: LobbyTab = "game"): void {
  const host = store.api;
  if (host === null) return;
  if (id === lobbyId && api !== null) {
    renderFromHost();
    showTab(tab);
    return;
  }
  closeLobby();
  lobbyId = id;
  api = host.lobbyApi(id);
  logView.setLines([], "Loading…");
  renderFromHost();
  refresh = window.setInterval(() => void poll(), POLL_MS);
  follow(api);
  void poll();
  showTab(tab);
}

/** Stops following the open lobby: one lobby's seats and events don't mix with another's. */
export function closeLobby(): void {
  stopLog?.();
  stopLog = null;
  lobbyCharts.close();
  window.clearInterval(refresh);
  refresh = undefined;
  stream?.abort();
  stream = null;
  api = null;
  lobbyId = null;
  resetView();
}

resetView();
