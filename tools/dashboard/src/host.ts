// The host view (plan WP17.13): one machine's server-host with its CPUs as a heatmap, its lobbies, and the form that
// starts a new lobby. Each lobby opens in the server view (main.ts) through the host's proxy.

import "./host.css";
import { ApiError, type HostApi, type HostCpu, type HostInfo, type Hint, type Lobby, type MapInfo, type NewLobby, type NewSeat } from "./api.ts";
import { byId, clock, fill, h, icon, isNumber, num, type Child } from "./dom.ts";
import { confirmAction, copyButton, toast } from "./ui.ts";

const POLL_MS = 2000;
const REQUEST_MS = 5000;
const BUSY_LOAD = 50;
const MAX_MAP_ITEMS = 150;

export interface HostCallbacks {
  /** Each poll's outcome: null when the host answered, else why not (and whether the token was refused). */
  onHealth(error: string | null, unauthorized: boolean): void;
  /** The lobby list changed (the server view's lobby bar follows it). */
  onLobbies(lobbies: Lobby[]): void;
}

// ---------------------------------------------------------------- elements

const hostName = byId<HTMLElement>("host-name");
const hostModel = byId<HTMLElement>("host-model");
const hostTiles = byId<HTMLElement>("host-tiles");
const heatmap = byId<HTMLElement>("heatmap");
const heatSelection = byId<HTMLElement>("heat-selection");
const heatClear = byId<HTMLButtonElement>("heat-clear");
const heatNew = byId<HTMLButtonElement>("heat-new");

const lobbiesBox = byId<HTMLElement>("lobbies");
const lobbiesEmpty = byId<HTMLElement>("lobbies-empty");
const lobbiesMeta = byId<HTMLElement>("lobbies-meta");
const lobbyNew = byId<HTMLButtonElement>("lobby-new");
const lobbyEmptyNew = byId<HTMLButtonElement>("lobbies-empty-new");
const createdBox = byId<HTMLElement>("lobby-created");

const newLobby = byId<HTMLElement>("new-lobby");
const lobbyForm = byId<HTMLFormElement>("lobby-form");
const lobbyCancel = byId<HTMLButtonElement>("lobby-cancel");
const lobbyName = byId<HTMLInputElement>("lobby-name");
const mapSearch = byId<HTMLInputElement>("map-search");
const mapList = byId<HTMLElement>("map-list");
const mapCount = byId<HTMLElement>("map-count");
const mapSelected = byId<HTMLElement>("map-selected");
const seatRows = byId<HTMLElement>("seat-rows");
const seatAdd = byId<HTMLButtonElement>("seat-add");
const seatCount = byId<HTMLElement>("seat-count");
const optionGrid = byId<HTMLElement>("option-grid");
const lobbySwr = byId<HTMLInputElement>("lobby-swr");
const lobbyMinutes = byId<HTMLInputElement>("lobby-minutes");
const cpuAuto = byId<HTMLInputElement>("cpu-auto");
const cpuCoresField = byId<HTMLElement>("cpu-cores-field");
const cpuCores = byId<HTMLInputElement>("cpu-cores");
const cpuSummary = byId<HTMLElement>("cpu-summary");
const hintBox = byId<HTMLElement>("hint-box");
const cpuWarnings = byId<HTMLElement>("cpu-warnings");
const lobbySubmit = byId<HTMLButtonElement>("lobby-submit");

// ---------------------------------------------------------------- state

let api: HostApi | null = null;
let callbacks: HostCallbacks | null = null;
let timer: number | undefined;
let polling = false;
let info: HostInfo | null = null;
let lobbies: Lobby[] = [];
const picked = new Set<number>();

let maps: MapInfo[] | null = null;
let mapsLoading = false;
let mapId = "";
let coresTouched = false;
let hint: Hint | null = null;
let hintKey = "";
let hintTimer: number | undefined;
let createdId: string | null = null;

interface SeatDraft {
  kind: "human" | "ai";
  name: string;
  uid: string;
  ai: string;
  faction: number;
  team: number;
}
let seats: SeatDraft[] = [];

// ---------------------------------------------------------------- helpers

const RUNNING = new Set(["starting", "lobby", "game", "ended"]);
const STATE_TONE: Record<string, string> = { starting: "info", lobby: "accent", game: "ok", ended: "neutral", failed: "bad", stopped: "muted" };
const STATE_PHRASE: Record<string, string> = {
  starting: "is starting",
  lobby: "is open",
  game: "is in game",
  ended: "has ended",
  failed: "failed",
  stopped: "was stopped",
};
const STATE_LABEL: Record<string, string> = { starting: "Starting", lobby: "Lobby", game: "In game", ended: "Ended", failed: "Failed", stopped: "Stopped" };

export function lobbyHue(id: string): number {
  let hash = 0;
  for (const char of id) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return Math.round((hash * 137.508) % 360);
}

export function lobbyById(id: string): Lobby | undefined {
  return lobbies.find((lobby) => lobby.id === id);
}

export function stateChip(state: string): HTMLElement {
  const tone = STATE_TONE[state] ?? "neutral";
  return h(
    "span",
    { class: `chip state-chip tone-${tone}${state === "starting" ? " spinning" : ""}` },
    h("span", { class: "chip-dot", "aria-hidden": "true" }),
    STATE_LABEL[state] ?? state,
  );
}

function lobbyLabel(id: string): string {
  const lobby = lobbyById(id);
  return lobby?.name ? `${lobby.name}` : id;
}

function cpuLoad(cpu: HostCpu): number {
  return isNumber(cpu.load10) ? cpu.load10 : isNumber(cpu.load) ? cpu.load : 0;
}

function cpuById(id: number): HostCpu | undefined {
  return info?.cpus.find((cpu) => cpu.id === id);
}

function coreKey(cpu: HostCpu): string {
  return `${isNumber(cpu.socket) ? cpu.socket : 0}:${isNumber(cpu.core) ? cpu.core : `cpu${cpu.id}`}`;
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count} ${count === 1 ? one : many}`;
}

function gb(mb: number): string {
  return `${(mb / 1024).toFixed(mb >= 100 * 1024 ? 0 : 1)} GB`;
}

// ---------------------------------------------------------------- machine

function tile(label: string, value: Child, extra?: Child): HTMLElement {
  return h("div", { class: "tile" }, h("dt", {}, label), h("dd", {}, value), extra ?? null);
}

function renderMachine(): void {
  if (info === null) return;
  hostName.textContent = info.name ?? "Host";
  hostModel.textContent = info.cpu_model ?? "CPU model unknown";
  const cpus = info.cpus;
  const cores = new Set(cpus.map(coreKey)).size;
  const sockets = new Set(cpus.map((cpu) => (isNumber(cpu.socket) ? cpu.socket : 0))).size;
  const average = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
  const running = lobbies.filter((lobby) => RUNNING.has(lobby.state)).length;

  const total = info.memory_mb?.total;
  const available = info.memory_mb?.available;
  let memory: HTMLElement;
  if (isNumber(total) && total > 0 && isNumber(available)) {
    const used = Math.max(0, total - available);
    const ratio = used / total;
    const fill = h("span", { class: "fill" });
    fill.style.width = `${(ratio * 100).toFixed(1)}%`;
    memory = tile(
      "Memory",
      h("span", {}, gb(available), h("span", { class: "dim small" }, ` free of ${gb(total)}`)),
      h(
        "div",
        {
          class: `bar memory${ratio > 0.9 ? " tone-bad" : ratio > 0.75 ? " tone-warn" : ""}`,
          role: "meter",
          "aria-label": "Memory in use",
          "aria-valuemin": 0,
          "aria-valuemax": total,
          "aria-valuenow": used,
          "aria-valuetext": `${gb(used)} of ${gb(total)} in use`,
        },
        fill,
      ),
    );
  } else {
    memory = tile("Memory", "–");
  }
  hostTiles.replaceChildren(
    tile("CPUs", `${cpus.length}`, h("span", { class: "tile-sub" }, `${plural(cores, "core")} · ${plural(sockets, "socket")}`)),
    tile("Load (10 s)", `${Math.round(average)}%`),
    memory,
    tile("Lobbies", `${running}`, h("span", { class: "tile-sub" }, `${lobbies.length} listed`)),
  );
}

// ---------------------------------------------------------------- heatmap

const cells = new Map<number, HTMLButtonElement>();
let heatSignature = "";

function buildHeatmap(cpus: HostCpu[]): void {
  cells.clear();
  const sockets = new Map<number, Map<string, HostCpu[]>>();
  for (const cpu of [...cpus].sort((a, b) => a.id - b.id)) {
    const socket = isNumber(cpu.socket) ? cpu.socket : 0;
    const cores = sockets.get(socket) ?? new Map<string, HostCpu[]>();
    const key = coreKey(cpu);
    const siblings = cores.get(key) ?? [];
    siblings.push(cpu);
    cores.set(key, siblings);
    sockets.set(socket, cores);
  }
  const blocks = [...sockets.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([socket, cores]) =>
      h(
        "div",
        { class: "socket", role: "group", "aria-label": `Socket ${socket}` },
        h("div", { class: "socket-head" }, h("span", {}, `Socket ${socket}`), h("span", { class: "dim" }, plural(cores.size, "core"))),
        h(
          "div",
          { class: "cores" },
          ...[...cores.values()].map((siblings) => {
            const first = siblings[0];
            const coreName = first && isNumber(first.core) ? `Core ${first.core}` : "Core";
            return h(
              "div",
              { class: `core${siblings.length > 1 ? " smt" : ""}`, title: coreName },
              ...siblings.map((cpu) => {
                const cell = h("button", { type: "button", class: "cpu" });
                const id = cpu.id;
                cell.addEventListener("click", () => toggleCpu(id));
                cells.set(cpu.id, cell);
                return cell;
              }),
            );
          }),
        ),
      ),
    );
  heatmap.replaceChildren(...blocks);
}

function renderHeatmap(): void {
  if (info === null) return;
  const cpus = info.cpus;
  const signature = cpus.map((cpu) => `${cpu.id}/${coreKey(cpu)}`).join(",");
  if (signature !== heatSignature) {
    heatSignature = signature;
    buildHeatmap(cpus);
  }
  for (const id of [...picked]) {
    if (!cells.has(id)) picked.delete(id);
  }
  for (const cpu of cpus) {
    const cell = cells.get(cpu.id);
    if (cell === undefined) continue;
    const load10 = cpuLoad(cpu);
    const load = isNumber(cpu.load) ? cpu.load : load10;
    const pinned = (cpu.lobbies ?? []).filter((id) => typeof id === "string");
    const names = pinned.map(lobbyLabel);
    cell.style.setProperty("--heat-h", String(Math.round(140 - 140 * Math.min(1, Math.max(0, load10) / 100))));
    cell.style.setProperty("--heat-mix", `${Math.round(14 + 0.72 * Math.min(100, Math.max(0, load10)))}%`);
    const first = pinned[0];
    if (first !== undefined) cell.style.setProperty("--lobby", `hsl(${lobbyHue(first)} 80% 55%)`);
    else cell.style.removeProperty("--lobby");
    cell.classList.toggle("in-lobby", pinned.length > 0);
    cell.classList.toggle("picked", picked.has(cpu.id));
    cell.classList.toggle("hot", load10 >= 70);
    cell.setAttribute("aria-pressed", String(picked.has(cpu.id)));
    const where = `core ${isNumber(cpu.core) ? cpu.core : "?"}, socket ${isNumber(cpu.socket) ? cpu.socket : 0}`;
    const lobbyText = names.length === 0 ? "no lobby" : `lobbies: ${names.join(", ")}`;
    cell.title = `CPU ${cpu.id} (${where})\nLoad ${Math.round(load)}% now, ${Math.round(load10)}% over 10 s\n${names.length === 0 ? "No lobby pinned" : `Lobbies: ${names.join(", ")}`}`;
    cell.setAttribute("aria-label", `CPU ${cpu.id}, ${where}, load ${Math.round(load)} percent, ${Math.round(load10)} percent over 10 seconds, ${lobbyText}`);
    fill(
      cell,
      h("span", { class: "cpu-id" }, String(cpu.id)),
      h("span", { class: "cpu-load" }, `${Math.round(load10)}%`),
      pinned.length === 0
        ? null
        : h(
            "span",
            { class: "cpu-dots", "aria-hidden": "true" },
            ...pinned.slice(0, 3).map((id) => {
              const dot = h("span", { class: "cpu-dot" });
              dot.style.background = `hsl(${lobbyHue(id)} 80% 55%)`;
              return dot;
            }),
          ),
    );
  }
  renderPicked();
}

function toggleCpu(id: number): void {
  if (picked.has(id)) picked.delete(id);
  else picked.add(id);
  if (picked.size > 0 && cpuAuto.checked) {
    cpuAuto.checked = false;
    renderCpuMode();
  }
  const cell = cells.get(id);
  cell?.classList.toggle("picked", picked.has(id));
  cell?.setAttribute("aria-pressed", String(picked.has(id)));
  renderPicked();
}

function pickedList(): number[] {
  return [...picked].sort((a, b) => a - b);
}

function renderPicked(): void {
  const list = pickedList();
  heatSelection.textContent = list.length === 0 ? "Click CPUs to pick them for a new lobby." : `Picked: CPU ${list.join(", ")}`;
  heatClear.hidden = list.length === 0;
  heatNew.hidden = list.length === 0 || !newLobby.hidden;
  heatNew.textContent = `New lobby on ${plural(list.length, "CPU")}`;
  renderCpuChoice();
}

heatClear.addEventListener("click", () => {
  picked.clear();
  renderHeatmap();
});
heatNew.addEventListener("click", () => openForm());

// ---------------------------------------------------------------- lobby cards

interface LobbyCard {
  root: HTMLElement;
  update(lobby: Lobby): void;
}

const lobbyCards = new Map<string, LobbyCard>();

/** Each human seat's join switches, with a copy button. */
function joinBlock(lobby: Lobby): HTMLElement {
  const humans = (lobby.seats ?? []).filter((seat) => seat.kind === "human");
  if (humans.length === 0) {
    return h("p", { class: "dim join-help" }, "No human seats: nobody joins this lobby from a game.");
  }
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
          h(
            "div",
            { class: "join-who" },
            h("strong", {}, who),
            h("span", { class: "dim" }, ` · seat ${seat.seat}${isNumber(seat.uid) ? ` · uid ${seat.uid}` : ""}`),
          ),
          h(
            "div",
            { class: "join-cmd" },
            h("code", { class: "cmd" }, command ?? "not given out yet"),
            command === null ? null : copyButton(command, `Copy the join switches for ${who}`),
          ),
        );
      }),
    ),
  );
}

function seatSummary(lobby: Lobby): string {
  const list = lobby.seats ?? [];
  const humans = list.filter((seat) => seat.kind === "human").length;
  const ais = list.length - humans;
  return [humans > 0 ? plural(humans, "player") : "", ais > 0 ? plural(ais, "AI", "AIs") : ""].filter((part) => part !== "").join(" + ") || "no seats";
}

function createCard(first: Lobby): LobbyCard {
  const id = first.id;
  const title = h("h3", { class: "lobby-name" });
  const chip = h("span", { class: "lobby-chip" });
  const mapLine = h("div", { class: "lobby-map" });
  const facts = h("dl", { class: "lobby-facts" });
  const exit = h("p", { class: "lobby-exit", hidden: true });
  const open = h("a", { class: "btn primary small", href: `#/lobby/${encodeURIComponent(id)}` }, "Open");
  const stop = h("button", { type: "button", class: "btn danger small" }, "Stop…");
  const forget = h("button", { type: "button", class: "btn ghost small" }, "Forget");
  const joinSummary = h("summary", {}, "Join commands");
  const joinBody = h("div", { class: "join-body" });
  const join = h("details", { class: "join-details" }, joinSummary, joinBody);
  let joinSignature = "";
  let current = first;

  stop.addEventListener("click", () => void stopLobby(current, stop));
  forget.addEventListener("click", () => void forgetLobby(current, forget));

  const root = h(
    "article",
    { class: "lobby-card", "aria-labelledby": `lobby-title-${id}` },
    h("div", { class: "lobby-head" }, title, chip),
    mapLine,
    facts,
    exit,
    join,
    h("div", { class: "lobby-actions" }, open, stop, forget),
  );
  title.id = `lobby-title-${id}`;
  root.style.setProperty("--lobby", `hsl(${lobbyHue(id)} 75% 52%)`);

  function update(lobby: Lobby): void {
    current = lobby;
    title.textContent = lobby.name || lobby.id;
    chip.replaceChildren(stateChip(lobby.state));
    root.dataset.state = lobby.state;
    const map = lobby.map;
    fill(
      mapLine,
      icon("map", "icon tiny"),
      h("span", {}, map?.name ?? map?.id ?? "map unknown"),
      map && (isNumber(map.km) || isNumber(map.players))
        ? h("span", { class: "dim" }, ` · ${[isNumber(map.km) ? `${map.km} km` : "", isNumber(map.players) ? `${map.players} spots` : ""].filter((part) => part !== "").join(" · ")}`)
        : null,
    );
    const cpus = (lobby.cpus ?? []).filter(isNumber);
    const factItems: [string, Child][] = [
      ["Seats", seatSummary(lobby)],
      ["CPUs", cpus.length === 0 ? "–" : h("span", { class: "cpu-chips" }, ...cpus.map((cpu) => h("span", { class: "cpu-chip" }, String(cpu))))],
      [
        "Phase",
        lobby.phase ? `${lobby.phase}${lobby.phase === "game" && isNumber(lobby.beat) ? ` · ${clock(lobby.beat)}` : ""}` : "–",
      ],
      ["Control", lobby.control === "organiser" ? "organiser" : lobby.control === "player" ? "player hosts" : "–"],
    ];
    if (isNumber(lobby.port)) factItems.push(["Port", String(lobby.port)]);
    if (lobby.created) {
      const created = new Date(lobby.created);
      if (!Number.isNaN(created.getTime())) factItems.push(["Created", created.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })]);
    }
    facts.replaceChildren(...factItems.map(([label, value]) => h("div", { class: "fact-item" }, h("dt", {}, label), h("dd", {}, value))));
    exit.hidden = !lobby.exit;
    exit.textContent = lobby.exit ? `Exit: ${lobby.exit}` : "";

    const running = RUNNING.has(lobby.state);
    open.hidden = !running;
    stop.hidden = !running;
    forget.hidden = lobby.state !== "stopped" && lobby.state !== "failed";

    const humans = (lobby.seats ?? []).filter((seat) => seat.kind === "human");
    join.hidden = humans.length === 0 || !running;
    joinSummary.textContent = `Join commands (${humans.length})`;
    const signature = JSON.stringify(humans.map((seat) => [seat.seat, seat.name, seat.uid, seat.join]));
    if (signature !== joinSignature) {
      joinSignature = signature;
      joinBody.replaceChildren(joinBlock(lobby));
    }
  }

  update(first);
  return { root, update };
}

function renderLobbies(): void {
  const present = new Set<string>();
  const wanted: HTMLElement[] = [];
  const order = [...lobbies].sort((a, b) => Number(!RUNNING.has(a.state)) - Number(!RUNNING.has(b.state)) || String(b.created ?? "").localeCompare(String(a.created ?? "")));
  for (const lobby of order) {
    present.add(lobby.id);
    let card = lobbyCards.get(lobby.id);
    if (card === undefined) {
      card = createCard(lobby);
      lobbyCards.set(lobby.id, card);
    } else {
      card.update(lobby);
    }
    wanted.push(card.root);
  }
  for (const id of [...lobbyCards.keys()]) {
    if (!present.has(id)) lobbyCards.delete(id);
  }
  const currentChildren = [...lobbiesBox.children];
  if (currentChildren.length !== wanted.length || currentChildren.some((node, index) => node !== wanted[index])) {
    lobbiesBox.replaceChildren(...wanted);
  }
  const running = lobbies.filter((lobby) => RUNNING.has(lobby.state)).length;
  lobbiesEmpty.hidden = lobbies.length > 0;
  lobbiesMeta.textContent = lobbies.length === 0 ? "" : `${running} running · ${lobbies.length} listed`;
  renderCreated();
}

function renderCreated(): void {
  const lobby = createdId === null ? undefined : lobbyById(createdId);
  if (lobby === undefined) {
    if (createdId === null) createdBox.hidden = true;
    return;
  }
  const signature = JSON.stringify([lobby.state, lobby.name, (lobby.seats ?? []).map((seat) => seat.join)]);
  if (createdBox.dataset.signature === signature) return;
  createdBox.dataset.signature = signature;
  const dismiss = h("button", { type: "button", class: "btn ghost small" }, "Dismiss");
  dismiss.addEventListener("click", () => {
    createdId = null;
    createdBox.hidden = true;
    createdBox.dataset.signature = "";
  });
  createdBox.replaceChildren(
    h(
      "div",
      { class: "created-head" },
      h("span", { class: "created-icon" }, icon("check")),
      h("div", {}, h("strong", {}, `${lobby.name || lobby.id} ${STATE_PHRASE[lobby.state] ?? `is ${lobby.state}`}`), h("span", { class: "dim" }, ` · ${lobby.map?.name ?? ""}`)),
      stateChip(lobby.state),
    ),
    joinBlock(lobby),
    h("div", { class: "lobby-actions" }, h("a", { class: "btn primary small", href: `#/lobby/${encodeURIComponent(lobby.id)}` }, "Open the lobby"), dismiss),
  );
  createdBox.hidden = false;
}

async function stopLobby(lobby: Lobby, button: HTMLButtonElement): Promise<void> {
  const current = api;
  if (current === null) return;
  const ok = await confirmAction(
    `Stop ${lobby.name || lobby.id}?`,
    `Its server stops${lobby.state === "game" ? " in the middle of the game" : ""}, and everyone in it is disconnected. It stays listed as stopped until you forget it.`,
    "Stop the lobby",
  );
  if (!ok) return;
  button.disabled = true;
  button.classList.add("busy");
  try {
    await current.stopLobby(lobby.id);
    toast("ok", `Stopped ${lobby.name || lobby.id}`);
  } catch (error) {
    toast("bad", `Couldn't stop ${lobby.name || lobby.id}`, error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
    button.classList.remove("busy");
  }
  void poll();
}

async function forgetLobby(lobby: Lobby, button: HTMLButtonElement): Promise<void> {
  const current = api;
  if (current === null) return;
  button.disabled = true;
  try {
    await current.forgetLobby(lobby.id);
    if (createdId === lobby.id) createdId = null;
    toast("ok", `Forgot ${lobby.name || lobby.id}`);
  } catch (error) {
    toast("bad", `Couldn't forget ${lobby.name || lobby.id}`, error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
  }
  void poll();
}

// ---------------------------------------------------------------- new lobby: options

interface OptionSpec {
  key: string;
  label: string;
  values: [string, string][];
  initial: string;
}

const OPTIONS: OptionSpec[] = [
  { key: "Victory", label: "Victory condition", values: [["demoralization", "Assassination"], ["domination", "Supremacy"], ["eradication", "Annihilation"], ["sandbox", "Sandbox"]], initial: "demoralization" },
  {
    key: "Share",
    label: "Share conditions",
    values: [["FullShare", "Full share"], ["ShareUntilDeath", "Share until death"], ["PartialShare", "Partial share"], ["TransferToKiller", "Transfer to killer"], ["Defectors", "Defectors"], ["CivilianDeserter", "Civilian deserter"]],
    initial: "FullShare",
  },
  { key: "UnitCap", label: "Unit cap", values: ["125", "250", "375", "500", "625", "750", "875", "1000", "1250", "1500"].map((value) => [value, value]), initial: "1000" },
  { key: "FogOfWar", label: "Fog of war", values: [["explored", "Explored"], ["none", "None"]], initial: "explored" },
  { key: "GameSpeed", label: "Game speed", values: [["normal", "Normal"], ["fast", "Fast"], ["adjustable", "Adjustable"]], initial: "normal" },
  { key: "CheatsEnabled", label: "Cheats", values: [["false", "Off"], ["true", "On"]], initial: "false" },
  { key: "Timeouts", label: "Pauses per player", values: [["3", "3"], ["0", "None"], ["-1", "Unlimited"]], initial: "3" },
  {
    key: "NoRushOption",
    label: "No rush",
    values: [["Off", "Off"], ...["1", "2", "3", "4", "5", "10", "15", "20", "25", "30", "35", "40", "45", "50", "55", "60"].map((minutes): [string, string] => [minutes, `${minutes} min`])],
    initial: "Off",
  },
  { key: "PrebuiltUnits", label: "Prebuilt units", values: [["Off", "Off"], ["On", "On"]], initial: "Off" },
];

for (const option of OPTIONS) {
  const select = h("select", { id: `opt-${option.key}` }, ...option.values.map(([value, label]) => h("option", { value }, label)));
  select.value = option.initial;
  optionGrid.append(h("div", { class: "field" }, h("label", { for: `opt-${option.key}` }, option.label), select));
}

function chosenOptions(): Record<string, string> {
  const options: Record<string, string> = {};
  for (const option of OPTIONS) {
    options[option.key] = byId<HTMLSelectElement>(`opt-${option.key}`).value;
  }
  return options;
}

// ---------------------------------------------------------------- new lobby: maps

function selectedMap(): MapInfo | undefined {
  return maps?.find((map) => map.id === mapId);
}

function mapPlayers(): number {
  const players = selectedMap()?.players;
  return isNumber(players) && players > 0 ? players : 16;
}

async function loadMaps(): Promise<void> {
  const current = api;
  if (current === null || mapsLoading || maps !== null) return;
  mapsLoading = true;
  mapList.replaceChildren(h("p", { class: "empty" }, "Loading the host's maps…"));
  try {
    const list = await current.maps(AbortSignal.timeout(REQUEST_MS * 2));
    if (api !== current) return;
    maps = list;
    if (mapId === "" && list.length > 0) {
      // A sensible first pick: a map with room for the seats there are.
      const fit = list.find((map) => isNumber(map.players) && map.players >= Math.max(2, seats.length)) ?? list[0];
      if (fit !== undefined) mapId = fit.id;
    }
    renderMaps();
    onMapChanged();
  } catch (error) {
    const retry = h("button", { type: "button", class: "btn small" }, "Try again");
    retry.addEventListener("click", () => void loadMaps());
    mapList.replaceChildren(h("div", { class: "empty" }, h("p", {}, `The host's maps didn't load: ${error instanceof Error ? error.message : String(error)}`), retry));
  } finally {
    mapsLoading = false;
  }
}

function renderMaps(): void {
  if (maps === null) return;
  const query = mapSearch.value.trim().toLowerCase();
  const matching = maps.filter((map) => query === "" || `${map.name ?? ""} ${map.id}`.toLowerCase().includes(query));
  const shown = matching.slice(0, MAX_MAP_ITEMS);
  // The selected map stays listed (and checked) even when the search hides it.
  const chosen = selectedMap();
  if (chosen !== undefined && !shown.includes(chosen)) shown.unshift(chosen);
  mapCount.textContent = matching.length === maps.length ? `${maps.length} maps` : `${matching.length} of ${maps.length} maps`;
  if (shown.length === 0) {
    mapList.replaceChildren(h("p", { class: "empty" }, "No map matches the search."));
    return;
  }
  mapList.replaceChildren(
    ...shown.map((map) => {
      const radio = h("input", { type: "radio", name: "map", value: map.id, class: "sr-only" });
      radio.checked = map.id === mapId;
      radio.addEventListener("change", () => {
        if (!radio.checked) return;
        mapId = map.id;
        for (const item of mapList.querySelectorAll(".map-item")) item.classList.toggle("selected", item.contains(radio));
        onMapChanged();
      });
      const source = map.source === "vault" ? "Vault" : map.source === "fa" ? "FA" : (map.source ?? "");
      return h(
        "label",
        { class: `map-item${map.id === mapId ? " selected" : ""}` },
        radio,
        h("span", { class: "map-thumb", "aria-hidden": "true" }, isNumber(map.km) ? `${map.km}` : "?"),
        h("span", { class: "map-text" }, h("span", { class: "map-name" }, map.name ?? map.id), h("span", { class: "map-id" }, map.id)),
        h(
          "span",
          { class: "map-meta" },
          h("span", {}, isNumber(map.km) ? `${map.km} km` : "– km"),
          h("span", {}, isNumber(map.players) ? plural(map.players, "player") : "– players"),
          source === "" ? null : h("span", { class: `source source-${map.source ?? "other"}` }, source),
        ),
      );
    }),
    matching.length > MAX_MAP_ITEMS ? h("p", { class: "dim small map-more" }, `Showing ${MAX_MAP_ITEMS} of ${matching.length}; search to narrow it.`) : "",
  );
}

mapSearch.addEventListener("input", renderMaps);

function onMapChanged(): void {
  const map = selectedMap();
  if (map === undefined) {
    mapSelected.replaceChildren(h("span", { class: "dim" }, "No map picked yet."));
  } else {
    fill(
      mapSelected,
      h("strong", {}, map.name ?? map.id),
      h("span", { class: "dim" }, ` · ${isNumber(map.km) ? `${map.km} km` : "size unknown"} · up to ${isNumber(map.players) ? plural(map.players, "player") : "? players"}`),
      map.description ? h("p", { class: "map-description" }, map.description) : null,
    );
  }
  const limit = mapPlayers();
  if (seats.length > limit) {
    seats = seats.slice(0, limit);
    toast("info", `Seats trimmed to ${limit}`, `${map?.name ?? "This map"} has ${limit} start spots.`);
  }
  renderSeats();
  requestHint();
}

// ---------------------------------------------------------------- new lobby: seats

const FACTION_CHOICES: [number, string][] = [
  [1, "UEF"],
  [2, "Aeon"],
  [3, "Cybran"],
  [4, "Seraphim"],
  [5, "Random"],
];

function aiChoices(): string[] {
  const list = info?.ai?.filter((name) => typeof name === "string" && name !== "") ?? [];
  return list.length > 0 ? list : ["adaptive"];
}

function newSeat(index: number, kind: "human" | "ai"): SeatDraft {
  const ai = aiChoices();
  return { kind, name: "", uid: "", ai: ai.includes("adaptive") ? "adaptive" : (ai[0] ?? "adaptive"), faction: 5, team: 2 + (index % 2) };
}

function select(id: string, label: string, choices: [string, string][], value: string, onChange: (value: string) => void): HTMLElement {
  const node = h("select", { id }, ...choices.map(([choice, text]) => h("option", { value: choice }, text)));
  node.value = value;
  node.addEventListener("change", () => onChange(node.value));
  return h("div", { class: "field" }, h("label", { for: id }, label), node);
}

function renderSeats(): void {
  const limit = mapPlayers();
  seatRows.replaceChildren(
    ...seats.map((seat, index) => {
      const n = index + 1;
      const kind = select(`seat-${n}-kind`, "Kind", [["human", "Human"], ["ai", "AI"]], seat.kind, (value) => {
        seat.kind = value === "ai" ? "ai" : "human";
        renderSeats();
      });
      const who: HTMLElement[] = [];
      if (seat.kind === "human") {
        const name = h("input", { id: `seat-${n}-name`, placeholder: "player name", spellcheck: "false", autocomplete: "off" });
        name.value = seat.name;
        name.addEventListener("input", () => (seat.name = name.value));
        const uid = h("input", { id: `seat-${n}-uid`, type: "number", inputmode: "numeric", placeholder: "auto" });
        uid.value = seat.uid;
        uid.addEventListener("input", () => (seat.uid = uid.value));
        who.push(
          h("div", { class: "field grow" }, h("label", { for: `seat-${n}-name` }, "Name"), name),
          h("div", { class: "field uid" }, h("label", { for: `seat-${n}-uid` }, "uid ", h("span", { class: "dim" }, "(optional)")), uid),
        );
      } else {
        const personality = select(`seat-${n}-ai`, "AI personality", aiChoices().map((name): [string, string] => [name, name]), seat.ai, (value) => (seat.ai = value));
        personality.classList.add("grow");
        who.push(personality);
      }
      const faction = select(`seat-${n}-faction`, "Faction", FACTION_CHOICES.map(([value, label]): [string, string] => [String(value), label]), String(seat.faction), (value) => (seat.faction = Number(value)));
      const team = select(
        `seat-${n}-team`,
        "Team",
        [["1", "No team"], ...[1, 2, 3, 4, 5, 6, 7, 8].map((t): [string, string] => [String(t + 1), `Team ${t}`])],
        String(seat.team),
        (value) => (seat.team = Number(value)),
      );
      const remove = h("button", { type: "button", class: "btn ghost small seat-remove", "aria-label": `Remove seat ${n}`, title: "Remove this seat" }, icon("trash", "icon tiny"));
      remove.disabled = seats.length <= 1;
      remove.addEventListener("click", () => {
        seats.splice(index, 1);
        renderSeats();
        requestHint();
      });
      return h(
        "fieldset",
        { class: `seat-row kind-${seat.kind}` },
        h("legend", {}, `Seat ${n}`, h("span", { class: "dim" }, ` · start spot ${n}`)),
        h("div", { class: "seat-fields" }, kind, ...who, faction, team),
        remove,
      );
    }),
  );
  seatCount.textContent = `${seats.length} of ${limit}`;
  seatAdd.disabled = seats.length >= limit;
  seatAdd.title = seats.length >= limit ? "The map has no more start spots" : "";
}

seatAdd.addEventListener("click", () => {
  if (seats.length >= mapPlayers()) return;
  seats.push(newSeat(seats.length, seats.some((seat) => seat.kind === "human") ? "ai" : "human"));
  renderSeats();
  requestHint();
  byId<HTMLSelectElement>(`seat-${seats.length}-kind`).focus();
});

// ---------------------------------------------------------------- new lobby: CPUs and the hint

function requestHint(): void {
  const map = selectedMap();
  if (api === null || map === undefined || !isNumber(map.km)) {
    hint = null;
    hintKey = "";
    renderCpuChoice();
    return;
  }
  const key = `${seats.length}|${map.km}`;
  if (key === hintKey) return;
  hintKey = key;
  window.clearTimeout(hintTimer);
  const current = api;
  const km = map.km;
  hintTimer = window.setTimeout(() => {
    current
      .hint(Math.max(1, seats.length), km, AbortSignal.timeout(REQUEST_MS))
      .then((answer) => {
        if (api !== current || hintKey !== key) return;
        hint = answer;
        if (!coresTouched && isNumber(answer.suggested_cores)) cpuCores.value = String(Math.max(1, answer.suggested_cores));
        renderCpuChoice();
      })
      .catch((error: unknown) => {
        if (hintKey !== key) return;
        hint = null;
        hintKey = "";
        hintBox.replaceChildren(h("span", { class: "dim" }, `No cost hint: ${error instanceof Error ? error.message : String(error)}`));
      });
  }, 200);
}

function renderCpuMode(): void {
  cpuCoresField.hidden = !cpuAuto.checked;
  cpuSummary.hidden = cpuAuto.checked;
  if (cpuAuto.checked && picked.size > 0) {
    picked.clear();
    renderHeatmap();
  }
  renderCpuChoice();
}

cpuAuto.addEventListener("change", renderCpuMode);
cpuCores.addEventListener("input", () => {
  coresTouched = true;
  renderCpuChoice();
});

interface Warning {
  tone: "warn" | "bad";
  text: string;
}

function cpuWarningsNow(): Warning[] {
  const warnings: Warning[] = [];
  const suggested = hint?.suggested_cores;
  if (cpuAuto.checked) {
    const cores = Number(cpuCores.value);
    if (!Number.isInteger(cores) || cores < 1) warnings.push({ tone: "bad", text: "Give at least 1 core." });
    else if (isNumber(suggested) && cores < suggested) warnings.push({ tone: "warn", text: `${plural(cores, "core")} is fewer than the ${suggested} suggested.` });
    else if (info !== null && cores > info.cpus.length) warnings.push({ tone: "bad", text: `The machine has only ${info.cpus.length} CPUs.` });
    return warnings;
  }
  const list = pickedList();
  if (list.length === 0) {
    warnings.push({ tone: "bad", text: "Pick CPUs on the heatmap, or switch Auto on." });
    return warnings;
  }
  const cores = new Set(list.map((id) => {
    const cpu = cpuById(id);
    return cpu === undefined ? `cpu${id}` : coreKey(cpu);
  })).size;
  if (isNumber(suggested) && cores < suggested) {
    warnings.push({ tone: "warn", text: `${plural(list.length, "CPU")} on ${plural(cores, "core")} is fewer than the ${plural(suggested, "core")} suggested.` });
  }
  for (const id of list) {
    const cpu = cpuById(id);
    if (cpu === undefined) continue;
    const pinned = (cpu.lobbies ?? []).filter((lobby) => typeof lobby === "string");
    if (pinned.length > 0) warnings.push({ tone: "warn", text: `CPU ${id} already runs ${pinned.map(lobbyLabel).join(", ")}.` });
    else if (cpuLoad(cpu) >= BUSY_LOAD) warnings.push({ tone: "warn", text: `CPU ${id} is ${Math.round(cpuLoad(cpu))}% busy over the last 10 s.` });
  }
  return warnings;
}

function renderCpuChoice(): void {
  const list = pickedList();
  cpuSummary.replaceChildren(
    list.length === 0
      ? h("span", { class: "dim" }, "Click CPUs on the heatmap to pick them.")
      : h("span", {}, "Picked on the heatmap: ", h("strong", {}, `CPU ${list.join(", ")}`), h("span", { class: "dim" }, ` (${plural(list.length, "CPU")})`)),
  );
  if (hint !== null) {
    const basis = hint.basis ?? "";
    hintBox.replaceChildren(
      h("span", { class: "hint-icon" }, icon("cpu")),
      h(
        "div",
        { class: "hint-text" },
        h("strong", { title: basis }, isNumber(hint.suggested_cores) ? `Suggests ${plural(hint.suggested_cores, "core")}` : "No suggestion"),
        h("span", { class: "dim" }, `mean ${num(hint.mean_cores, 2)} · worst ${num(hint.worst_cores, 2)} cores for ${plural(seats.length, "player")} on ${num(hint.km)} km`),
        basis === "" ? null : h("details", { class: "hint-basis" }, h("summary", {}, "How this is estimated"), h("p", {}, basis)),
      ),
    );
  } else if (hintKey === "") {
    hintBox.replaceChildren(h("span", { class: "dim" }, selectedMap() ? "No cost hint for this map." : "Pick a map for a cost hint."));
  }
  const warnings = cpuWarningsNow();
  cpuWarnings.replaceChildren(...warnings.map((warning) => h("li", { class: `warning tone-${warning.tone}` }, icon(warning.tone === "bad" ? "ban" : "warn", "icon tiny"), warning.text)));
}

// ---------------------------------------------------------------- new lobby: open, submit

function openForm(): void {
  if (api === null) return;
  newLobby.hidden = false;
  heatNew.hidden = true;
  if (seats.length === 0) seats = [newSeat(0, "human"), newSeat(1, "ai")];
  if (lobbyName.value.trim() === "") lobbyName.value = `${info?.name ?? "Host"} lobby ${lobbies.length + 1}`;
  if (picked.size > 0) cpuAuto.checked = false;
  renderSeats();
  renderCpuMode();
  void loadMaps();
  requestHint();
  newLobby.scrollIntoView({ behavior: "smooth", block: "start" });
  lobbyName.focus({ preventScroll: true });
}

function closeForm(): void {
  newLobby.hidden = true;
  renderPicked();
}

lobbyNew.addEventListener("click", openForm);
lobbyEmptyNew.addEventListener("click", openForm);
lobbyCancel.addEventListener("click", closeForm);

lobbyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void submit();
});

function fail(text: string, focus?: HTMLElement | null): void {
  toast("bad", "Can't start the lobby yet", text);
  focus?.focus();
}

async function submit(): Promise<void> {
  const current = api;
  if (current === null || lobbySubmit.disabled) return;
  const map = selectedMap();
  if (map === undefined) return fail("Pick a map.", mapSearch);
  if (seats.length === 0) return fail("Add at least one seat.", seatAdd);
  const body: NewSeat[] = [];
  for (const [index, seat] of seats.entries()) {
    const n = index + 1;
    if (seat.kind === "human") {
      const name = seat.name.trim();
      if (name === "") return fail(`Seat ${n} needs the player's name.`, document.getElementById(`seat-${n}-name`));
      const entry: NewSeat = { kind: "human", name, faction: seat.faction, team: seat.team };
      if (seat.uid.trim() !== "") {
        const uid = Number(seat.uid);
        if (!Number.isInteger(uid) || uid <= 0) return fail(`Seat ${n}'s uid is a whole number above 0.`, document.getElementById(`seat-${n}-uid`));
        entry.uid = uid;
      }
      body.push(entry);
    } else {
      body.push({ kind: "ai", ai: seat.ai, faction: seat.faction, team: seat.team });
    }
  }
  if (seats.length > mapPlayers()) return fail(`${map.name ?? map.id} has ${mapPlayers()} start spots.`);
  const blocking = cpuWarningsNow().find((warning) => warning.tone === "bad");
  if (blocking !== undefined) return fail(blocking.text, cpuAuto.checked ? cpuCores : cpuAuto);
  const control = (lobbyForm.querySelector<HTMLInputElement>('input[name="lobby-control"]:checked')?.value ?? "player") === "organiser" ? "organiser" : "player";
  const swr = Math.max(0, Math.round(Number(lobbySwr.value) || 0));
  const minutes = Math.max(1, Math.round(Number(lobbyMinutes.value) || 60));
  const request: NewLobby = {
    name: lobbyName.value.trim() || `${info?.name ?? "Host"} lobby`,
    map: map.id,
    options: chosenOptions(),
    seats: body,
    control,
    start_when_ready: swr,
    lobby_minutes: minutes,
    cpus: cpuAuto.checked ? "auto" : pickedList(),
  };
  if (cpuAuto.checked) request.cores = Math.max(1, Math.round(Number(cpuCores.value) || 1));

  lobbySubmit.disabled = true;
  lobbySubmit.classList.add("busy");
  try {
    const lobby = await current.createLobby(request);
    if (api !== current) return;
    toast("ok", `${lobby.name || lobby.id} is starting`, `On CPU ${(lobby.cpus ?? []).join(", ") || "?"}`);
    createdId = lobby.id;
    if (!lobbies.some((known) => known.id === lobby.id)) lobbies = [...lobbies, lobby];
    picked.clear();
    coresTouched = false;
    lobbyName.value = "";
    closeForm();
    renderLobbies();
    renderHeatmap();
    createdBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
    void poll();
  } catch (error) {
    const why = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error);
    toast("bad", "The host didn't start the lobby", why);
  } finally {
    lobbySubmit.disabled = false;
    lobbySubmit.classList.remove("busy");
  }
}

// ---------------------------------------------------------------- polling, start, stop

async function poll(): Promise<void> {
  const current = api;
  if (current === null || polling) return;
  polling = true;
  try {
    const [host, list] = await Promise.all([current.host(AbortSignal.timeout(REQUEST_MS)), current.lobbies(AbortSignal.timeout(REQUEST_MS))]);
    if (api !== current) return;
    info = host;
    lobbies = list;
    renderAll();
    callbacks?.onHealth(null, false);
    callbacks?.onLobbies(lobbies);
  } catch (error) {
    if (api !== current) return;
    const unauthorized = error instanceof ApiError && error.status === 401;
    callbacks?.onHealth(error instanceof Error ? error.message : String(error), unauthorized);
  } finally {
    polling = false;
  }
}

function renderAll(): void {
  renderLobbies();
  renderMachine();
  renderHeatmap();
}

/** Shows this host: its first answer, then polls every 2 s until `stopHost`. */
export function startHost(hostApi: HostApi, first: HostInfo, events: HostCallbacks): void {
  stopHost();
  api = hostApi;
  callbacks = events;
  info = first;
  renderAll();
  timer = window.setInterval(() => void poll(), POLL_MS);
  void poll();
}

export function stopHost(): void {
  window.clearInterval(timer);
  window.clearTimeout(hintTimer);
  timer = undefined;
  api = null;
  callbacks = null;
  info = null;
  lobbies = [];
  maps = null;
  mapId = "";
  seats = [];
  hint = null;
  hintKey = "";
  createdId = null;
  coresTouched = false;
  picked.clear();
  lobbyCards.clear();
  cells.clear();
  heatSignature = "";
  lobbiesBox.replaceChildren();
  heatmap.replaceChildren();
  hostTiles.replaceChildren();
  createdBox.hidden = true;
  createdBox.dataset.signature = "";
  newLobby.hidden = true;
  lobbyName.value = "";
}
