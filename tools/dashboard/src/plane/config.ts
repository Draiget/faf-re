// The configuration panel (plan WP17.18-WP17.20): a tournament lobby (map, seats, observers, every game setting,
// lobby control, countdown) or open slots (players, count, default settings), and where it goes: Auto or CPUs picked
// on the heatmap, planned by the host on every change with its estimate and warnings before anything starts.

import { ApiError, type Lobby, type MapInfo, type NewLobby, type NewSeat, type NewSlots, type PlanRequest, type SettingKey, type Settings } from "../api.ts";
import { byId, fill, h, icon, isNumber, num, type Child } from "../dom.ts";
import { toast } from "../ui.ts";
import { rate } from "./capacity.ts";
import { joinBlock, warningList, watchBlock } from "./lists.ts";
import { countChanges, FALLBACK_OPTIONS, filterOptions, pruneChosen, renderOptions } from "./options.ts";
import { actions, displayName, emit, on, plural, store } from "./store.ts";

const PLAN_DEBOUNCE_MS = 250;
const REQUEST_MS = 5000;
const MAX_MAP_ITEMS = 150;
const MAX_OBSERVERS = 32;
const MAX_OBSERVER_NAME = 40;

// ---------------------------------------------------------------- elements

const panel = byId<HTMLElement>("plane-config");
const form = byId<HTMLFormElement>("cfg-form");
const kindRadios = [...document.querySelectorAll<HTMLInputElement>('input[name="cfg-kind"]')];
const nameInput = byId<HTMLInputElement>("cfg-name");
const maxPlayers = byId<HTMLSelectElement>("cfg-max-players");
const slotCount = byId<HTMLInputElement>("cfg-count");
const slotKm = byId<HTMLSelectElement>("cfg-km");
const slotReopen = byId<HTMLInputElement>("cfg-reopen");
const mapSearch = byId<HTMLInputElement>("cfg-map-search");
const mapList = byId<HTMLElement>("cfg-map-list");
const mapCount = byId<HTMLElement>("cfg-map-count");
const mapSelected = byId<HTMLElement>("cfg-map-selected");
const seatRows = byId<HTMLElement>("cfg-seats");
const seatAdd = byId<HTMLButtonElement>("cfg-seat-add");
const seatCount = byId<HTMLElement>("cfg-seat-count");
const observerRows = byId<HTMLElement>("cfg-observers");
const observerAdd = byId<HTMLButtonElement>("cfg-observer-add");
const observerCount = byId<HTMLElement>("cfg-observer-count");
const observerDelayField = byId<HTMLElement>("cfg-observer-delay-field");
const observerDelay = byId<HTMLInputElement>("cfg-observer-delay");
const settingsBox = byId<HTMLElement>("cfg-settings");
const settingsMeta = byId<HTMLElement>("cfg-settings-meta");
const settingsNote = byId<HTMLElement>("cfg-settings-note");
const settingsFilter = byId<HTMLInputElement>("cfg-settings-filter");
const settingsReset = byId<HTMLButtonElement>("cfg-settings-reset");
const swr = byId<HTMLInputElement>("cfg-swr");
const minutes = byId<HTMLInputElement>("cfg-minutes");
const autoSwitch = byId<HTMLInputElement>("cfg-auto");
const coresField = byId<HTMLElement>("cfg-cores-field");
const coresInput = byId<HTMLInputElement>("cfg-cores");
const pickedSummary = byId<HTMLElement>("cfg-picked");
const estimateBox = byId<HTMLElement>("cfg-estimate");
const warningsBox = byId<HTMLElement>("cfg-warnings");
const forceField = byId<HTMLElement>("cfg-force-field");
const forceBox = byId<HTMLInputElement>("cfg-force");
const submitButton = byId<HTMLButtonElement>("cfg-submit");
const submitNote = byId<HTMLElement>("cfg-submit-note");
const createdBox = byId<HTMLElement>("plane-created");

// ---------------------------------------------------------------- state

type Kind = "lobby" | "slots";
let kind: Kind = "lobby";
let maps: MapInfo[] | null = null;
let mapsLoading = false;
let mapId = "";
const settingsCache = new Map<string, Settings>();
let settings: Settings | null = null;
/** False when the host answers 404 for /api/v1/settings (before WP17.20): the usual options are shown instead. */
let settingsSupported = true;
/** The operator's changes: only values that differ from their defaults are sent. */
const chosen = new Map<string, SettingKey>();
let coresTouched = false;
let planTimer: number | undefined;
let planSeq = 0;
let planError = "";
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

interface ObserverDraft {
  name: string;
  referee: boolean;
}
let observers: ObserverDraft[] = [];

// ---------------------------------------------------------------- kind

function setKind(next: Kind): void {
  kind = next;
  panel.dataset.kind = kind;
  for (const radio of kindRadios) radio.checked = radio.value === kind;
  for (const section of panel.querySelectorAll<HTMLElement>("[data-for]")) section.hidden = section.dataset.for !== kind;
  submitButton.textContent = kind === "lobby" ? "Create the lobby" : "Create the slots";
  if (nameInput.value.trim() === "" || nameInput.dataset.auto === "1") {
    nameInput.value = kind === "lobby" ? `${store.info?.name ?? "Host"} lobby ${store.lobbies.length + 1}` : "Public games";
    nameInput.dataset.auto = "1";
  }
  void loadSettings();
  if (kind === "lobby") void loadMaps();
  schedulePlan();
}

for (const radio of kindRadios) radio.addEventListener("change", () => radio.checked && setKind(radio.value === "slots" ? "slots" : "lobby"));
nameInput.addEventListener("input", () => (nameInput.dataset.auto = "0"));
maxPlayers.replaceChildren(...Array.from({ length: 15 }, (_, i) => h("option", { value: String(i + 2) }, `${i + 2} players`)));
maxPlayers.value = "8";
for (const input of [maxPlayers, slotKm]) input.addEventListener("change", schedulePlan);
slotCount.addEventListener("input", () => renderPlan());

actions.configure = (next: Kind): void => {
  setKind(next);
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
  nameInput.focus({ preventScroll: true });
};

// ---------------------------------------------------------------- maps

function selectedMap(): MapInfo | undefined {
  return maps?.find((map) => map.id === mapId);
}

function mapPlayers(): number {
  const players = selectedMap()?.players;
  return isNumber(players) && players > 0 ? players : 16;
}

async function loadMaps(): Promise<void> {
  const api = store.api;
  if (api === null || mapsLoading || maps !== null) return;
  mapsLoading = true;
  mapList.replaceChildren(h("p", { class: "empty" }, "Loading the host's maps…"));
  try {
    const list = await api.maps(AbortSignal.timeout(REQUEST_MS * 2));
    if (store.api !== api) return;
    maps = list;
    if (mapId === "" && list.length > 0) {
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
  const current = selectedMap();
  if (current !== undefined && !shown.includes(current)) shown.unshift(current);
  mapCount.textContent = matching.length === maps.length ? `${maps.length} maps` : `${matching.length} of ${maps.length} maps`;
  if (shown.length === 0) {
    mapList.replaceChildren(h("p", { class: "empty" }, "No map matches the search."));
    return;
  }
  mapList.replaceChildren(
    ...shown.map((map) => {
      const radio = h("input", { type: "radio", name: "cfg-map", value: map.id, class: "sr-only" });
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
  void loadSettings();
  schedulePlan();
}

// ---------------------------------------------------------------- settings catalog

const FALLBACK = FALLBACK_OPTIONS;

function settingsKey(): string {
  return kind === "lobby" ? mapId : "";
}

async function loadSettings(): Promise<void> {
  const api = store.api;
  if (api === null) return;
  if (kind === "lobby" && mapId === "") return;
  const key = settingsKey();
  const cached = settingsCache.get(key);
  if (cached !== undefined) {
    useSettings(cached);
    return;
  }
  if (!settingsSupported) {
    useSettings({ options: FALLBACK, ai: [], map_options: [] });
    return;
  }
  settingsMeta.textContent = "loading…";
  try {
    const answer = await api.settings(key === "" ? undefined : key, AbortSignal.timeout(REQUEST_MS));
    if (store.api !== api) return;
    settingsCache.set(key, answer);
    if (key === settingsKey()) useSettings(answer);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404 && !/map/i.test(error.message)) {
      settingsSupported = false;
      useSettings({ options: FALLBACK, ai: [], map_options: [] });
      return;
    }
    settingsMeta.textContent = "";
    fill(settingsBox, h("p", { class: "empty" }, `The settings didn't load: ${error instanceof Error ? error.message : String(error)}`));
  }
}

function useSettings(next: Settings): void {
  settings = next;
  // Changes that still mean something on this map stay; the rest (another map's options) go.
  pruneChosen(chosen, next);
  settingsNote.hidden = settingsSupported;
  renderSettings();
  renderSeats();
}

function renderSettings(): void {
  if (settings === null) return;
  renderOptions(settingsBox, settings, kind === "lobby" ? (selectedMap()?.name ?? "this map") : null, { chosen, onChange: renderSettingsCounts });
  renderSettingsCounts();
  applySettingsFilter();
}

function renderSettingsCounts(): void {
  const total = countChanges(settingsBox);
  const count = (settings?.options.length ?? 0) + (kind === "lobby" ? (settings?.map_options.length ?? 0) : 0);
  settingsMeta.textContent = total === 0 ? `${count} settings, all default` : `${count} settings · ${total} changed`;
  settingsReset.hidden = total === 0;
}

function applySettingsFilter(): void {
  filterOptions(settingsBox, settingsFilter.value);
}

settingsFilter.addEventListener("input", applySettingsFilter);
settingsReset.addEventListener("click", () => {
  chosen.clear();
  renderSettings();
});

// ---------------------------------------------------------------- seats

const FACTIONS: [number, string][] = [
  [1, "UEF"],
  [2, "Aeon"],
  [3, "Cybran"],
  [4, "Seraphim"],
  [5, "Random"],
];

function aiChoices(): [string, string][] {
  const catalog = settings?.ai ?? [];
  if (catalog.length > 0) return catalog.map((ai): [string, string] => [ai.key, `${ai.name ?? ai.key}${isNumber(ai.rating) ? ` · ${ai.rating}` : ""}`]);
  const list = store.info?.ai?.filter((name) => typeof name === "string" && name !== "") ?? [];
  return (list.length > 0 ? list : ["adaptive"]).map((name): [string, string] => [name, name]);
}

function newSeat(index: number, seatKind: "human" | "ai"): SeatDraft {
  const ai = aiChoices().map(([key]) => key);
  return { kind: seatKind, name: "", uid: "", ai: ai.includes("adaptive") ? "adaptive" : (ai[0] ?? "adaptive"), faction: 5, team: 2 + (index % 2) };
}

function selectField(id: string, label: string, choices: [string, string][], value: string, onChange: (value: string) => void): HTMLElement {
  const node = h("select", { id }, ...choices.map(([choice, text]) => h("option", { value: choice }, text)));
  node.value = choices.some(([choice]) => choice === value) ? value : (choices[0]?.[0] ?? "");
  node.addEventListener("change", () => onChange(node.value));
  return h("div", { class: "field" }, h("label", { for: id }, label), node);
}

function renderSeats(): void {
  const limit = mapPlayers();
  const ais = aiChoices();
  seatRows.replaceChildren(
    ...seats.map((seat, index) => {
      const n = index + 1;
      if (seat.kind === "ai" && !ais.some(([key]) => key === seat.ai)) seat.ai = ais[0]?.[0] ?? seat.ai;
      const who: HTMLElement[] = [];
      if (seat.kind === "human") {
        const name = h("input", { id: `cfg-seat-${n}-name`, placeholder: "player name", spellcheck: "false", autocomplete: "off" });
        name.value = seat.name;
        name.addEventListener("input", () => (seat.name = name.value));
        const uid = h("input", { id: `cfg-seat-${n}-uid`, type: "number", inputmode: "numeric", placeholder: "auto" });
        uid.value = seat.uid;
        uid.addEventListener("input", () => (seat.uid = uid.value));
        who.push(h("div", { class: "field grow" }, h("label", { for: `cfg-seat-${n}-name` }, "Name"), name), h("div", { class: "field uid" }, h("label", { for: `cfg-seat-${n}-uid` }, "uid ", h("span", { class: "dim" }, "(optional)")), uid));
      } else {
        const personality = selectField(`cfg-seat-${n}-ai`, "AI", ais, seat.ai, (value) => (seat.ai = value));
        personality.classList.add("grow");
        who.push(personality);
      }
      const remove = h("button", { type: "button", class: "btn ghost small seat-remove", "aria-label": `Remove seat ${n}`, title: "Remove this seat" }, icon("trash", "icon tiny"));
      remove.disabled = seats.length <= 1;
      remove.addEventListener("click", () => {
        seats.splice(index, 1);
        renderSeats();
        schedulePlan();
      });
      return h(
        "fieldset",
        { class: `seat-row kind-${seat.kind}` },
        h("legend", {}, `Seat ${n}`, h("span", { class: "dim" }, ` · start spot ${n}`)),
        h(
          "div",
          { class: "seat-fields" },
          selectField(`cfg-seat-${n}-kind`, "Kind", [["human", "Human"], ["ai", "AI"]], seat.kind, (value) => {
            seat.kind = value === "ai" ? "ai" : "human";
            renderSeats();
          }),
          ...who,
          selectField(`cfg-seat-${n}-faction`, "Faction", FACTIONS.map(([value, label]): [string, string] => [String(value), label]), String(seat.faction), (value) => (seat.faction = Number(value))),
          selectField(`cfg-seat-${n}-team`, "Team", [["1", "No team"], ...[1, 2, 3, 4, 5, 6, 7, 8].map((t): [string, string] => [String(t + 1), `Team ${t}`])], String(seat.team), (value) => (seat.team = Number(value))),
        ),
        remove,
      );
    }),
  );
  seatCount.textContent = `${seats.length} of ${limit}`;
  seatAdd.disabled = seats.length >= limit;
}

seatAdd.addEventListener("click", () => {
  if (seats.length >= mapPlayers()) return;
  seats.push(newSeat(seats.length, seats.some((seat) => seat.kind === "human") ? "ai" : "human"));
  renderSeats();
  schedulePlan();
  byId<HTMLSelectElement>(`cfg-seat-${seats.length}-kind`).focus();
});

// ---------------------------------------------------------------- observers

function renderObservers(): void {
  observerRows.replaceChildren(
    ...observers.map((observer, index) => {
      const n = index + 1;
      const name = h("input", { id: `cfg-observer-${n}-name`, maxlength: MAX_OBSERVER_NAME, placeholder: `Observer ${n}`, spellcheck: "false", autocomplete: "off" });
      name.value = observer.name;
      name.addEventListener("input", () => (observer.name = name.value));
      const referee = h("input", { id: `cfg-observer-${n}-referee`, type: "checkbox" });
      referee.checked = observer.referee;
      referee.addEventListener("change", () => {
        observer.referee = referee.checked;
        renderObserverDelay();
      });
      const remove = h("button", { type: "button", class: "btn ghost small", "aria-label": `Remove observer ${n}`, title: "Remove this observer" }, icon("trash", "icon tiny"));
      remove.addEventListener("click", () => {
        observers.splice(index, 1);
        renderObservers();
        (document.getElementById(`cfg-observer-${Math.min(n, observers.length)}-name`) ?? observerAdd).focus();
      });
      return h(
        "div",
        { class: "observer-row", role: "group", "aria-label": `Observer ${n}` },
        h("div", { class: "field grow" }, h("label", { for: `cfg-observer-${n}-name` }, `Observer ${n}`), name),
        h("label", { class: "check", for: `cfg-observer-${n}-referee` }, referee, h("span", {}, "Referee, no delay")),
        remove,
      );
    }),
  );
  observerCount.textContent = observers.length === 0 ? "none" : `${observers.length} of ${MAX_OBSERVERS}`;
  observerAdd.disabled = observers.length >= MAX_OBSERVERS;
  renderObserverDelay();
}

function renderObserverDelay(): void {
  observerDelayField.hidden = !observers.some((observer) => !observer.referee);
}

observerAdd.addEventListener("click", () => {
  if (observers.length >= MAX_OBSERVERS) return;
  observers.push({ name: "", referee: false });
  renderObservers();
  byId<HTMLInputElement>(`cfg-observer-${observers.length}-name`).focus();
});

// ---------------------------------------------------------------- placement and the plan

function players(): number {
  return kind === "lobby" ? Math.max(1, seats.length) : Number(maxPlayers.value) || 8;
}

function km(): number {
  if (kind === "slots") return Number(slotKm.value) || 20;
  const size = selectedMap()?.km;
  return isNumber(size) && size > 0 ? size : 20;
}

function planRequest(): PlanRequest {
  const request: PlanRequest = { players: players(), km: km() };
  if (!store.auto && store.picked.size > 0) request.cpus = [...store.picked].sort((a, b) => a - b);
  else request.cores = coresTouched ? Math.max(1, Math.round(Number(coresInput.value) || 1)) : 0;
  return request;
}

function schedulePlan(): void {
  window.clearTimeout(planTimer);
  if (store.api === null) return;
  if (kind === "lobby" && selectedMap() === undefined) return;
  store.planning = true;
  renderPlan();
  planTimer = window.setTimeout(() => void runPlan(), PLAN_DEBOUNCE_MS);
}

async function runPlan(): Promise<void> {
  const api = store.api;
  if (api === null) return;
  const seq = ++planSeq;
  try {
    const plan = await api.plan(planRequest(), AbortSignal.timeout(REQUEST_MS));
    if (seq !== planSeq || store.api !== api) return;
    store.plan = plan;
    planError = "";
    if (!coresTouched && store.auto && isNumber(plan.estimate.suggested_cores)) coresInput.value = String(Math.max(1, plan.estimate.suggested_cores));
  } catch (error) {
    if (seq !== planSeq) return;
    store.plan = null;
    planError = error instanceof Error ? error.message : String(error);
  } finally {
    if (seq === planSeq) {
      store.planning = false;
      // "Start anyway" answers this plan's error; once it fits, it no longer applies.
      if (store.plan?.fits !== false) forceBox.checked = false;
      renderPlan();
      emit("plan");
    }
  }
}

function renderPicked(): void {
  autoSwitch.checked = store.auto;
  coresField.hidden = !store.auto;
  pickedSummary.hidden = store.auto;
  const list = [...store.picked].sort((a, b) => a - b);
  fill(
    pickedSummary,
    list.length === 0
      ? h("span", { class: "dim" }, "Click CPUs on the heatmap to pick them.")
      : h("span", {}, "Picked: ", h("strong", {}, `CPU ${list.join(", ")}`), h("span", { class: "dim" }, ` (${plural(list.length, "CPU")})`)),
  );
}

function stat(label: string, value: Child, sub?: Child): HTMLElement {
  return h("div", { class: "est" }, h("span", { class: "est-label" }, label), h("span", { class: "est-value" }, value), sub === undefined ? null : h("span", { class: "est-sub dim" }, sub));
}

function renderPlan(): void {
  renderPicked();
  const plan = store.plan;
  if (planError !== "") {
    fill(estimateBox, h("p", { class: "form-error" }, `The host couldn't plan it: ${planError}`));
    warningsBox.replaceChildren();
  } else if (plan === null) {
    fill(estimateBox, h("p", { class: "dim small" }, kind === "lobby" && selectedMap() === undefined ? "Pick a map to see what it needs." : "Planning…"));
    warningsBox.replaceChildren();
  } else {
    const est = plan.estimate;
    const basis = est.basis ?? "";
    fill(
      estimateBox,
      h(
        "div",
        { class: `estimate${store.planning ? " stale" : ""}`, title: basis },
        stat("Cores", isNumber(est.suggested_cores) ? `${est.suggested_cores} suggested` : "–", `mean ${num(est.mean_cores, 2)} · worst ${num(est.worst_cores, 2)}`),
        stat("Memory", isNumber(est.memory_mb) ? `~${est.memory_mb} MB` : "–"),
        stat("Upload", isNumber(est.upload_kbps) ? `~${rate(est.upload_kbps)}` : "–", "from the server"),
        stat("Per player", isNumber(est.min_connection_kbps) ? `≥ ${rate(est.min_connection_kbps)}` : "–", "minimum connection"),
      ),
      h(
        "p",
        { class: "plan-line" },
        h("span", { class: `chip tone-${plan.fits ? "ok" : "bad"}` }, plan.fits ? "Fits" : "Doesn't fit"),
        " ",
        plan.cpus.length === 0 ? h("span", { class: "dim" }, "no CPUs") : h("span", {}, `${store.auto ? "Auto picks" : "On"} CPU ${plan.cpus.join(", ")}`),
        plan.nodes.length === 0 ? "" : h("span", { class: "dim" }, ` · ${plan.nodes.length > 1 ? "nodes" : "node"} ${plan.nodes.join(", ")}`),
        kind === "slots" && (Number(slotCount.value) || 1) > 1 ? h("span", { class: "dim" }, ` · for each of ${Number(slotCount.value) || 1} slots`) : "",
      ),
      basis === "" ? null : h("details", { class: "hint-basis" }, h("summary", {}, "How this is estimated"), h("p", {}, basis)),
    );
    const extra = kind === "slots" && !store.auto && (Number(slotCount.value) || 1) > 1 ? [{ code: "same_cpus", severity: "warn", text: "With CPUs picked by hand, every slot gets the same CPUs: use Auto to spread them." }] : [];
    const all = [...plan.warnings, ...extra];
    fill(warningsBox, all.length === 0 ? h("p", { class: "ok-line small" }, icon("check", "icon tiny"), "No warnings: it fits where it's planned.") : warningList(all));
  }
  const blocked = plan !== null && !plan.fits;
  forceField.hidden = !blocked;
  submitButton.disabled = store.planning || (blocked && !forceBox.checked);
  submitNote.textContent = store.planning ? "Planning…" : blocked && !forceBox.checked ? "The plan has an error: tick “Start anyway” to create it regardless." : "";
}

autoSwitch.addEventListener("change", () => {
  store.auto = autoSwitch.checked;
  if (store.auto && store.picked.size > 0) {
    store.picked.clear();
    emit("picked");
  }
  renderPicked();
  schedulePlan();
});
coresInput.addEventListener("input", () => {
  coresTouched = true;
  schedulePlan();
});
forceBox.addEventListener("change", renderPlan);

on("picked", () => {
  if (store.picked.size > 0) store.auto = false;
  renderPicked();
  schedulePlan();
});

// ---------------------------------------------------------------- submit

function fail(text: string, focus?: HTMLElement | null): void {
  toast("bad", kind === "lobby" ? "Can't create the lobby yet" : "Can't create the slots yet", text);
  focus?.focus();
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void submit();
});

function placementFields(): { cpus: number[] | "auto"; cores?: number } {
  if (!store.auto && store.picked.size > 0) return { cpus: [...store.picked].sort((a, b) => a - b) };
  // What the heatmap showed is what starts: the planned CPUs, not a new auto pick the load may have moved since.
  // Several slots at once stay on auto, so the host gives each its own.
  const several = kind === "slots" && (Number(slotCount.value) || 1) > 1;
  const planned = store.plan?.cpus ?? [];
  if (!several && planned.length > 0) return { cpus: [...planned] };
  const cores = Math.max(1, Math.round(Number(coresInput.value) || store.plan?.estimate.suggested_cores || 1));
  return { cpus: "auto", cores };
}

async function submit(): Promise<void> {
  const api = store.api;
  if (api === null || submitButton.disabled) return;
  const force = store.plan !== null && !store.plan.fits && forceBox.checked;
  const options = Object.fromEntries(chosen);
  const name = nameInput.value.trim();
  const lobbyMinutes = Math.max(1, Math.round(Number(minutes.value) || 60));
  if (!store.auto && store.picked.size === 0) return fail("Pick CPUs on the heatmap, or switch Auto on.", autoSwitch);

  if (kind === "slots") {
    const count = Math.round(Number(slotCount.value) || 1);
    if (count < 1 || count > 16) return fail("Make 1 to 16 slots at once.", slotCount);
    const placement = placementFields();
    const request: NewSlots = { name: name || "Open slot", max_players: Number(maxPlayers.value) || 8, km: km(), lobby_minutes: lobbyMinutes, count, options, reopen: slotReopen.checked };
    if (placement.cpus === "auto") request.cores = placement.cores;
    else request.cpus = placement.cpus;
    if (force) request.force = true;
    await send(async () => {
      const made = await api.createSlots(request);
      toast("ok", `${plural(made.length, "slot")} open`, made.length > 0 ? `Claim codes are in the list; on CPU ${made.map((slot) => (slot.cpus ?? []).join("+")).join(", ")}` : "");
    });
    return;
  }

  const map = selectedMap();
  if (map === undefined) return fail("Pick a map.", mapSearch);
  if (seats.length === 0) return fail("Add at least one seat.", seatAdd);
  const body: NewSeat[] = [];
  for (const [index, seat] of seats.entries()) {
    const n = index + 1;
    if (seat.kind === "human") {
      const player = seat.name.trim();
      if (player === "") return fail(`Seat ${n} needs the player's name.`, document.getElementById(`cfg-seat-${n}-name`));
      const entry: NewSeat = { kind: "human", name: player, faction: seat.faction, team: seat.team };
      if (seat.uid.trim() !== "") {
        const uid = Number(seat.uid);
        if (!Number.isInteger(uid) || uid <= 0) return fail(`Seat ${n}'s uid is a whole number above 0.`, document.getElementById(`cfg-seat-${n}-uid`));
        entry.uid = uid;
      }
      body.push(entry);
    } else {
      body.push({ kind: "ai", ai: seat.ai, faction: seat.faction, team: seat.team });
    }
  }
  if (!body.some((seat) => seat.kind === "human")) return fail("A lobby needs a human seat: an all-AI game has nobody to host or watch it.", seatAdd);
  const control = (form.querySelector<HTMLInputElement>('input[name="cfg-control"]:checked')?.value ?? "player") === "organiser" ? "organiser" : "player";
  const request: NewLobby = {
    name: name || `${store.info?.name ?? "Host"} lobby`,
    map: map.id,
    options,
    seats: body,
    control,
    start_when_ready: Math.max(0, Math.round(Number(swr.value) || 0)),
    lobby_minutes: lobbyMinutes,
    ...placementFields(),
  };
  if (observers.length > 0) {
    for (const [index, observer] of observers.entries()) {
      if (observer.name.trim().length > MAX_OBSERVER_NAME) return fail(`Observer ${index + 1}'s name is longer than ${MAX_OBSERVER_NAME} characters.`, document.getElementById(`cfg-observer-${index + 1}-name`));
    }
    let delay = 0;
    if (observers.some((observer) => !observer.referee)) {
      delay = Number(observerDelay.value || "0");
      if (!Number.isFinite(delay) || delay < 0 || delay > 3600) return fail("The observers' delay is 0 to 3600 seconds.", observerDelay);
    }
    request.observers = observers.map((observer) => (observer.referee ? { name: observer.name.trim(), referee: true } : { name: observer.name.trim() }));
    request.observer_delay_seconds = delay;
  }
  if (force) request.force = true;
  await send(async () => {
    const lobby = await api.createLobby(request);
    toast("ok", `${displayName(lobby)} is starting`, `On CPU ${(lobby.cpus ?? []).join(", ") || "?"}${(lobby.nodes ?? []).length > 0 ? `, node ${(lobby.nodes ?? []).join(", ")}` : ""}`);
    createdId = lobby.id;
    if (!store.lobbies.some((known) => known.id === lobby.id)) store.lobbies = [...store.lobbies, lobby];
    observers = [];
    observerDelay.value = "0";
    renderObservers();
    renderCreated();
    emit("lists");
    createdBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
}

async function send(work: () => Promise<void>): Promise<void> {
  submitButton.disabled = true;
  submitButton.classList.add("busy");
  try {
    await work();
    store.picked.clear();
    store.auto = true;
    coresTouched = false;
    forceBox.checked = false;
    nameInput.value = "";
    nameInput.dataset.auto = "1";
    setKind(kind);
    emit("picked");
    actions.refresh();
  } catch (error) {
    toast("bad", kind === "lobby" ? "The host didn't create the lobby" : "The host didn't create the slots", error instanceof Error ? error.message : String(error));
  } finally {
    submitButton.classList.remove("busy");
    renderPlan();
  }
}

// ---------------------------------------------------------------- the created callout

function renderCreated(): void {
  const lobby: Lobby | undefined = createdId === null ? undefined : store.lobbies.find((candidate) => candidate.id === createdId);
  if (lobby === undefined) {
    if (createdId === null) createdBox.hidden = true;
    return;
  }
  const signature = JSON.stringify([lobby.state, lobby.name, (lobby.seats ?? []).map((seat) => seat.join), (lobby.observers ?? []).map((observer) => observer.watch)]);
  if (createdBox.dataset.signature === signature) return;
  createdBox.dataset.signature = signature;
  const dismiss = h("button", { type: "button", class: "btn ghost small" }, "Dismiss");
  dismiss.addEventListener("click", () => {
    createdId = null;
    createdBox.hidden = true;
    createdBox.dataset.signature = "";
  });
  const phrase: Record<string, string> = { starting: "is starting", lobby: "is open", game: "is in game", ended: "has ended", failed: "failed", stopped: "was stopped" };
  fill(
    createdBox,
    h(
      "div",
      { class: "created-head" },
      h("span", { class: "created-icon" }, icon("check")),
      h("div", {}, h("strong", {}, `${displayName(lobby)} ${phrase[lobby.state] ?? `is ${lobby.state}`}`), h("span", { class: "dim" }, ` · ${lobby.map?.name ?? ""} · CPU ${(lobby.cpus ?? []).join(", ")}`)),
    ),
    joinBlock(lobby),
    (lobby.observers ?? []).length === 0 ? null : watchBlock(lobby),
    h("div", { class: "lobby-actions" }, h("a", { class: "btn primary small", href: `#/lobby/${encodeURIComponent(lobby.id)}` }, "Open the lobby"), dismiss),
  );
  createdBox.hidden = false;
}

on("lists", renderCreated);
let hostAiSignature = "";
on("host", () => {
  // Without a settings catalog the seats' AIs come from the host: redraw them only when that list changes.
  const signature = (store.info?.ai ?? []).join(",");
  if (signature !== hostAiSignature) {
    hostAiSignature = signature;
    if (seats.length > 0 && (settings?.ai ?? []).length === 0) renderSeats();
  }
});
on("lists", () => {
  // Lobbies and slots coming or going change what Auto picks.
  const signature = [...store.lobbies.map((lobby) => `${lobby.id}:${lobby.state}`), ...store.slots.map((slot) => `${slot.id}:${slot.state}`)].join(",");
  if (signature !== listsSignature) {
    listsSignature = signature;
    schedulePlan();
  }
});
let listsSignature = "";

// ---------------------------------------------------------------- start, stop

export function startConfig(): void {
  seats = [newSeat(0, "human"), newSeat(1, "ai")];
  observers = [];
  renderSeats();
  renderObservers();
  setKind("lobby");
}

export function resetConfig(): void {
  window.clearTimeout(planTimer);
  planSeq += 1;
  maps = null;
  mapsLoading = false;
  mapId = "";
  settingsCache.clear();
  settings = null;
  settingsSupported = true;
  chosen.clear();
  coresTouched = false;
  planError = "";
  createdId = null;
  seats = [];
  observers = [];
  listsSignature = "";
  hostAiSignature = "";
  nameInput.value = "";
  nameInput.dataset.auto = "1";
  settingsBox.replaceChildren();
  mapList.replaceChildren();
  createdBox.hidden = true;
  createdBox.dataset.signature = "";
}
