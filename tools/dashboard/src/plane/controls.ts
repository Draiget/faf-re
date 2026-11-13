// A lobby's control ops (docs/SERVER_DASHBOARD.md, "A lobby's page"): start now, the lobby's game settings (set_options)
// as the settings form with the catalog's keys and values, pause and resume, end with results, the player ops (eject,
// set player, substitute, timeouts) on the seat picked on its card, and the handshake allowlist. lobby.ts owns the
// lobby and gives this module what it needs through `bindControls`.

import { ApiError, type Answer, type Lobby, type Seat, type ServerApi, type SettingKey, type SettingOption, type Settings, type Status } from "../api.ts";
import { byId, h } from "../dom.ts";
import { confirmAction, toast } from "../ui.ts";
import { countChanges, filterOptions, renderOptions, sameKey } from "./options.ts";
import { store } from "./store.ts";

export interface ControlContext {
  api(): ServerApi | null;
  status(): Status | null;
  lobby(): Lobby | undefined;
  nameOf(uid: unknown): string;
  /** Ask the lobby again now. */
  poll(): void;
  /** Pick a seat for the player ops (null: none); the seat cards follow. */
  selectSeat(uid: number | null): void;
  hasSeat(uid: number): boolean;
}

let ctx: ControlContext | null = null;

export function bindControls(context: ControlContext): void {
  ctx = context;
}

const controls = byId<HTMLFieldSetElement>("controls");
const controlsMeta = byId<HTMLElement>("controls-meta");
const seatPick = byId<HTMLSelectElement>("seat-pick");
const playerUid = byId<HTMLInputElement>("player-uid");

// ---------------------------------------------------------------- the seat picker

export function renderSeatPicker(seats: Seat[], selected: number | null): void {
  const signature = seats.map((seat) => `${seat.uid}:${seat.name}`).join("|");
  if (seatPick.dataset.signature !== signature) {
    seatPick.dataset.signature = signature;
    seatPick.replaceChildren(
      h("option", { value: "" }, seats.length === 0 ? "No seats" : "Choose a seat"),
      ...seats.map((seat) => h("option", { value: String(seat.uid) }, `${seat.name || "(no name)"} · uid ${seat.uid}`)),
    );
  }
  seatPick.value = selected !== null && seats.some((seat) => seat.uid === selected) ? String(selected) : "";
}

/** Shows the picked seat in the picker and the uid field. */
export function showSelection(uid: number | null): void {
  seatPick.value = uid === null ? "" : String(uid);
  if (uid !== null) playerUid.value = String(uid);
}

seatPick.addEventListener("change", () => {
  ctx?.selectSeat(seatPick.value === "" ? null : Number(seatPick.value));
});
playerUid.addEventListener("input", () => {
  const uid = Number(playerUid.value);
  const known = playerUid.value !== "" && ctx?.hasSeat(uid) === true;
  ctx?.selectSeat(known ? uid : null);
});

/** The controls follow the lobby's phase: the other phase's groups dim. */
export function showPhase(status: Status): void {
  for (const group of controls.querySelectorAll<HTMLElement>(".group[data-phase]")) {
    group.classList.toggle("off-phase", group.dataset.phase !== status.phase);
  }
  controlsMeta.textContent = status.phase === "game" ? "in game" : status.phase === "lobby" ? "in the lobby" : status.phase;
  renderOptionsState();
}

export function enableControls(on: boolean, why = "waiting for the lobby"): void {
  controls.disabled = !on;
  if (!on) controlsMeta.textContent = why;
}

// ---------------------------------------------------------------- the lobby's game settings

const optionsGroup = byId<HTMLElement>("lobby-options-group");
const optionsMeta = byId<HTMLElement>("lobby-options-meta");
const optionsNote = byId<HTMLElement>("lobby-options-note");
const optionsForm = byId<HTMLElement>("lobby-options-form");
const optionsBox = byId<HTMLElement>("lobby-options");
const optionsFilter = byId<HTMLInputElement>("lobby-options-filter");
const optionsRevert = byId<HTMLButtonElement>("lobby-options-revert");
const optionsApply = byId<HTMLButtonElement>("lobby-options-apply");
const optionsRaw = byId<HTMLElement>("lobby-options-raw");

/** Options the match file fixes before the lobby opens: the server refuses them (SWITCHES.md, `set_options`). */
const FIXED = new Set(["ScenarioFile", "GameSpeed", "TeamLock"]);
const REQUEST_MS = 5000;

let optionsLobby: string | null = null;
let catalogMap: string | null = null;
let catalog: Settings | null = null;
/** "missing": the host has no settings catalog (404); "failed": it didn't load. Both fall back to the text box. */
let catalogState: "idle" | "loading" | "ok" | "missing" | "failed" = "idle";
let catalogError = "";
const catalogCache = new Map<string, Settings>();
/** The lobby's values as far as the page knows: what it started with, then every `options` event. */
const current = new Map<string, SettingKey>();
/** The form's values that differ from their defaults. */
const chosen = new Map<string, SettingKey>();
let edited = false;
let applying = false;

function shownSettings(): Settings | null {
  if (catalog === null) return null;
  return { ...catalog, options: catalog.options.filter((option) => !FIXED.has(option.key)) };
}

function allOptions(): SettingOption[] {
  const settings = shownSettings();
  return settings === null ? [] : [...settings.options, ...settings.map_options];
}

/** What would change: each option whose form value differs from the lobby's. */
function pending(): { option: SettingOption; value: SettingKey }[] {
  const out: { option: SettingOption; value: SettingKey }[] = [];
  for (const option of allOptions()) {
    const wanted = chosen.get(option.key) ?? option.default;
    const now = current.get(option.key) ?? option.default;
    if (wanted !== undefined && wanted !== null && !sameKey(wanted, now ?? undefined)) out.push({ option, value: wanted });
  }
  return out;
}

/** Why the settings can't be changed now, or "" when they can. */
function blockedReason(): string {
  const lobby = ctx?.lobby();
  const status = ctx?.status();
  if (lobby?.control === "player") return "A player hosts this lobby: its game options are theirs, set in their lobby screen. They're shown here as the lobby started.";
  if (status !== null && status !== undefined && status.phase !== "lobby") return "The game has started: settings change in the lobby only.";
  return "";
}

function renderOptionsForm(): void {
  const settings = shownSettings();
  if (settings === null) return;
  chosen.clear();
  for (const option of [...settings.options, ...settings.map_options]) {
    const value = current.get(option.key);
    if (value !== undefined && !sameKey(value, option.default ?? undefined)) chosen.set(option.key, value);
  }
  edited = false;
  const map = ctx?.lobby()?.map;
  renderOptions(optionsBox, settings, map?.name ?? map?.id ?? "this map", { chosen, idPrefix: "lobby-set-", onChange: onOptionsEdit });
  filterOptions(optionsBox, optionsFilter.value);
  renderOptionsState();
}

function onOptionsEdit(): void {
  edited = true;
  renderOptionsState();
}

function renderOptionsState(): void {
  const showForm = catalogState === "ok" || catalogState === "loading" || catalogState === "idle";
  // Once the game runs the settings can't change: the note says so and the form folds away.
  const phase = ctx?.status()?.phase;
  const inGame = phase !== undefined && phase !== "lobby";
  optionsForm.hidden = !showForm || inGame;
  optionsRaw.hidden = showForm || inGame;
  const why = blockedReason();
  let note = why;
  if (catalogState === "missing") note = [why, "This host doesn't list its settings: type them as Key=Value."].filter((part) => part !== "").join(" ");
  if (catalogState === "failed") note = [why, `The settings didn't load (${catalogError}): type them as Key=Value.`].filter((part) => part !== "").join(" ");
  optionsNote.textContent = note;
  optionsNote.hidden = note === "";
  optionsGroup.classList.toggle("locked", why !== "");
  optionsForm.inert = why !== "" && showForm;

  if (catalogState === "loading" || catalogState === "idle") {
    optionsMeta.textContent = "loading…";
    optionsApply.disabled = true;
    optionsApply.textContent = "Apply";
    optionsRevert.hidden = true;
    return;
  }
  if (!showForm) {
    optionsMeta.textContent = "";
    return;
  }
  const changes = pending();
  const changedFromDefault = countChanges(optionsBox);
  for (const field of optionsBox.querySelectorAll<HTMLElement>(".setting")) {
    const key = field.querySelector<HTMLSelectElement>("select")?.dataset.key ?? "";
    field.classList.toggle("pending", changes.some((change) => change.option.key === key));
  }
  optionsMeta.textContent = changes.length > 0 ? `${changes.length} to apply` : changedFromDefault > 0 ? `${changedFromDefault} not default` : "all default";
  optionsApply.textContent = changes.length === 0 ? "Apply" : changes.length === 1 ? "Apply 1 change" : `Apply ${changes.length} changes`;
  optionsApply.disabled = applying || changes.length === 0 || why !== "";
  optionsRevert.hidden = !edited || changes.length === 0;
}

async function loadCatalog(mapId: string): Promise<void> {
  const cached = catalogCache.get(mapId);
  if (cached !== undefined) {
    catalog = cached;
    catalogState = "ok";
    renderOptionsForm();
    return;
  }
  const api = store.api;
  if (api === null || optionsLobby === null) return;
  // Through the control service only those who run the lobby read its host's settings (and see this form).
  if (ctx?.lobby()?.service?.can_operate === false) return;
  catalogState = "loading";
  renderOptionsState();
  try {
    const answer = await api.lobbyHost(optionsLobby).settings(mapId === "" ? undefined : mapId, AbortSignal.timeout(REQUEST_MS));
    if (catalogMap !== mapId || store.api !== api) return;
    catalogCache.set(mapId, answer);
    catalog = answer;
    catalogState = answer.options.length === 0 && answer.map_options.length === 0 ? "missing" : "ok";
    if (catalogState === "ok") renderOptionsForm();
    else renderOptionsState();
  } catch (error) {
    if (catalogMap !== mapId) return;
    catalog = null;
    catalogState = error instanceof ApiError && error.status === 404 && !/map/i.test(error.message) ? "missing" : "failed";
    catalogError = error instanceof Error ? error.message : String(error);
    renderOptionsState();
  }
}

/** The form follows the lobby open in the page: its starting options, and the catalog for its map. */
export function followLobby(id: string | null, lobby: Lobby | undefined): void {
  if (id !== optionsLobby) {
    optionsLobby = id;
    catalogMap = null;
    catalog = null;
    catalogState = "idle";
    current.clear();
    chosen.clear();
    edited = false;
    optionsBox.replaceChildren();
    optionsFilter.value = "";
    if (lobby !== undefined) for (const [key, value] of Object.entries(lobby.options ?? {})) current.set(key, value);
  } else if (current.size === 0 && lobby?.options) {
    for (const [key, value] of Object.entries(lobby.options)) current.set(key, value);
    if (catalogState === "ok" && !edited) renderOptionsForm();
  }
  if (id === null || lobby === undefined) {
    renderOptionsState();
    return;
  }
  const mapId = lobby.map?.id ?? "";
  if (mapId !== catalogMap) {
    catalogMap = mapId;
    void loadCatalog(mapId);
  } else {
    renderOptionsState();
  }
}

/** An `options` event ("Key=Value,Key=Value"): the lobby has them now, whoever set them. */
export function optionsChanged(text: string): void {
  for (const pair of text.split(",")) {
    const at = pair.indexOf("=");
    if (at <= 0) continue;
    current.set(pair.slice(0, at).trim(), pair.slice(at + 1).trim());
  }
  if (catalogState === "ok" && !edited) renderOptionsForm();
  else renderOptionsState();
}

optionsFilter.addEventListener("input", () => filterOptions(optionsBox, optionsFilter.value));
optionsRevert.addEventListener("click", renderOptionsForm);
optionsApply.addEventListener("click", () => void applyOptions());

async function applyOptions(): Promise<void> {
  const changes = pending();
  if (changes.length === 0 || blockedReason() !== "") return;
  const text = changes.map((change) => `${change.option.key}=${String(change.value)}`).join(",");
  applying = true;
  optionsApply.classList.add("busy");
  renderOptionsState();
  const ok = await run("set_options", { options: text }, optionsApply);
  applying = false;
  optionsApply.classList.remove("busy");
  if (ok) {
    for (const change of changes) current.set(change.option.key, change.value);
    edited = false;
    toast("ok", "Settings applied", changes.map((change) => `${change.option.label ?? change.option.key}: ${change.option.values.find((value) => sameKey(value.key, change.value))?.text ?? String(change.value)}`).join(", "));
  }
  renderOptionsState();
}

export function resetControls(): void {
  followLobby(null, undefined);
  catalogCache.clear();
  renderSeatPicker([], null);
  playerUid.value = "";
  // What was typed for one lobby (results, reasons, a substitute's token) isn't sent to the next.
  for (const id of ["options", "results", "end-reason", "eject-reason", "player-options", "sub-name", "sub-token", "address"]) byId<HTMLInputElement>(id).value = "";
  enableControls(false);
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

/** Runs the op on the open lobby; true when it was done. */
async function run(op: string, fields: Record<string, unknown>, button: HTMLButtonElement): Promise<boolean> {
  const label = OP_LABEL[op] ?? op;
  const current = ctx?.api() ?? null;
  if (current === null) {
    toast("bad", `${label}: no lobby open`);
    return false;
  }
  button.disabled = true;
  button.classList.add("busy");
  let done = false;
  try {
    const result = await current.op(op, fields);
    done = result.ok;
    if (result.ok) {
      if (op !== "set_options") toast("ok", `${label}: done`, answerDetail(result));
    } else {
      toast("bad", `${label}: refused`, result.error ?? "no reason given");
    }
  } catch (error) {
    toast("bad", `${label}: failed`, error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
    button.classList.remove("busy");
  }
  ctx?.poll();
  return done;
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
  const nameOf = (uid: number): string => ctx?.nameOf(uid) ?? `uid ${uid}`;
  switch (op) {
    case "set_options": {
      const text = value("options");
      if (await run(op, { options: text }, button)) toast("ok", "Set options: done", text);
      return;
    }
    case "allow":
    case "disallow":
      await run(op, { address: value("address") }, button);
      return;
    case "eject": {
      const uid = pickedUid(label);
      if (uid === null) return;
      const reason = value("eject-reason");
      const ok = await confirmAction(`Eject ${nameOf(uid)}?`, `uid ${uid} leaves the ${ctx?.status()?.phase === "game" ? "game" : "lobby"}${reason === "" ? "" : `, with the reason "${reason}"`}.`, "Eject");
      if (ok) await run(op, { uid, reason }, button);
      return;
    }
    case "set_player": {
      const uid = pickedUid(label);
      if (uid === null) return;
      await run(op, { uid, options: value("player-options") }, button);
      return;
    }
    case "substitute": {
      const uid = pickedUid(label);
      if (uid === null) return;
      await run(op, { uid, token: value("sub-token"), name: value("sub-name") }, button);
      return;
    }
    case "extend_timeouts": {
      const uid = pickedUid(label);
      if (uid === null) return;
      const count = Number(value("timeouts-count") || "1");
      await run(op, { uid, count }, button);
      return;
    }
    case "end": {
      const outcome = value("results");
      const reason = value("end-reason");
      const ok = await confirmAction(
        "End the game?",
        outcome === "" ? "Without results the game counts as stopped, not ended." : `The game ends with the results ${outcome}.`,
        "End the game",
      );
      if (ok) await run(op, { results: outcome, reason }, button);
      return;
    }
    default:
      await run(op, {}, button);
  }
}
