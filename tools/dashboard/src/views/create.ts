// Create lobby: a full page in six steps with a summary beside them that follows every change. 1. kind (tournament or
// custom), name and map from a gallery of previews; 2. the slots: the map's start spots drawn on its preview, each
// spot a player, an AI or empty, with team and faction; 3. every game setting with its default (changed ones marked)
// and the map's own options; 4. observers and start rules; 5. placement: Auto or CPUs picked on the machine map, the
// planner's estimate and warnings live, and what to do when it doesn't fit (queue it or refuse); 6. review, then
// create. The host is asked for a plan on every change; nothing starts before Create.

import { ApiError, type HostApi, type MapInfo, type NewLobby, type Plan, type PlanRequest, type SettingKey, type Settings } from "../api.ts";
import { canOrganise, globalOrganiser, organisedTournaments, topRole, type ServiceNewLobby, type ServicePlacement, type ServicePlacementHost, type ServiceTournament } from "../control.ts";
import { byId, fill, h, icon, isNumber, num, type Child } from "../dom.ts";
import { MapGallery, MapPreview, mapFacts, spotsOf, type PreviewSource } from "../maps.ts";
import { MachineMap } from "../plane/machine.ts";
import { countChanges, FALLBACK_OPTIONS, filterOptions, pruneChosen, renderOptions, sameKey } from "../plane/options.ts";
import { emptyState, rate, warningList } from "../plane/parts.ts";
import { actions, coresOf, nodeOf, cpuById, on, plural, poolCpus, store } from "../plane/store.ts";
import { hostByName, reachableHosts, service } from "../service.ts";
import { SlotsEditor, type SlotKind, type UidRule } from "../slots.ts";
import { toast } from "../ui.ts";
import { hostMaps, pageHead, type View } from "./common.ts";

const PLAN_DEBOUNCE_MS = 250;
const REQUEST_MS = 5000;
const MAX_OBSERVERS = 32;
/** The host picker's value for placement by the players' ping. */
const BY_PING = "@ping";

type Kind = "tournament" | "custom";
type Step = "map" | "slots" | "settings" | "start" | "placement" | "review";
const STEPS: [Step, string, string][] = [
  ["map", "Kind and map", "map"],
  ["slots", "Slots", "users"],
  ["settings", "Settings", "sliders"],
  ["start", "Observers and start", "eye"],
  ["placement", "Placement", "cpu"],
  ["review", "Review", "check"],
];

interface ObserverDraft {
  name: string;
  referee: boolean;
  /** Through the control service: the observer's FAF id (a tournament's observers need it). */
  uid: string;
}

export function createView(): View {
  const root = byId<HTMLElement>("view-create");

  // ---------------------------------------------------------------- state
  /** Through the control service: an organised lobby on the host picked, or the least loaded one that fits. */
  let svc = false;
  /** The tournament whose lists apply ("" = outside tournaments). */
  let tournamentId = "";
  /** The host picked ("" = the least loaded that fits when it's made, or by ping with byPing). */
  let hostChoice = "";
  /** Through the service, no host picked: the one whose worst player ping is lowest rather than the least loaded. */
  let byPing = false;
  /** Where the service would place it by ping now (POST /api/v1/placement), or why it couldn't say. */
  let pingPlacement: ServicePlacement | null = null;
  let pingError = "";
  let pingLoading = false;
  let pingSeq = 0;
  let kind: Kind = "tournament";
  let step: Step = "map";
  let maps: MapInfo[] = [];
  let mapId = "";
  let name = "";
  let nameTouched = false;
  const settingsCache = new Map<string, Settings>();
  let settings: Settings | null = null;
  let settingsFallback = false;
  const chosen = new Map<string, SettingKey>();
  let observers: ObserverDraft[] = [];
  let observerDelay = 0;
  let countdown = 10;
  let lobbyMinutes = 60;
  let auto = true;
  const picked = new Set<number>();
  let coresFixed = 0;
  let ifFull: "queue" | "refuse" = "queue";
  let force = false;
  let plan: Plan | null = null;
  let planning = false;
  let planError = "";
  let planTimer: number | undefined;
  let planSeq = 0;
  let creating = false;
  let offs: (() => void)[] = [];

  const selectedMap = (): MapInfo | undefined => maps.find((map) => map.id === mapId);
  const aiChoices = (): [string, string][] => {
    const catalog = settings?.ai ?? [];
    if (catalog.length > 0) return catalog.map((ai): [string, string] => [ai.key, `${ai.name ?? ai.key}${isNumber(ai.rating) ? ` · ${ai.rating}` : ""}`]);
    const list = store.info?.ai?.filter((key) => typeof key === "string" && key !== "") ?? [];
    return (list.length > 0 ? list : ["adaptive"]).map((key): [string, string] => [key, key]);
  };

  // ---------------------------------------------------------------- the host the form reads from
  /** Through the service: the host picked, else the least loaded one answering (the maps, settings and plan come from it). */
  const formHostName = (): string => (hostChoice !== "" ? hostChoice : (reachableHosts()[0]?.name ?? ""));
  const formApi = (): HostApi | null => {
    if (!svc) return store.api;
    const name = formHostName();
    return name === "" || service.api === null ? null : service.api.hostApi(name);
  };
  const formPreview: PreviewSource = (map) => Promise.resolve(formApi()?.previewUrl(map) ?? null);
  const tournament = (): ServiceTournament | undefined => service.me?.tournaments.find((item) => item.id === tournamentId);
  const uidRule = (): UidRule | null => {
    const chosen = svc ? tournament() : undefined;
    return chosen === undefined ? null : { allowed: chosen.players ?? [], list: `${chosen.name}'s player list` };
  };
  /** Who may watch a tournament's lobby: its observers and organisers. */
  const observerIds = (): number[] | null => {
    const chosen = svc ? tournament() : undefined;
    return chosen === undefined ? null : [...(chosen.observers ?? []), ...(chosen.organisers ?? [])];
  };

  // ---------------------------------------------------------------- pieces
  const slots = new SlotsEditor({ ais: aiChoices, uid: true, uidRule, onChange: () => onSlotsChanged() });
  const preview = new MapPreview(formPreview, (spot) => slots.focusSpot(spot));
  const summaryPreview = new MapPreview(formPreview);
  const gallery = new MapGallery({ source: formPreview, onSelect: (map) => selectMap(map.id), minSpots: () => Math.max(1, slots.filled()) });
  const machine = new MachineMap({
    mode: "pick",
    selected: () => picked,
    planned: () => (auto ? new Set(plan?.cpus ?? []) : new Set<number>()),
    pickedLabel: "Picked for this lobby",
    onToggle: (cpus, turnOn) => {
      for (const id of cpus) {
        if (turnOn) picked.add(id);
        else picked.delete(id);
      }
      if (picked.size > 0) auto = false;
      renderPlacementMode();
      machine.update();
      schedulePlan();
    },
  });

  // ---------------------------------------------------------------- layout
  const stepper = h("nav", { class: "stepper", "aria-label": "Steps" });
  const panels = new Map<Step, HTMLElement>();
  for (const [id] of STEPS) panels.set(id, h("section", { class: "step-panel", "data-step": id, hidden: true }));
  const back = h("button", { type: "button", class: "btn" }, icon("chevron", "icon"), "Back");
  const next = h("button", { type: "button", class: "btn primary" }, "Next");
  const stepNote = h("span", { class: "step-note" });
  const footer = h("div", { class: "step-footer" }, back, stepNote, next);
  const summary = h("aside", { class: "create-summary card", "aria-label": "Summary" });
  const startOver = h("button", { type: "button", class: "btn ghost" }, "Start over");
  const headSub = h("span", {}, "A tournament lobby the organiser runs, or a custom one a player hosts. Every step can be changed again before Create.");
  const layout = h("div", { class: "create-layout" }, h("div", { class: "create-main" }, stepper, ...panels.values(), footer), summary);
  /** Through the service, for a viewer who may not make lobbies: why, instead of the flow. */
  const refusal = h("div", { hidden: true });
  root.replaceChildren(pageHead("Create lobby", headSub, startOver, h("a", { class: "btn", href: "#/lobbies" }, "Cancel")), refusal, layout);
  back.addEventListener("click", () => go(STEPS[Math.max(0, stepIndex() - 1)]?.[0] ?? "map"));
  next.addEventListener("click", () => {
    if (step === "review") void create();
    else go(STEPS[Math.min(STEPS.length - 1, stepIndex() + 1)]?.[0] ?? "review");
  });
  startOver.addEventListener("click", () => reset());

  function stepIndex(): number {
    return STEPS.findIndex(([id]) => id === step);
  }

  function go(target: Step): void {
    step = target;
    renderStepper();
    for (const [id, panel] of panels) panel.hidden = id !== step;
    renderStep();
    renderFooter();
    window.scrollTo({ top: 0 });
  }

  /** Why a step isn't done yet, or "". */
  function stepProblem(id: Step): string {
    switch (id) {
      case "map":
        if (svc && formHostName() === "") return "No host answers the control service now.";
        if (svc && hostChoice !== "" && hostByName(hostChoice)?.reachable !== true) return `${hostChoice} doesn't answer: pick another host, or the least loaded one.`;
        return selectedMap() === undefined ? "Pick a map." : "";
      case "slots":
        return slots.problem();
      case "start": {
        if (observers.some((observer) => observer.name.trim().length > 40)) return "An observer's name is longer than 40 characters.";
        const allowed = observerIds();
        for (const [index, observer] of observers.entries()) {
          const raw = observer.uid.trim();
          if (raw !== "" && !(Number.isInteger(Number(raw)) && Number(raw) > 0)) return `Observer ${index + 1}'s FAF id is a whole number above 0.`;
          if (allowed !== null && raw === "") return `Observer ${index + 1}: a tournament's observers are listed users: give the FAF id.`;
          if (allowed !== null && !allowed.includes(Number(raw))) return `Observer ${index + 1}: FAF user ${raw} isn't on ${tournament()?.name ?? "the tournament"}'s observer or organiser list.`;
        }
        return "";
      }
      case "placement":
        if (svc) {
          if (plan !== null && !plan.fits && hostChoice !== "" && !force) return `It doesn't fit on ${hostChoice} now: pick another host, or the least loaded one.`;
          return "";
        }
        if (!auto && picked.size === 0) return "Pick CPUs on the machine map, or use Auto.";
        if (plan !== null && !plan.fits && ifFull === "refuse" && !force) return "It doesn't fit now: queue it, or start it anyway.";
        return "";
      default:
        return "";
    }
  }

  function firstProblem(): { step: Step; text: string } | null {
    for (const [id] of STEPS) {
      const text = stepProblem(id);
      if (text !== "") return { step: id, text };
    }
    return null;
  }

  function renderStepper(): void {
    stepper.replaceChildren(
      ...STEPS.map(([id, label, iconName], index) => {
        const problem = stepProblem(id);
        const done = index < stepIndex() && problem === "";
        const button = h(
          "button",
          { type: "button", class: `step${id === step ? " current" : ""}${done ? " done" : ""}${problem !== "" && index < stepIndex() ? " problem" : ""}`, "aria-current": id === step ? "step" : null },
          h("span", { class: "step-num" }, done ? icon("check", "icon tiny") : String(index + 1)),
          h("span", { class: "step-text" }, h("span", { class: "step-label" }, svc && id === "map" ? "Tournament and map" : label), h("span", { class: "step-sub" }, stepSub(id))),
        );
        button.prepend(icon(iconName, "icon step-icon"));
        button.addEventListener("click", () => go(id));
        return button;
      }),
    );
  }

  function stepSub(id: Step): string {
    const map = selectedMap();
    switch (id) {
      case "map":
        if (svc) return map === undefined ? "not picked" : `${tournament()?.name ?? "No tournament"} · ${map.name ?? map.id}`;
        return map === undefined ? "not picked" : `${kind === "tournament" ? "Tournament" : "Custom"} · ${map.name ?? map.id}`;
      case "slots": {
        const seats = slots.seats();
        const humans = seats.filter((seat) => seat.kind === "human").length;
        return map === undefined ? "after the map" : `${plural(humans, "player")}, ${plural(seats.length - humans, "AI", "AIs")}`;
      }
      case "settings": {
        const changed = chosen.size;
        return changed === 0 ? "all default" : `${changed} changed`;
      }
      case "start":
        return `${observers.length === 0 ? "no observers" : plural(observers.length, "observer")} · ${countdown > 0 ? `${countdown} s countdown` : "no countdown"}`;
      case "placement":
        if (svc) return planning ? "planning…" : `${hostWords()}${plan === null ? "" : plan.fits ? " · fits" : " · doesn't fit now"}`;
        return planning ? "planning…" : plan === null ? "–" : plan.fits ? `fits${auto ? " (Auto)" : ""}` : ifFull === "queue" ? "doesn't fit now: queued" : "doesn't fit now";
      default:
        return "check and create";
    }
  }

  function createLabel(): string {
    if (svc) return "Create lobby";
    return plan !== null && !plan.fits && ifFull === "queue" && !force ? "Create and queue" : "Create lobby";
  }

  function renderFooter(): void {
    back.disabled = stepIndex() === 0;
    const problem = stepProblem(step);
    stepNote.textContent = problem !== "" ? problem : `Step ${stepIndex() + 1} of ${STEPS.length}`;
    stepNote.classList.toggle("bad-text", problem !== "");
    if (step === "review") {
      const blocker = firstProblem();
      next.replaceChildren(icon("rocket", "icon"), createLabel());
      next.disabled = creating || blocker !== null || planning;
    } else {
      next.replaceChildren(`Next: ${STEPS[stepIndex() + 1]?.[1] ?? ""}`, h("span", { class: "flip" }, icon("chevron", "icon")));
      next.disabled = false;
    }
  }

  // ---------------------------------------------------------------- step 1: kind, name, map
  const kindCards = h("div", { class: "choice-cards kind-cards", role: "radiogroup", "aria-label": "Kind of lobby" });
  const nameInput = h("input", { id: "create-name", autocomplete: "off", spellcheck: "false", maxlength: 80 });
  nameInput.addEventListener("input", () => {
    name = nameInput.value;
    nameTouched = true;
    renderSummary();
  });
  const galleryNote = h("p", { class: "dim small" });
  const kindBlock = h("div", { class: "form-block" }, h("h2", {}, "What kind of lobby"), kindCards);
  // Through the service: the tournament whose lists apply, and the host.
  const tournamentSelect = h("select", { id: "create-tournament" });
  const hostSelect = h("select", { id: "create-host" });
  const tournamentHelp = h("span", { class: "dim small" });
  const hostHelp = h("span", { class: "dim small" });
  const whereBlock = h(
    "div",
    { class: "form-block", hidden: true },
    h("h2", {}, "Tournament and host"),
    h("p", { class: "dim small section-help" }, "Made through the control service, a lobby is organised: nobody hosts it; it starts from its page, or by itself once every player is ready."),
    h(
      "div",
      { class: "two-col tight" },
      h("div", { class: "field" }, h("label", { for: "create-tournament" }, "Tournament"), tournamentSelect, tournamentHelp),
      h("div", { class: "field" }, h("label", { for: "create-host" }, "Host"), hostSelect, hostHelp),
    ),
  );
  tournamentSelect.addEventListener("change", () => {
    tournamentId = tournamentSelect.value;
    if (!nameTouched) defaultName();
    renderWhere();
    slots.render();
    onSlotsChanged();
    renderObservers();
  });
  hostSelect.addEventListener("change", () => {
    byPing = hostSelect.value === BY_PING;
    hostChoice = byPing ? "" : hostSelect.value;
    pingPlacement = null;
    pingError = "";
    force = false;
    renderWhere();
    void loadMaps();
    schedulePlan();
  });
  panels.get("map")?.append(
    kindBlock,
    whereBlock,
    h("div", { class: "form-block narrow-field" }, h("label", { for: "create-name", class: "field-label" }, "Name ", h("span", { class: "dim" }, "(shown on the dashboard and in the players' lobby)")), nameInput),
    h("div", { class: "form-block" }, h("div", { class: "block-head" }, h("h2", {}, "Map"), galleryNote), gallery.root),
  );

  /** The tournament and host pickers, through the service. */
  function renderWhere(): void {
    kindBlock.hidden = svc;
    whereBlock.hidden = !svc;
    if (!svc) return;
    const me = service.me;
    const list = organisedTournaments(me);
    const choices: [string, string][] = [...(globalOrganiser(me) ? [["", "No tournament (open seats allowed)"] as [string, string]] : []), ...list.map((item): [string, string] => [item.id, item.name])];
    if (!choices.some(([id]) => id === tournamentId)) tournamentId = choices[0]?.[0] ?? "";
    const tsig = JSON.stringify(choices);
    if (tournamentSelect.dataset.sig !== tsig) {
      tournamentSelect.dataset.sig = tsig;
      tournamentSelect.replaceChildren(...choices.map(([id, text]) => h("option", { value: id }, text)));
    }
    tournamentSelect.value = tournamentId;
    const chosen = tournament();
    tournamentHelp.textContent =
      chosen === undefined
        ? "Outside tournaments: any player may take a seat, named or open."
        : `Seats only for its ${plural((chosen.players ?? []).length, "listed player")}, each with their FAF id; observers from its observer or organiser lists.`;
    const hosts = [...service.hosts].sort((a, b) => a.name.localeCompare(b.name));
    const least = reachableHosts()[0];
    const options: [string, string, boolean][] = [
      ["", `Least loaded that fits${least === undefined ? "" : ` (now ${least.name})`}`, false],
      [BY_PING, "Lowest worst ping of the players", false],
      ...hosts.map((host): [string, string, boolean] => [host.name, `${host.name}${host.region ? ` · ${host.region}` : ""}${host.reachable ? (isNumber(host.load) ? ` · ${Math.round(host.load / 5) * 5}% busy` : "") : " · not answering"}`, !host.reachable]),
    ];
    const hsig = JSON.stringify(options);
    if (hostSelect.dataset.sig !== hsig) {
      hostSelect.dataset.sig = hsig;
      hostSelect.replaceChildren(...options.map(([value, text, off]) => h("option", { value, disabled: off }, text)));
    }
    if (hostChoice !== "" && !hosts.some((host) => host.name === hostChoice)) hostChoice = "";
    hostSelect.value = byPing ? BY_PING : hostChoice;
    const source = least === undefined ? "from no host: none answers" : `${least.name}'s`;
    hostHelp.textContent =
      hostChoice !== ""
        ? `It goes to ${hostChoice} or not at all.`
        : byPing
          ? `When you create it, the service tries the hosts that have the map and room for it, lowest worst player ping first, by the pings the players reported in the last 30 minutes; pings within 10 ms go to the less loaded host. Placement shows each host's worst ping. Maps, settings and the estimate here are ${source}.`
          : `When you create it, the service tries the hosts that have the map, least loaded first, until one has room. Maps, settings and the estimate here are ${source}.`;
  }

  /** Where it goes, in a few words. */
  function hostWords(): string {
    return hostChoice !== "" ? hostChoice : byPing ? "lowest worst ping" : "least loaded";
  }

  function renderKind(): void {
    const option = (value: Kind, title: string, text: string, iconName: string): HTMLElement => {
      const input = h("input", { type: "radio", name: "create-kind", value });
      input.checked = kind === value;
      input.addEventListener("change", () => {
        if (!input.checked) return;
        kind = value;
        if (!nameTouched) defaultName();
        resetSlots();
        renderAll();
      });
      return h("label", { class: "choice big" }, input, h("span", { class: "choice-icon" }, icon(iconName, "icon")), h("span", { class: "choice-body" }, h("strong", {}, title), h("span", {}, text)));
    };
    kindCards.replaceChildren(
      option("tournament", "Tournament", "The organiser runs it: you set the map, every slot and every setting here. Nobody hosts; it starts from its page, or by itself once every player is ready.", "trophy"),
      option("custom", "Custom", "A player hosts it: the player on spot 1 opens the lobby in their own game and launches it. Slots and settings here are where it starts.", "crown"),
    );
  }

  function defaultName(): void {
    const map = selectedMap();
    const what = svc ? (tournament()?.name ?? "Organised lobby") : kind === "tournament" ? "Tournament" : "Custom game";
    name = `${what}${map === undefined ? "" : ` on ${map.name ?? map.id}`}`;
    nameInput.value = name;
  }

  function selectMap(id: string): void {
    mapId = id;
    if (!nameTouched) defaultName();
    resetSlots();
    void loadSettings();
    schedulePlan();
    renderAll();
  }

  let mapsFrom = "";

  async function loadMaps(): Promise<void> {
    const api = formApi();
    if (api === null) {
      galleryNote.textContent = svc ? "No host answers the control service: no maps to show." : "";
      return;
    }
    if (api.base === mapsFrom && maps.length > 0) return;
    galleryNote.textContent = svc ? `Loading ${formHostName()}'s maps…` : "Loading the host's maps…";
    try {
      const list = await hostMaps(api);
      if (formApi()?.base !== api.base) return;
      maps = list;
      mapsFrom = api.base;
      galleryNote.textContent = `${svc ? `${formHostName()}'s maps. ` : ""}Dots are the start spots. Sizes are the map's side.`;
      if ((mapId === "" || selectedMap() === undefined) && maps.length > 0) {
        const preferred = maps.find((map) => map.preview && (map.players ?? 0) >= 2 && (map.players ?? 0) <= 8) ?? maps[0];
        if (preferred !== undefined) selectMap(preferred.id);
      } else if (mapId !== "") {
        void loadSettings();
        schedulePlan();
      }
      gallery.setMaps(maps, mapId);
    } catch (error) {
      galleryNote.textContent = `The maps didn't load: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  // ---------------------------------------------------------------- step 2: slots
  panels.get("slots")?.append(
    h(
      "div",
      { class: "slots-layout" },
      h("div", { class: "slots-preview" }, preview.root, h("p", { class: "dim small" }, "Click a spot to edit its slot. Colours are teams.")),
      h("div", { class: "slots-editor" }, h("h2", {}, "Who plays where"), h("p", { class: "dim small section-help" }, "One row per start spot. A player without a name is an open seat: whoever gets its join line takes it. The uid is optional (the player's FAF id)."), slots.root),
    ),
  );

  function resetSlots(): void {
    const map = selectedMap();
    const count = map === undefined ? 0 : spotsOf(map).length;
    slots.slots = [];
    slots.setSpots(count, (index): SlotKind => (index < 2 ? "human" : "empty"));
  }

  function onSlotsChanged(): void {
    preview.update(selectedMap(), slots.marks());
    summaryPreview.update(selectedMap(), slots.marks());
    gallery.refreshFit();
    schedulePlan();
    renderSummary();
    renderStepper();
    renderFooter();
  }

  // ---------------------------------------------------------------- step 3: settings
  const settingsBox = h("div", { class: "settings-form wide" });
  const settingsMeta = h("span", { class: "dim small" });
  const settingsFilter = h("input", { type: "search", placeholder: "Filter settings", spellcheck: "false", "aria-label": "Filter settings" });
  const settingsReset = h("button", { type: "button", class: "btn small ghost", hidden: true }, "Reset all to default");
  const settingsNote = h("p", { class: "settings-note", hidden: true }, "This host doesn't list its settings: the usual ones are shown.");
  const customNote = h("p", { class: "dim small section-help" }, "These are where the game starts; the player hosting a custom lobby can change them in their lobby screen.");
  settingsFilter.addEventListener("input", () => filterOptions(settingsBox, settingsFilter.value));
  settingsReset.addEventListener("click", () => {
    chosen.clear();
    renderSettings();
  });
  panels.get("settings")?.append(h("div", { class: "block-head" }, h("h2", {}, "Game settings"), settingsMeta), customNote, settingsNote, h("div", { class: "settings-tools" }, settingsFilter, settingsReset), settingsBox);

  async function loadSettings(): Promise<void> {
    const api = formApi();
    if (api === null || mapId === "") return;
    const key = mapId;
    const cacheKey = `${api.base} ${key}`;
    const cached = settingsCache.get(cacheKey);
    if (cached !== undefined) {
      useSettings(cached);
      return;
    }
    settingsMeta.textContent = "loading…";
    try {
      const answer = await api.settings(key, AbortSignal.timeout(REQUEST_MS));
      settingsCache.set(cacheKey, answer);
      if (key === mapId && formApi()?.base === api.base) useSettings(answer);
    } catch (error) {
      if (error instanceof ApiError && error.status === 404 && !/map/i.test(error.message)) {
        settingsFallback = true;
        useSettings({ options: FALLBACK_OPTIONS, ai: [], map_options: [] });
        return;
      }
      settingsMeta.textContent = `didn't load: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  function useSettings(next: Settings): void {
    settings = next;
    pruneChosen(chosen, next);
    settingsNote.hidden = !settingsFallback;
    renderSettings();
    slots.render();
    onSlotsChanged();
  }

  function renderSettings(): void {
    if (settings === null) return;
    renderOptions(settingsBox, settings, selectedMap()?.name ?? "this map", { chosen, idPrefix: "create-set-", onChange: renderSettingsCounts, openAll: true });
    filterOptions(settingsBox, settingsFilter.value);
    renderSettingsCounts();
  }

  function renderSettingsCounts(): void {
    const total = countChanges(settingsBox);
    const count = (settings?.options.length ?? 0) + (settings?.map_options.length ?? 0);
    settingsMeta.textContent = total === 0 ? `${count} settings, all at their default` : `${count} settings · ${total} changed from the default`;
    settingsReset.hidden = total === 0;
    renderSummary();
    renderStepper();
  }

  // ---------------------------------------------------------------- step 4: observers and start
  const countdownInput = h("input", { id: "create-countdown", type: "number", min: 0, max: 600, inputmode: "numeric" });
  const minutesInput = h("input", { id: "create-minutes", type: "number", min: 1, max: 1440, inputmode: "numeric" });
  const observerRows = h("div", { class: "observer-rows" });
  const observerAdd = h("button", { type: "button", class: "btn small" }, icon("plus", "icon tiny"), "Add an observer");
  const delayInput = h("input", { id: "create-delay", type: "number", min: 0, max: 3600, inputmode: "numeric" });
  const delayField = h("div", { class: "field narrow-field" }, h("label", { for: "create-delay" }, "Delay for observers (seconds)"), delayInput, h("span", { class: "dim small" }, "Referees always watch live."));
  const startHelp = h("p", { class: "dim small section-help" });
  countdownInput.addEventListener("input", () => {
    countdown = Math.max(0, Math.round(Number(countdownInput.value) || 0));
    renderSummary();
    renderStepper();
  });
  minutesInput.addEventListener("input", () => {
    lobbyMinutes = Math.max(1, Math.round(Number(minutesInput.value) || 60));
    renderSummary();
  });
  delayInput.addEventListener("input", () => {
    observerDelay = Math.max(0, Math.min(3600, Math.round(Number(delayInput.value) || 0)));
    renderSummary();
  });
  observerAdd.addEventListener("click", () => {
    if (observers.length >= MAX_OBSERVERS) return;
    observers.push({ name: "", referee: false, uid: "" });
    renderObservers();
    observerRows.lastElementChild?.querySelector("input")?.focus();
  });
  panels.get("start")?.append(
    h(
      "div",
      { class: "two-col" },
      h(
        "div",
        { class: "form-block" },
        h("h2", {}, "Start rules"),
        startHelp,
        h("div", { class: "field narrow-field" }, h("label", { for: "create-countdown" }, "Countdown once every player is ready (seconds)"), countdownInput, h("span", { class: "dim small" }, "0 turns it off: then it starts only from its page.")),
        h("div", { class: "field narrow-field" }, h("label", { for: "create-minutes" }, "The lobby stays open for (minutes)"), minutesInput, h("span", { class: "dim small" }, "Without a game by then, its server stops and its CPUs are free again.")),
      ),
      h(
        "div",
        { class: "form-block" },
        h("div", { class: "block-head" }, h("h2", {}, "Observers"), h("span", { class: "dim small" }, `up to ${MAX_OBSERVERS}`)),
        h("p", { class: "dim small section-help" }, "Each gets a watch line of their own: a live replay of the game. Casters watch with the delay; referees watch live."),
        observerRows,
        observerAdd,
        delayField,
      ),
    ),
  );

  const observerUids = h("datalist", { id: "create-observer-uids" });
  observerRows.after(observerUids);

  function renderObservers(): void {
    observerUids.replaceChildren(...(observerIds() ?? []).map((uid) => h("option", { value: String(uid) })));
    observerRows.replaceChildren(
      ...observers.map((observer, index) => {
        const n = index + 1;
        const nameField = h("input", { maxlength: 40, placeholder: `Observer ${n}`, spellcheck: "false", autocomplete: "off", "aria-label": `Observer ${n}: name` });
        nameField.value = observer.name;
        nameField.addEventListener("input", () => {
          observer.name = nameField.value;
          renderSummary();
        });
        const referee = h("input", { type: "checkbox", "aria-label": `Observer ${n} is a referee` });
        referee.checked = observer.referee;
        referee.addEventListener("change", () => {
          observer.referee = referee.checked;
          renderObservers();
        });
        const remove = h("button", { type: "button", class: "btn ghost small", "aria-label": `Remove observer ${n}` }, icon("trash", "icon tiny"));
        remove.addEventListener("click", () => {
          observers.splice(index, 1);
          renderObservers();
        });
        let uidField: HTMLInputElement | null = null;
        if (svc) {
          const listed = observerIds();
          uidField = h("input", { type: "number", inputmode: "numeric", class: "slot-uid", placeholder: listed === null ? "uid" : "uid *", list: listed === null ? null : "create-observer-uids", "aria-label": `Observer ${n}: FAF id${listed === null ? " (optional)" : " (required)"}`, title: listed === null ? "The observer's FAF id (optional): their watch line then shows on their page" : "The observer's FAF id, from the tournament's observer or organiser list" });
          uidField.value = observer.uid;
          uidField.addEventListener("input", () => {
            observer.uid = uidField?.value ?? "";
            renderSummary();
            renderStepper();
            renderFooter();
          });
        }
        return h("div", { class: `observer-row${svc ? " with-uid" : ""}` }, nameField, uidField, h("label", { class: "check" }, referee, h("span", {}, "Referee (live)")), remove);
      }),
    );
    observerAdd.disabled = observers.length >= MAX_OBSERVERS;
    delayField.hidden = !observers.some((observer) => !observer.referee);
    renderSummary();
    renderStepper();
    renderFooter();
  }

  // ---------------------------------------------------------------- step 5: placement
  const modeCards = h("div", { class: "choice-cards", role: "radiogroup", "aria-label": "Placement" });
  const coresBox = h("div", { class: "cores-row" });
  const estimateBox = h("div", { "aria-live": "polite" });
  const warningsBox = h("div", { "aria-live": "polite" });
  const fullCards = h("div", { class: "choice-cards compact", role: "radiogroup", "aria-label": "If it doesn't fit" });
  const forceBox = h("label", { class: "check force" }, h("input", { type: "checkbox" }), h("span", {}, "Start it anyway, despite the error"));
  const forceInput = forceBox.querySelector("input") as HTMLInputElement;
  forceInput.addEventListener("change", () => {
    force = forceInput.checked;
    renderPlan();
  });
  const pickedLine = h("p", { class: "picked-line" });
  const clearPicks = h("button", { type: "button", class: "btn small ghost" }, "Clear the picks");
  clearPicks.addEventListener("click", () => {
    picked.clear();
    machine.update();
    renderPlacementMode();
    schedulePlan();
  });
  const pickedRow = h("div", { class: "picked-row" }, pickedLine, clearPicks);
  const fullHead = h("h3", { class: "sub-head" }, "If it doesn't fit now");
  /** Through the service: where it goes, in words (no machine map: the service gives no host's CPUs). */
  const serviceWhere = h("div", { class: "service-where", hidden: true });
  panels.get("placement")?.append(
    h(
      "div",
      { class: "placement-layout" },
      h("div", { class: "placement-main" }, h("h2", {}, "Where it runs"), serviceWhere, modeCards, coresBox, pickedRow, machine.root),
      h("div", { class: "placement-side" }, h("h2", {}, "What it needs"), estimateBox, h("h3", { class: "sub-head" }, "Warnings"), warningsBox, fullHead, fullCards, forceBox),
    ),
  );

  /** Through the service, by ping: the hosts with their worst player ping, in the order the service would try them. */
  const pingBox = h("div", { class: "ping-placement", "aria-live": "polite" });

  function pingNote(row: ServicePlacementHost, picked: string | undefined): Child {
    if (!row.candidate) return h("span", { class: "dim" }, row.reason ?? "can't take it now");
    const notes: Child[] = [];
    if (row.host === picked) notes.push(h("span", { class: "chip tiny tone-ok" }, "goes here"));
    if ((row.unreachable_for ?? []).length > 0) notes.push(h("span", { class: "chip tiny tone-bad" }, `no reply to ${(row.unreachable_for ?? []).join(", ")}`));
    if ((row.unmeasured ?? []).length > 0) notes.push(h("span", { class: "chip tiny tone-warn" }, `not measured by ${(row.unmeasured ?? []).join(", ")}`));
    return notes.length === 0 ? h("span", { class: "dim" }, "–") : h("span", { class: "ping-notes" }, ...notes);
  }

  function pingTable(pl: ServicePlacement): HTMLElement {
    const rows = [...pl.hosts].sort((a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9) || a.host.localeCompare(b.host));
    return h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        { class: "grid-table ping-table" },
        h("thead", {}, h("tr", {}, ...["Order", "Host", "Worst ping", "Slowest player", "Load", ""].map((text) => h("th", { scope: "col" }, text)))),
        h(
          "tbody",
          {},
          ...rows.map((row) =>
            h(
              "tr",
              { "data-picked": row.host === pl.picked ? "yes" : null, "data-candidate": row.candidate ? null : "no" },
              h("td", { "data-label": "Order" }, row.rank === undefined ? "–" : `#${row.rank}`),
              h("td", { "data-label": "Host" }, h("strong", {}, row.host), row.region ? h("span", { class: "dim" }, ` · ${row.region}`) : null),
              h("td", { "data-label": "Worst ping" }, row.worst_ms === null ? "–" : `${num(row.worst_ms)} ms`),
              h("td", { "data-label": "Slowest player" }, row.worst_player ?? "–"),
              h("td", { "data-label": "Load" }, `${num(row.load)}%`),
              h("td", { "data-label": "" }, pingNote(row, pl.picked)),
            ),
          ),
        ),
      ),
    );
  }

  function renderPing(): void {
    const again = h("button", { type: "button", class: "btn small ghost" }, pingLoading ? "Checking…" : "Check again");
    again.disabled = pingLoading;
    again.addEventListener("click", () => void loadPing());
    const pl = pingPlacement;
    fill(
      pingBox,
      h("div", { class: "block-head" }, h("h3", { class: "sub-head" }, "Players' ping to each host"), again),
      pingError !== ""
        ? h("p", { class: "form-error" }, `The service couldn't place it: ${pingError}`)
        : pl === null
          ? h("p", { class: "dim" }, pingLoading ? "Asking the service…" : selectedMap() === undefined ? "Pick a map first." : "Not checked yet.")
          : h(
              "div",
              {},
              h("p", { class: "dim small" }, `${pl.basis}.`),
              pl.missing.length > 0
                ? h("p", { class: "small warn-text" }, `Without a ping: ${pl.missing.map((m) => `${m.name} (${m.why})`).join(", ")}. They don't change the order.`)
                : null,
              pingTable(pl),
              h("p", { class: "dim small" }, "Players report their ping with rtt-probe; a report counts for 30 minutes. The order is checked again when you create the lobby."),
            ),
    );
  }

  /** Asks the service where the lobby would go by ping now; nothing is made. */
  async function loadPing(): Promise<void> {
    const control = service.api;
    const map = selectedMap();
    if (!svc || !byPing || control === null || map === undefined) return;
    const seq = ++pingSeq;
    pingLoading = true;
    renderPing();
    try {
      const pl = await control.placement(serviceRequest(map), AbortSignal.timeout(REQUEST_MS));
      if (seq !== pingSeq) return;
      pingPlacement = pl;
      pingError = "";
    } catch (error) {
      if (seq !== pingSeq) return;
      pingPlacement = null;
      pingError = error instanceof Error ? error.message : String(error);
    } finally {
      if (seq === pingSeq) {
        pingLoading = false;
        renderPing();
      }
    }
  }

  function renderServiceWhere(): void {
    serviceWhere.hidden = !svc;
    modeCards.hidden = svc;
    pickedRow.hidden = svc;
    machine.root.hidden = svc;
    fullHead.hidden = svc;
    fullCards.hidden = svc;
    if (!svc) return;
    const reference = formHostName();
    const change = h("button", { type: "button", class: "btn small ghost" }, "Change the host");
    change.addEventListener("click", () => go("map"));
    fill(
      serviceWhere,
      h(
        "p",
        {},
        hostChoice !== ""
          ? `It goes to ${hostChoice}, where the planner picks whole cores on one NUMA node. If ${hostChoice} has no room then, it isn't made: nothing waits in a queue.`
          : byPing
            ? `The control service places it when you create it: on the host with the lowest worst player ping among those that have the map and room for it. On that host the planner picks whole cores on one NUMA node${reference === "" ? "" : `; the estimate shown is ${reference}'s`}.`
            : `The control service places it when you create it: on the least loaded host that has the map and room for it${reference === "" ? "" : ` (now ${reference}, whose estimate is shown)`}. On that host the planner picks whole cores on one NUMA node.`,
        " ",
        change,
      ),
      byPing && hostChoice === "" ? pingBox : null,
    );
    if (byPing && hostChoice === "") renderPing();
  }

  function renderPlacementMode(): void {
    const option = (value: boolean, title: string, text: string): HTMLElement => {
      const input = h("input", { type: "radio", name: "create-auto", value: String(value) });
      input.checked = auto === value;
      input.addEventListener("change", () => {
        if (!input.checked) return;
        auto = value;
        if (auto) picked.clear();
        renderPlacementMode();
        machine.update();
        schedulePlan();
      });
      return h("label", { class: "choice" }, input, h("span", { class: "choice-body" }, h("strong", {}, title), h("span", {}, text)));
    };
    const pool = poolCpus();
    modeCards.replaceChildren(
      option(true, "Auto", `The planner picks whole cores on one NUMA node, the least busy, ${pool.size > 0 ? "outside the player-hosting pool" : "anywhere free"}. Its pick shows dashed on the map.`),
      option(false, "Pick CPUs", "Click CPUs on the machine map. Any CPU may be picked; the warnings say what's wrong with a pick (shared, another node, in the pool)."),
    );
    // Cores: the suggestion or a fixed count (Auto only).
    coresBox.hidden = !auto;
    const suggested = plan?.estimate.suggested_cores;
    const coresInput = h("input", { type: "number", min: 1, max: 64, inputmode: "numeric", "aria-label": "Cores", value: coresFixed > 0 ? coresFixed : isNumber(suggested) ? suggested : 1 });
    coresInput.disabled = coresFixed === 0;
    coresInput.addEventListener("input", () => {
      coresFixed = Math.max(1, Math.round(Number(coresInput.value) || 1));
      schedulePlan();
    });
    const suggestedBox = h("input", { type: "checkbox" });
    suggestedBox.checked = coresFixed === 0;
    suggestedBox.addEventListener("change", () => {
      coresFixed = suggestedBox.checked ? 0 : Math.max(1, isNumber(suggested) ? suggested : 1);
      renderPlacementMode();
      schedulePlan();
    });
    coresBox.replaceChildren(h("span", { class: "field-label" }, "Cores"), h("label", { class: "check" }, suggestedBox, h("span", {}, `As suggested${isNumber(suggested) ? ` (${suggested})` : ""}`)), coresInput, h("span", { class: "dim small" }, "whole cores, both of their CPUs"));
    const list = [...picked].sort((a, b) => a - b);
    clearPicks.hidden = list.length === 0;
    if (auto) pickedLine.replaceChildren(h("span", { class: "dim" }, plan !== null && plan.cpus.length > 0 ? `Auto puts it on CPU ${plan.cpus.join(", ")} (node ${plan.nodes.join(", ")}).` : "Auto finds no room now."));
    else {
      const nodes = [...new Set(list.map((id) => cpuById(id)).filter((cpu) => cpu !== undefined).map((cpu) => nodeOf(cpu)))];
      pickedLine.replaceChildren(list.length === 0 ? h("span", { class: "dim" }, "No CPU picked yet: click CPUs on the map.") : h("span", {}, "Picked ", h("b", {}, `CPU ${list.join(", ")}`), h("span", { class: "dim" }, ` · ${plural(coresOf(list), "core")} · node ${nodes.join(", ")}`)));
    }
    renderStepper();
    renderFooter();
  }

  function renderFull(): void {
    const option = (value: "queue" | "refuse", title: string, text: string): HTMLElement => {
      const input = h("input", { type: "radio", name: "create-full", value });
      input.checked = ifFull === value;
      input.addEventListener("change", () => {
        if (!input.checked) return;
        ifFull = value;
        renderPlan();
      });
      return h("label", { class: "choice" }, input, h("span", { class: "choice-body" }, h("strong", {}, title), h("span", {}, text)));
    };
    fullCards.replaceChildren(
      option("queue", "Queue it", "It waits in the operator queue and starts by itself when a lobby ends and it fits."),
      option("refuse", "Don't create it", "Say so now; nothing waits."),
    );
  }

  function est(label: string, value: Child, sub?: Child): HTMLElement {
    return h("div", { class: "est" }, h("span", { class: "est-label" }, label), h("span", { class: "est-value" }, value), sub === undefined ? null : h("span", { class: "est-sub" }, sub));
  }

  function renderPlan(): void {
    if (planError !== "") {
      fill(estimateBox, h("p", { class: "form-error" }, `${svc ? formHostName() : "The host"} couldn't plan it: ${planError}`));
      warningsBox.replaceChildren();
    } else if (plan === null) {
      fill(estimateBox, h("p", { class: "dim" }, selectedMap() === undefined ? "Pick a map to see what it needs." : "Planning…"));
      warningsBox.replaceChildren();
    } else {
      const e = plan.estimate;
      fill(estimateBox, 
        h(
          "div",
          { class: `estimate${planning ? " stale" : ""}`, title: e.basis ?? "" },
          est("Cores", isNumber(e.suggested_cores) ? `${e.suggested_cores} suggested` : "–", `average ${num(e.mean_cores, 2)}, at worst ${num(e.worst_cores, 2)}`),
          est("Memory", isNumber(e.memory_mb) ? `about ${num(e.memory_mb)} MB` : "–"),
          est("Server upload", isNumber(e.upload_kbps) ? `about ${rate(e.upload_kbps)}` : "–", "for the whole game"),
          est("Each player needs", isNumber(e.min_connection_kbps) ? `at least ${rate(e.min_connection_kbps)}` : "–", "of connection"),
        ),
        h(
          "p",
          { class: "plan-line" },
          h("span", { class: `chip tone-${plan.fits ? "ok" : "bad"}` }, plan.fits ? "Fits now" : "Doesn't fit now"),
          plan.cpus.length === 0 ? h("span", { class: "dim" }, "no CPUs free for it") : h("span", {}, `on CPU ${plan.cpus.join(", ")}`, h("span", { class: "dim" }, ` · ${plural(plan.cores || coresOf(plan.cpus), "core")} · node ${plan.nodes.join(", ")}`)),
          plan.nodes.length > 1 ? h("span", { class: "chip tone-warn" }, "spans NUMA nodes") : plan.nodes.length === 1 ? h("span", { class: "chip tone-ok" }, "one NUMA node") : null,
        ),
        e.basis ? h("details", { class: "hint-basis" }, h("summary", {}, "How this is estimated"), h("p", {}, e.basis)) : null,
      );
      warningsBox.replaceChildren(plan.warnings.length === 0 ? h("p", { class: "ok-line small" }, icon("check", "icon tiny"), "No warnings.") : warningList(plan.warnings));
    }
    const blocked = plan !== null && !plan.fits;
    fullCards.classList.toggle("dim-block", !blocked);
    // Through the service only an admin may force, and only on a host picked by name.
    forceBox.hidden = !blocked || (svc && (topRole(service.me) !== "admin" || hostChoice === ""));
    forceInput.checked = force;
    renderServiceWhere();
    renderPlacementMode();
    renderSummary();
  }

  function planRequest(): PlanRequest | null {
    const map = selectedMap();
    if (map === undefined) return null;
    const request: PlanRequest = { players: Math.max(1, slots.filled()), km: isNumber(map.km) && map.km > 0 ? map.km : 20, side: "operator" };
    if (!auto && picked.size > 0) request.cpus = [...picked].sort((a, b) => a - b);
    else request.cores = coresFixed;
    return request;
  }

  function schedulePlan(): void {
    window.clearTimeout(planTimer);
    if (formApi() === null || selectedMap() === undefined) return;
    planning = true;
    planTimer = window.setTimeout(() => void runPlan(), PLAN_DEBOUNCE_MS);
  }

  async function runPlan(): Promise<void> {
    const api = formApi();
    const request = planRequest();
    if (api === null || request === null) return;
    const seq = ++planSeq;
    try {
      const answer = await api.plan(request, AbortSignal.timeout(REQUEST_MS));
      if (seq !== planSeq) return;
      plan = answer;
      planError = "";
      if (plan.fits) force = false;
    } catch (error) {
      if (seq !== planSeq) return;
      plan = null;
      planError = error instanceof Error ? error.message : String(error);
    } finally {
      if (seq === planSeq) {
        planning = false;
        machine.update();
        renderPlan();
        renderStepper();
        renderFooter();
      }
    }
  }

  // ---------------------------------------------------------------- step 6: review
  const reviewBox = h("div", { class: "review" });
  panels.get("review")?.append(h("h2", {}, "Check it, then create it"), reviewBox);

  function reviewSection(title: string, target: Step, ...body: Child[]): HTMLElement {
    const change = h("button", { type: "button", class: "btn small ghost" }, "Change");
    change.addEventListener("click", () => go(target));
    const problem = stepProblem(target);
    return h("section", { class: `review-section${problem !== "" ? " problem" : ""}` }, h("div", { class: "review-head" }, h("h3", {}, title), change), problem === "" ? null : h("p", { class: "bad-text small" }, problem), ...body);
  }

  function changedSettings(): [string, string][] {
    const all = [...(settings?.options ?? []), ...(settings?.map_options ?? [])];
    return [...chosen].map(([key, value]) => {
      const option = all.find((item) => item.key === key);
      const text = option?.values.find((item) => sameKey(item.key, value))?.text ?? String(value);
      return [option?.label ?? key, text];
    });
  }

  function renderReview(): void {
    const map = selectedMap();
    const seats = slots.seats();
    const ais = new Map(aiChoices());
    const changes = changedSettings();
    reviewBox.replaceChildren(
      reviewSection(
        "Lobby",
        "map",
        svc
          ? h(
              "dl",
              { class: "review-facts" },
              h("dt", {}, "Name"),
              h("dd", {}, name.trim() || "(the tournament's name)"),
              h("dt", {}, "Kind"),
              h("dd", {}, "Organised: the organisers run it, nobody hosts"),
              h("dt", {}, "Tournament"),
              h("dd", {}, tournament()?.name ?? "none (open seats allowed)"),
              h("dt", {}, "Host"),
              h("dd", {}, hostChoice !== "" ? hostChoice : byPing ? `the lowest worst player ping that fits, when it's made${pingPlacement?.picked ? ` (now ${pingPlacement.picked})` : ""}` : "the least loaded one that fits, when it's made"),
              h("dt", {}, "Map"),
              h("dd", {}, map === undefined ? "–" : `${map.name ?? map.id} · ${mapFacts(map)}`),
            )
          : h("dl", { class: "review-facts" }, h("dt", {}, "Name"), h("dd", {}, name.trim() || "(the host names it)"), h("dt", {}, "Kind"), h("dd", {}, kind === "tournament" ? "Tournament: the organiser runs it, nobody hosts" : "Custom: the player on spot 1 hosts"), h("dt", {}, "Map"), h("dd", {}, map === undefined ? "–" : `${map.name ?? map.id} · ${mapFacts(map)}`)),
      ),
      reviewSection(
        "Slots",
        "slots",
        seats.length === 0
          ? h("p", { class: "dim" }, "No seats.")
          : h(
              "ul",
              { class: "review-seats" },
              ...seats.map((seat) => {
                const badge = h("span", { class: "slot-badge" }, String(seat.seat));
                badge.style.setProperty("--team", seat.team > 1 ? `var(--series-${((seat.team - 2) % 8) + 1})` : "var(--neutral)");
                return h("li", {}, badge, h("span", {}, seat.kind === "ai" ? (ais.get(seat.ai ?? "") ?? seat.ai ?? "AI") : (seat.name ?? "Open seat"), isNumber(seat.uid) ? h("span", { class: "dim" }, ` · uid ${seat.uid}`) : null), h("span", { class: "dim" }, `${seat.team > 1 ? `team ${seat.team - 1}` : "no team"} · ${["", "UEF", "Aeon", "Cybran", "Seraphim", "random faction"][seat.faction] ?? ""}`));
              }),
            ),
      ),
      reviewSection("Settings", "settings", changes.length === 0 ? h("p", { class: "dim" }, "Every setting at its default.") : h("dl", { class: "review-facts" }, ...changes.flatMap(([label, value]) => [h("dt", {}, label), h("dd", {}, value)]))),
      reviewSection(
        "Observers and start",
        "start",
        h(
          "dl",
          { class: "review-facts" },
          h("dt", {}, "Countdown"),
          h("dd", {}, countdown > 0 ? `${countdown} s once every player is ready` : "off"),
          h("dt", {}, "Open for"),
          h("dd", {}, `${lobbyMinutes} minutes`),
          h("dt", {}, "Observers"),
          h("dd", {}, observers.length === 0 ? "none" : observers.map((observer, i) => `${observer.name.trim() || `Observer ${i + 1}`}${svc && observer.uid.trim() !== "" ? ` (uid ${observer.uid.trim()})` : ""}${observer.referee ? " (referee)" : ""}`).join(", ") + (observers.some((observer) => !observer.referee) && observerDelay > 0 ? ` · ${observerDelay} s delay` : "")),
        ),
      ),
      reviewSection(
        "Placement",
        "placement",
        plan === null
          ? h("p", { class: "dim" }, "Not planned yet.")
          : svc
            ? h("p", {}, h("span", { class: `chip tone-${plan.fits ? "ok" : hostChoice === "" ? "warn" : "bad"}` }, plan.fits ? `Fits on ${formHostName()} now` : `Doesn't fit on ${formHostName()} now`), " ", hostChoice === "" ? (byPing ? "The service tries every host with the map, lowest worst player ping first." : "The service tries every host with the map, least loaded first.") : force ? "Started anyway (admin)." : "")
            : h("p", {}, h("span", { class: `chip tone-${plan.fits ? "ok" : "bad"}` }, plan.fits ? "Fits now" : ifFull === "queue" ? "Doesn't fit now: it will be queued" : "Doesn't fit now"), " ", auto ? "Auto" : "Picked by hand", plan.cpus.length > 0 ? `: CPU ${plan.cpus.join(", ")}, node ${plan.nodes.join(", ")}` : ""),
        plan !== null && plan.warnings.length > 0 ? warningList(plan.warnings) : null,
      ),
    );
  }

  // ---------------------------------------------------------------- the summary beside the steps
  function renderSummary(): void {
    const map = selectedMap();
    const seats = slots.seats();
    const humans = seats.filter((seat) => seat.kind === "human").length;
    const blocker = firstProblem();
    const create = h("button", { type: "button", class: "btn primary block" }, icon("rocket", "icon"), createLabel());
    create.disabled = creating || blocker !== null || planning;
    create.addEventListener("click", () => void create_());
    const row = (label: string, value: Child, target: Step): HTMLElement => {
      const link = h("button", { type: "button", class: "summary-row" }, h("span", { class: "summary-label" }, label), h("span", { class: "summary-value" }, value));
      link.addEventListener("click", () => go(target));
      return link;
    };
    fill(summary, 
      h("h2", {}, name.trim() || "New lobby"),
      h("p", { class: "dim small" }, svc ? `Organised · ${tournament()?.name ?? "no tournament"} · ${hostChoice === "" ? `${hostWords()} host` : hostChoice}` : kind === "tournament" ? "Tournament · the organiser runs it" : "Custom · a player hosts it"),
      summaryPreview.root,
      row("Seats", map === undefined ? "–" : `${plural(humans, "player")}, ${plural(seats.length - humans, "AI", "AIs")} of ${spotsOf(map).length} spots`, "slots"),
      row("Settings", chosen.size === 0 ? "all default" : `${chosen.size} changed`, "settings"),
      row("Observers", observers.length === 0 ? "none" : String(observers.length), "start"),
      row("Countdown", countdown > 0 ? `${countdown} s` : "off", "start"),
      row(
        "Placement",
        planning
          ? "planning…"
          : plan === null
            ? "–"
            : svc
              ? h("span", {}, h("span", { class: `chip tiny tone-${plan.fits ? "ok" : hostChoice === "" ? "warn" : "bad"}` }, plan.fits ? "fits" : "doesn't fit"), ` on ${formHostName()}`)
              : h("span", {}, h("span", { class: `chip tiny tone-${plan.fits ? "ok" : "bad"}` }, plan.fits ? "fits" : "doesn't fit"), plan.cpus.length > 0 ? ` CPU ${plan.cpus.join(", ")}` : ""),
        "placement",
      ),
      plan !== null && plan.warnings.length > 0 ? row("Warnings", `${plan.warnings.length}`, "placement") : null,
      h("div", { class: "summary-actions" }, create, blocker === null ? null : h("p", { class: "small bad-text" }, `${STEPS.find(([id]) => id === blocker.step)?.[1] ?? ""}: ${blocker.text}`)),
    );
    summaryPreview.update(map, slots.marks());
    if (step === "review") renderReview();
  }

  // ---------------------------------------------------------------- create
  async function create_(): Promise<void> {
    await create();
  }

  async function create(): Promise<void> {
    const api = store.api;
    const map = selectedMap();
    if (api === null || map === undefined || creating) return;
    const blocker = firstProblem();
    if (blocker !== null) {
      go(blocker.step);
      return;
    }
    if (svc) {
      await createThroughService(map);
      return;
    }
    const request: NewLobby = {
      name: name.trim() || `${kind === "tournament" ? "Tournament" : "Custom game"} on ${map.name ?? map.id}`,
      map: map.id,
      kind,
      control: kind === "tournament" ? "organiser" : "player",
      options: Object.fromEntries(chosen),
      seats: slots.seats(),
      start_when_ready: countdown,
      lobby_minutes: lobbyMinutes,
      cpus: "auto",
    };
    // What the map showed is what starts: the picked or planned CPUs; Auto again only when nothing fits now.
    if (!auto && picked.size > 0) request.cpus = [...picked].sort((a, b) => a - b);
    else if (plan !== null && plan.fits && plan.cpus.length > 0) request.cpus = [...plan.cpus];
    else request.cores = coresFixed > 0 ? coresFixed : (plan?.estimate.suggested_cores ?? 1);
    if (observers.length > 0) {
      request.observers = observers.map((observer) => (observer.referee ? { name: observer.name.trim(), referee: true } : { name: observer.name.trim() }));
      request.observer_delay_seconds = observers.some((observer) => !observer.referee) ? observerDelay : 0;
    }
    if (plan !== null && !plan.fits) {
      if (force) request.force = true;
      else if (ifFull === "queue") request.queue = true;
    }
    creating = true;
    renderFooter();
    renderSummary();
    try {
      const answer = await api.createLobby(request);
      if (answer.queued !== null) {
        toast("info", `${request.name} is queued`, `Position ${answer.queued.position ?? "?"} in the operator queue: it starts when it fits.`);
        reset();
        actions.refresh();
        location.hash = "#/queue";
      } else if (answer.lobby !== null) {
        toast("ok", `${answer.lobby.name ?? request.name} is starting`, `On CPU ${(answer.lobby.cpus ?? []).join(", ") || "?"}`);
        const id = answer.lobby.id;
        reset();
        actions.refresh();
        location.hash = `#/lobby/${encodeURIComponent(id)}`;
      }
    } catch (error) {
      toast("bad", "The host didn't create the lobby", error instanceof Error ? error.message : String(error));
    } finally {
      creating = false;
      renderFooter();
      renderSummary();
    }
  }

  /** The control service's lobby body for the form as it stands. */
  function serviceRequest(map: MapInfo): ServiceNewLobby {
    const request: ServiceNewLobby = {
      name: name.trim() || `${tournament()?.name ?? "Organised lobby"} on ${map.name ?? map.id}`,
      map: map.id,
      seats: slots.seats(),
      options: Object.fromEntries(chosen),
      start_when_ready: countdown,
      lobby_minutes: lobbyMinutes,
      cpus: "auto",
    };
    if (tournamentId !== "") request.tournament = tournamentId;
    if (hostChoice !== "") request.host = hostChoice;
    // On a named host, what the plan showed is what starts; else the service plans it on the host it picks.
    if (hostChoice !== "" && plan !== null && plan.fits && plan.cpus.length > 0) request.cpus = [...plan.cpus];
    else request.cores = coresFixed > 0 ? coresFixed : (plan?.estimate.suggested_cores ?? 1);
    if (observers.length > 0) {
      request.observers = observers.map((observer, index) => {
        const uid = Number(observer.uid.trim());
        return { name: observer.name.trim() || `Observer ${index + 1}`, ...(observer.uid.trim() !== "" && uid > 0 ? { uid } : {}), ...(observer.referee ? { referee: true } : {}) };
      });
      request.observer_delay_seconds = observers.some((observer) => !observer.referee) ? observerDelay : 0;
    }
    if (force && hostChoice !== "" && plan !== null && !plan.fits) request.force = true;
    if (byPing && hostChoice === "") request.placement = "ping";
    return request;
  }

  /** `POST /api/v1/lobbies` on the control service: organised, on the host picked, the least loaded one that fits, or
   * the one with the lowest worst player ping. */
  async function createThroughService(map: MapInfo): Promise<void> {
    const control = service.api;
    if (control === null) return;
    const request = serviceRequest(map);
    creating = true;
    renderFooter();
    renderSummary();
    try {
      const { lobby, placement } = await control.createLobbyPlaced(request);
      const row = placement?.hosts.find((item) => item.host === lobby.host);
      const ping = row !== undefined && row.worst_ms !== null ? ` · worst player ping ${num(row.worst_ms)} ms` : "";
      toast("ok", `${lobby.name || request.name} is starting`, `On ${lobby.host}${ping}`);
      reset();
      actions.refresh();
      location.hash = `#/lobby/${encodeURIComponent(lobby.key)}`;
    } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      const status = error instanceof ApiError ? error.status : 0;
      toast("bad", status === 409 ? "No host can take the lobby now" : status === 403 ? "Your role doesn't allow this lobby" : "The control service didn't create the lobby", why);
    } finally {
      creating = false;
      renderFooter();
      renderSummary();
    }
  }

  // ---------------------------------------------------------------- everything
  function renderStep(): void {
    if (step === "slots") {
      slots.render();
      preview.update(selectedMap(), slots.marks());
    }
    if (step === "placement") machine.update();
    if (step === "placement" && svc && byPing && hostChoice === "" && !pingLoading) void loadPing();
    if (step === "review") renderReview();
    customNote.hidden = kind !== "custom" || svc;
    startHelp.textContent =
      kind === "tournament" || svc ? "Nobody hosts an organised lobby: it starts from its page (Start now), or by itself after the countdown once every player is ready." : "The host player launches a custom lobby from their lobby screen; the countdown starts it by itself once every player is ready.";
  }

  function renderAll(): void {
    renderWhere();
    renderKind();
    gallery.select(mapId);
    gallery.refreshFit();
    renderStepper();
    renderStep();
    renderPlan();
    renderFooter();
    renderSummary();
  }

  function reset(): void {
    kind = "tournament";
    mapId = "";
    name = "";
    nameTouched = false;
    chosen.clear();
    observers = [];
    observerDelay = 0;
    countdown = 10;
    lobbyMinutes = 60;
    auto = true;
    picked.clear();
    coresFixed = 0;
    ifFull = "queue";
    force = false;
    plan = null;
    planError = "";
    pingPlacement = null;
    pingError = "";
    slots.slots = [];
    countdownInput.value = "10";
    minutesInput.value = "60";
    delayInput.value = "0";
    nameInput.value = "";
    renderObservers();
    renderFull();
    if (maps.length > 0) {
      const preferred = maps.find((map) => map.preview && (map.players ?? 0) >= 2 && (map.players ?? 0) <= 8) ?? maps[0];
      if (preferred !== undefined) selectMap(preferred.id);
    }
    go("map");
  }

  countdownInput.value = "10";
  minutesInput.value = "60";
  delayInput.value = "0";
  renderObservers();
  renderFull();

  /** Through the service, for a viewer who may not make lobbies: what they can do instead. */
  function renderRefusal(): boolean {
    const me = service.me;
    const allowed = !svc || canOrganise(me, "") || (me?.tournaments ?? []).some((item) => canOrganise(me, item.id));
    refusal.hidden = allowed;
    layout.hidden = !allowed;
    startOver.hidden = !allowed;
    if (!allowed) {
      refusal.replaceChildren(
        emptyState(
          "Making lobbies is for organisers",
          `You are signed in as a player. Organised lobbies are made by admins and the organisers of a tournament (the service's configuration lists them).${me?.player_hosting ? " You can ask for a game you host under My games." : ""}`,
          me?.player_hosting ? h("a", { class: "btn primary", href: "#/games" }, "My games") : null,
        ),
      );
    }
    return allowed;
  }

  return {
    show(arg): void {
      const wasSvc = svc;
      svc = store.mode === "service";
      if (svc) kind = "tournament";
      headSub.textContent = svc
        ? "An organised lobby on the host you pick, the least loaded one that fits, or the one with the lowest worst player ping; a tournament's lists decide who plays and watches. Every step can be changed again before Create."
        : "A tournament lobby the organiser runs, or a custom one a player hosts. Every step can be changed again before Create.";
      if (wasSvc !== svc) {
        maps = [];
        mapsFrom = "";
        mapId = "";
        plan = null;
        gallery.setMaps([], "");
      }
      if (!renderRefusal()) return;
      if (offs.length === 0) {
        offs = [
          on("host", () => {
            if (step === "placement") machine.update();
          }),
          on("lists", () => {
            // Lobbies coming or going change what fits.
            schedulePlan();
          }),
          on("service", () => {
            if (!svc) return;
            if (!renderRefusal()) return;
            renderWhere();
            if (mapsFrom !== (formApi()?.base ?? "")) void loadMaps();
          }),
        ];
      }
      const preset = /^host=(.+)$/.exec(arg ?? "");
      if (svc && preset !== null) {
        hostChoice = preset[1] ?? "";
        byPing = false;
        mapsFrom = "";
      }
      if (maps.length === 0 || mapsFrom !== (formApi()?.base ?? "")) void loadMaps();
      const target = STEPS.find(([id]) => id === arg)?.[0];
      go(target ?? (preset !== null ? "map" : step));
      renderAll();
    },
    hide(): void {
      for (const off of offs) off();
      offs = [];
    },
  };
}
