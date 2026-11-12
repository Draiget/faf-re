// Create lobby: a full page in six steps with a summary beside them that follows every change. 1. kind (tournament or
// custom), name and map from a gallery of previews; 2. the slots: the map's start spots drawn on its preview, each
// spot a player, an AI or empty, with team and faction; 3. every game setting with its default (changed ones marked)
// and the map's own options; 4. observers and start rules; 5. placement: Auto or CPUs picked on the machine map, the
// planner's estimate and warnings live, and what to do when it doesn't fit (queue it or refuse); 6. review, then
// create. The host is asked for a plan on every change; nothing starts before Create.

import { ApiError, type MapInfo, type NewLobby, type Plan, type PlanRequest, type SettingKey, type Settings } from "../api.ts";
import { byId, fill, h, icon, isNumber, num, type Child } from "../dom.ts";
import { MapGallery, MapPreview, mapArt, mapFacts, spotsOf } from "../maps.ts";
import { MachineMap } from "../plane/machine.ts";
import { countChanges, FALLBACK_OPTIONS, filterOptions, pruneChosen, renderOptions, sameKey } from "../plane/options.ts";
import { rate, warningList } from "../plane/parts.ts";
import { actions, coresOf, nodeOf, cpuById, on, plural, poolCpus, store } from "../plane/store.ts";
import { SlotsEditor, type SlotKind } from "../slots.ts";
import { toast } from "../ui.ts";
import { hostMaps, hostPreview, pageHead, type View } from "./common.ts";

const PLAN_DEBOUNCE_MS = 250;
const REQUEST_MS = 5000;
const MAX_OBSERVERS = 32;

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
}

export function createView(): View {
  const root = byId<HTMLElement>("view-create");

  // ---------------------------------------------------------------- state
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

  // ---------------------------------------------------------------- pieces
  const slots = new SlotsEditor({ ais: aiChoices, uid: true, onChange: () => onSlotsChanged() });
  const preview = new MapPreview(hostPreview, (spot) => slots.focusSpot(spot));
  const summaryPreview = new MapPreview(hostPreview);
  const gallery = new MapGallery({ source: hostPreview, onSelect: (map) => selectMap(map.id), minSpots: () => Math.max(1, slots.filled()) });
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
  root.replaceChildren(
    pageHead("Create lobby", "A tournament lobby the organiser runs, or a custom one a player hosts. Every step can be changed again before Create.", startOver, h("a", { class: "btn", href: "#/lobbies" }, "Cancel")),
    h("div", { class: "create-layout" }, h("div", { class: "create-main" }, stepper, ...panels.values(), footer), summary),
  );
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
        return selectedMap() === undefined ? "Pick a map." : "";
      case "slots":
        return slots.problem();
      case "start":
        return observers.some((observer) => observer.name.trim().length > 40) ? "An observer's name is longer than 40 characters." : "";
      case "placement":
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
          h("span", { class: "step-text" }, h("span", { class: "step-label" }, label), h("span", { class: "step-sub" }, stepSub(id))),
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
        return planning ? "planning…" : plan === null ? "–" : plan.fits ? `fits${auto ? " (Auto)" : ""}` : ifFull === "queue" ? "doesn't fit now: queued" : "doesn't fit now";
      default:
        return "check and create";
    }
  }

  function renderFooter(): void {
    back.disabled = stepIndex() === 0;
    const problem = stepProblem(step);
    stepNote.textContent = problem !== "" ? problem : `Step ${stepIndex() + 1} of ${STEPS.length}`;
    stepNote.classList.toggle("bad-text", problem !== "");
    if (step === "review") {
      const blocker = firstProblem();
      next.replaceChildren(icon("rocket", "icon"), plan !== null && !plan.fits && ifFull === "queue" && !force ? "Create and queue" : "Create lobby");
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
  panels.get("map")?.append(
    h("div", { class: "form-block" }, h("h2", {}, "What kind of lobby"), kindCards),
    h("div", { class: "form-block narrow-field" }, h("label", { for: "create-name", class: "field-label" }, "Name ", h("span", { class: "dim" }, "(shown on the dashboard and in the players' lobby)")), nameInput),
    h("div", { class: "form-block" }, h("div", { class: "block-head" }, h("h2", {}, "Map"), galleryNote), gallery.root),
  );

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
    name = `${kind === "tournament" ? "Tournament" : "Custom game"}${map === undefined ? "" : ` on ${map.name ?? map.id}`}`;
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

  async function loadMaps(): Promise<void> {
    galleryNote.textContent = "Loading the host's maps…";
    try {
      maps = await hostMaps();
      galleryNote.textContent = "Dots are the start spots. Sizes are the map's side.";
      if (mapId === "" && maps.length > 0) {
        const preferred = maps.find((map) => map.preview && (map.players ?? 0) >= 2 && (map.players ?? 0) <= 8) ?? maps[0];
        if (preferred !== undefined) selectMap(preferred.id);
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
    const api = store.api;
    if (api === null || mapId === "") return;
    const key = mapId;
    const cached = settingsCache.get(key);
    if (cached !== undefined) {
      useSettings(cached);
      return;
    }
    settingsMeta.textContent = "loading…";
    try {
      const answer = await api.settings(key, AbortSignal.timeout(REQUEST_MS));
      settingsCache.set(key, answer);
      if (key === mapId) useSettings(answer);
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
    observers.push({ name: "", referee: false });
    renderObservers();
    observerRows.querySelectorAll("input")[observers.length * 2 - 2]?.focus();
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

  function renderObservers(): void {
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
        return h("div", { class: "observer-row" }, nameField, h("label", { class: "check" }, referee, h("span", {}, "Referee (live)")), remove);
      }),
    );
    observerAdd.disabled = observers.length >= MAX_OBSERVERS;
    delayField.hidden = !observers.some((observer) => !observer.referee);
    renderSummary();
    renderStepper();
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
  panels.get("placement")?.append(
    h(
      "div",
      { class: "placement-layout" },
      h(
        "div",
        { class: "placement-main" },
        h("h2", {}, "Where it runs"),
        modeCards,
        coresBox,
        h("div", { class: "picked-row" }, pickedLine, clearPicks),
        machine.root,
      ),
      h(
        "div",
        { class: "placement-side" },
        h("h2", {}, "What it needs"),
        estimateBox,
        h("h3", { class: "sub-head" }, "Warnings"),
        warningsBox,
        h("h3", { class: "sub-head" }, "If it doesn't fit now"),
        fullCards,
        forceBox,
      ),
    ),
  );

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
      fill(estimateBox, h("p", { class: "form-error" }, `The host couldn't plan it: ${planError}`));
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
    forceBox.hidden = !blocked;
    forceInput.checked = force;
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
    if (store.api === null || selectedMap() === undefined) return;
    planning = true;
    planTimer = window.setTimeout(() => void runPlan(), PLAN_DEBOUNCE_MS);
  }

  async function runPlan(): Promise<void> {
    const api = store.api;
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
        h("dl", { class: "review-facts" }, h("dt", {}, "Name"), h("dd", {}, name.trim() || "(the host names it)"), h("dt", {}, "Kind"), h("dd", {}, kind === "tournament" ? "Tournament: the organiser runs it, nobody hosts" : "Custom: the player on spot 1 hosts"), h("dt", {}, "Map"), h("dd", {}, map === undefined ? "–" : `${map.name ?? map.id} · ${mapFacts(map)}`)),
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
                return h("li", {}, badge, h("span", {}, seat.kind === "ai" ? (ais.get(seat.ai ?? "") ?? seat.ai ?? "AI") : (seat.name ?? "Open seat")), h("span", { class: "dim" }, `${seat.team > 1 ? `team ${seat.team - 1}` : "no team"} · ${["", "UEF", "Aeon", "Cybran", "Seraphim", "random faction"][seat.faction] ?? ""}`));
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
          h("dd", {}, observers.length === 0 ? "none" : observers.map((observer, i) => `${observer.name.trim() || `Observer ${i + 1}`}${observer.referee ? " (referee)" : ""}`).join(", ") + (observers.some((observer) => !observer.referee) && observerDelay > 0 ? ` · ${observerDelay} s delay` : "")),
        ),
      ),
      reviewSection(
        "Placement",
        "placement",
        plan === null ? h("p", { class: "dim" }, "Not planned yet.") : h("p", {}, h("span", { class: `chip tone-${plan.fits ? "ok" : "bad"}` }, plan.fits ? "Fits now" : ifFull === "queue" ? "Doesn't fit now: it will be queued" : "Doesn't fit now"), " ", auto ? "Auto" : "Picked by hand", plan.cpus.length > 0 ? `: CPU ${plan.cpus.join(", ")}, node ${plan.nodes.join(", ")}` : ""),
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
    const create = h("button", { type: "button", class: "btn primary block" }, icon("rocket", "icon"), plan !== null && !plan.fits && ifFull === "queue" && !force ? "Create and queue" : "Create lobby");
    create.disabled = creating || blocker !== null || planning;
    create.addEventListener("click", () => void create_());
    const row = (label: string, value: Child, target: Step): HTMLElement => {
      const link = h("button", { type: "button", class: "summary-row" }, h("span", { class: "summary-label" }, label), h("span", { class: "summary-value" }, value));
      link.addEventListener("click", () => go(target));
      return link;
    };
    fill(summary, 
      h("h2", {}, name.trim() || "New lobby"),
      h("p", { class: "dim small" }, kind === "tournament" ? "Tournament · the organiser runs it" : "Custom · a player hosts it"),
      summaryPreview.root,
      row("Seats", map === undefined ? "–" : `${plural(humans, "player")}, ${plural(seats.length - humans, "AI", "AIs")} of ${spotsOf(map).length} spots`, "slots"),
      row("Settings", chosen.size === 0 ? "all default" : `${chosen.size} changed`, "settings"),
      row("Observers", observers.length === 0 ? "none" : String(observers.length), "start"),
      row("Countdown", countdown > 0 ? `${countdown} s` : "off", "start"),
      row(
        "Placement",
        planning ? "planning…" : plan === null ? "–" : h("span", {}, h("span", { class: `chip tiny tone-${plan.fits ? "ok" : "bad"}` }, plan.fits ? "fits" : "doesn't fit"), plan.cpus.length > 0 ? ` CPU ${plan.cpus.join(", ")}` : ""),
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

  // ---------------------------------------------------------------- everything
  function renderStep(): void {
    if (step === "slots") {
      slots.render();
      preview.update(selectedMap(), slots.marks());
    }
    if (step === "placement") machine.update();
    if (step === "review") renderReview();
    customNote.hidden = kind !== "custom";
    startHelp.textContent =
      kind === "tournament" ? "Nobody hosts a tournament lobby: it starts from its page (Start now), or by itself after the countdown once every player is ready." : "The host player launches a custom lobby from their lobby screen; the countdown starts it by itself once every player is ready.";
  }

  function renderAll(): void {
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

  return {
    show(arg): void {
      if (offs.length === 0) {
        offs = [
          on("host", () => {
            if (step === "placement") machine.update();
          }),
          on("lists", () => {
            // Lobbies coming or going change what fits.
            schedulePlan();
          }),
        ];
      }
      if (maps.length === 0) void loadMaps();
      const target = STEPS.find(([id]) => id === arg)?.[0];
      go(target ?? step);
      renderAll();
    },
    hide(): void {
      for (const off of offs) off();
      offs = [];
    },
  };
}
