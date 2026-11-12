// Player hosting: whether players may ask for a server, and the capacity their games get. On or off; the pool's CPUs
// picked on the machine map as whole cores (or a whole NUMA node); games at once, the largest player count, cores per
// game (from map and players, or fixed) with the planner's hint of how many games of a typical size fit; how long a
// lobby waits; access (open, or with a code); the default settings; the link to hand out; and live, the games running
// on the pool and its queue. Changes are kept as a draft until Save.

import type { Estimate, Pool, PoolUpdate, SettingKey, Settings } from "../api.ts";
import { byId, fill, h, icon, isNumber, type Child } from "../dom.ts";
import { MachineMap } from "../plane/machine.ts";
import { countChanges, filterOptions, pruneChosen, renderOptions } from "../plane/options.ts";
import { emptyState, loopback, stateChip, swatch } from "../plane/parts.ts";
import { actions, coresOf, cpuById, displayName, holderOf, isPoolLobby, nodeOf, on, plural, RUNNING, siblingsOf, store } from "../plane/store.ts";
import { confirmAction, copyButton, toast } from "../ui.ts";
import { pageHead, type View } from "./common.ts";

/** The public request page, next to this page, pointed at the host. */
export function requestLink(hostBase: string): string {
  const url = new URL("request.html", window.location.href);
  url.search = new URLSearchParams({ host: hostBase }).toString();
  url.hash = "";
  return url.toString();
}

function randomCode(): string {
  const bytes = new Uint8Array(5);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => "abcdefghjkmnpqrstuvwxyz23456789"[byte % 31]).join("");
}

export function hostingView(): View {
  const root = byId<HTMLElement>("view-hosting");
  let draft: Pool | null = null;
  let saved: Pool | null = null;
  const options = new Map<string, SettingKey>();
  let settings: Settings | null = null;
  let typical: Estimate | null = null;
  let largest: Estimate | null = null;
  let hintKey = "";
  let saving = false;
  let offs: (() => void)[] = [];

  const switchInput = h("input", { type: "checkbox", role: "switch", id: "pool-enabled" });
  const switchText = h("span", { class: "switch-text" });
  const sub = h("span", {});
  const cpuSummary = h("div", { class: "pool-summary" });
  const machine = new MachineMap({
    mode: "pick",
    wholeCores: true,
    nodeButtons: true,
    pickedLabel: "In the pool (draft)",
    selected: () => new Set(draft?.cpus ?? []),
    pool: () => new Set(draft?.cpus ?? []),
    onToggle: (cpus, turnOn) => {
      if (draft === null) return;
      const set = new Set(draft.cpus);
      // Whole cores only: a CPU brings its siblings.
      for (const id of cpus.flatMap(siblingsOf)) {
        if (turnOn) set.add(id);
        else set.delete(id);
      }
      draft.cpus = [...set].sort((a, b) => a - b);
      changed();
    },
  });
  const limits = h("div", { class: "form-grid" });
  const hint = h("div", { class: "fit-hint" });
  const access = h("div", {});
  const link = h("div", {});
  const live = h("div", {});
  const settingsBox = h("div", { class: "settings-form wide" });
  const settingsMeta = h("span", { class: "card-meta" });
  const settingsFilter = h("input", { type: "search", placeholder: "Filter settings", spellcheck: "false", "aria-label": "Filter settings" });
  settingsFilter.addEventListener("input", () => filterOptions(settingsBox, settingsFilter.value));
  const saveBar = h("div", { class: "save-bar", hidden: true });
  const body = h("div", { class: "hosting-body" });

  root.replaceChildren(
    pageHead("Player hosting", sub, h("label", { class: "switch big-switch", for: "pool-enabled" }, switchInput, h("span", { class: "switch-track", "aria-hidden": "true" }), switchText)),
    body,
    saveBar,
  );
  body.append(
    h(
      "div",
      { class: "grid-main-side" },
      h(
        "div",
        { class: "stack" },
        h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "CPUs for player games"), h("span", { class: "card-meta" }, "Click a core to add it or take it out; whole cores only.")), cpuSummary, machine.root),
        h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Now on the pool"), h("span", { class: "card-meta" }, h("a", { href: "#/queue" }, "The queue"))), live),
      ),
      h(
        "div",
        { class: "stack" },
        h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Limits")), limits, hint),
        h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Who may ask")), access, link),
      ),
    ),
    h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Default settings of player games"), settingsMeta), h("p", { class: "dim small section-help" }, "Where a requested game starts; the player may change them on the request page and in their lobby."), h("div", { class: "settings-tools" }, settingsFilter), settingsBox),
  );

  switchInput.addEventListener("change", () => void toggle(switchInput.checked));

  async function toggle(turnOn: boolean): Promise<void> {
    const api = store.api;
    if (api === null || saved === null) return;
    let update: PoolUpdate = { enabled: turnOn };
    if (!turnOn) {
      const queued = store.pool?.usage.queued ?? 0;
      const dialog = await offDialog(queued);
      if (dialog === null) {
        switchInput.checked = true;
        return;
      }
      update = { enabled: false, drop_queue: dialog };
    } else if (draft !== null && draft.cpus.length === 0) {
      toast("warn", "Pick the pool's CPUs first", "Player hosting with no CPUs can't start any game: every request would wait.");
    }
    try {
      const answer = await api.setPool(update);
      store.pool = answer;
      saved = answer.pool;
      if (draft !== null) draft.enabled = answer.pool.enabled;
      toast("ok", `Player hosting is ${answer.pool.enabled ? "on" : "off"}`, answer.pool.enabled ? "Players can ask for a server with the request link." : "New requests are refused; running games finish.");
    } catch (error) {
      switchInput.checked = !turnOn;
      toast("bad", "The host didn't change it", error instanceof Error ? error.message : String(error));
    }
    actions.refresh();
    renderAll();
  }

  /** Asks before turning it off; null to keep it on, else whether to refuse what waits. */
  async function offDialog(queued: number): Promise<boolean | null> {
    if (queued === 0) return (await confirmAction("Turn player hosting off?", "New requests are refused. Games running on the pool play on until they end.", "Turn it off")) ? false : null;
    const ok = await confirmAction("Turn player hosting off?", `New requests are refused and games running on the pool play on. ${plural(queued, "request")} ${queued === 1 ? "waits" : "wait"} in the queue: they are refused too.`, "Turn off and refuse the queue");
    return ok ? true : null;
  }

  function changes(): PoolUpdate {
    if (draft === null || saved === null) return {};
    const out: PoolUpdate = {};
    if (JSON.stringify(draft.cpus) !== JSON.stringify([...saved.cpus].sort((a, b) => a - b))) out.cpus = draft.cpus;
    for (const key of ["max_games", "max_players", "cores", "lobby_minutes", "max_queue", "access", "code"] as const) if (draft[key] !== saved[key]) (out as Record<string, unknown>)[key] = draft[key];
    const opts = Object.fromEntries(options);
    if (JSON.stringify(opts) !== JSON.stringify(saved.options)) out.options = opts;
    return out;
  }

  function changed(): void {
    machine.update();
    renderCpuSummary();
    renderLimits();
    renderSaveBar();
    void loadHint();
  }

  function renderSaveBar(): void {
    const update = changes();
    const count = Object.keys(update).length;
    saveBar.hidden = count === 0;
    if (count === 0) return;
    const names: Record<string, string> = { cpus: "CPUs", max_games: "games at once", max_players: "players per game", cores: "cores per game", lobby_minutes: "lobby time", max_queue: "queue length", access: "access", code: "access code", options: "default settings" };
    const save = h("button", { type: "button", class: "btn primary" }, "Save");
    save.disabled = saving;
    save.addEventListener("click", () => void saveDraft());
    const discard = h("button", { type: "button", class: "btn" }, "Discard");
    discard.addEventListener("click", () => {
      draft = saved === null ? null : { ...saved, cpus: [...saved.cpus] };
      options.clear();
      for (const [key, value] of Object.entries(saved?.options ?? {})) options.set(key, value);
      renderAll();
    });
    saveBar.replaceChildren(h("span", {}, icon("info", "icon"), h("b", {}, `Unsaved: `), Object.keys(update).map((key) => names[key] ?? key).join(", ")), h("span", { class: "save-buttons" }, discard, save));
  }

  async function saveDraft(): Promise<void> {
    const api = store.api;
    const update = changes();
    if (api === null || Object.keys(update).length === 0) return;
    if (draft?.access === "code" && draft.code.trim() === "") {
      toast("bad", "The access code is empty", "Type one or make one, or let anyone ask.");
      return;
    }
    saving = true;
    renderSaveBar();
    try {
      const answer = await api.setPool(update);
      store.pool = answer;
      saved = answer.pool;
      draft = { ...answer.pool, cpus: [...answer.pool.cpus].sort((a, b) => a - b) };
      toast("ok", "Player hosting saved", `${plural(answer.pool.cpus.length, "CPU")} · up to ${answer.pool.max_games} games`);
      if (answer.warnings.length > 0) toast("warn", "Saved, with a warning", answer.warnings.map((warning) => warning.text).join(" "));
    } catch (error) {
      toast("bad", "The host didn't save it", error instanceof Error ? error.message : String(error));
    } finally {
      saving = false;
    }
    actions.refresh();
    renderAll();
  }

  function renderCpuSummary(): void {
    if (draft === null) return;
    const cpus = draft.cpus;
    const nodes = [...new Set(cpus.map((id) => cpuById(id)).filter((cpu) => cpu !== undefined).map((cpu) => nodeOf(cpu)))].sort();
    const all = store.info?.cpus.length ?? 0;
    const busy = cpus.filter((id) => {
      const holder = holderOf(id);
      return holder !== undefined && !isPoolLobby(holder);
    });
    const notes: Child[] = [];
    if (nodes.length > 1) notes.push(h("li", { class: "warning tone-info" }, icon("info", "icon tiny"), "The pool spans NUMA nodes: each game still goes on one node."));
    if (busy.length > 0) notes.push(h("li", { class: "warning tone-warn" }, icon("warn", "icon tiny"), `CPU ${busy.join(", ")} ${busy.length === 1 ? "runs" : "run"} an operator lobby now: player games get ${busy.length === 1 ? "it" : "them"} when it ends.`));
    if (cpus.length === 0) notes.push(h("li", { class: "warning tone-warn" }, icon("warn", "icon tiny"), "No CPUs: no player game can start."));
    fill(cpuSummary, 
      h(
        "div",
        { class: "pool-numbers" },
        h("div", {}, h("span", { class: "big-number" }, String(coresOf(cpus))), h("span", { class: "dim" }, ` ${coresOf(cpus) === 1 ? "core" : "cores"} (${plural(cpus.length, "CPU")})${nodes.length > 0 ? ` on node ${nodes.join(", ")}` : ""} for player games`)),
        h("div", {}, h("span", { class: "big-number" }, String(coresOf((store.info?.cpus ?? []).map((cpu) => cpu.id).filter((id) => !cpus.includes(id))))), h("span", { class: "dim" }, ` cores (${plural(all - cpus.length, "CPU")}) left for operator lobbies; Auto doesn't pick the pool's`)),
      ),
      notes.length === 0 ? null : h("ul", { class: "warnings" }, ...notes),
    );
  }

  function numberField(id: string, label: string, help: string, value: number, min: number, max: number, set: (value: number) => void): HTMLElement {
    const input = h("input", { id, type: "number", min, max, inputmode: "numeric", value });
    input.addEventListener("input", () => {
      const parsed = Math.round(Number(input.value));
      if (Number.isFinite(parsed) && parsed >= min && parsed <= max) {
        set(parsed);
        renderSaveBar();
        renderHint();
        void loadHint();
      }
    });
    return h("div", { class: "field" }, h("label", { for: id }, label), input, h("span", { class: "dim small" }, help));
  }

  function renderLimits(): void {
    if (draft === null) return;
    const d = draft;
    const coresAuto = h("input", { type: "radio", name: "pool-cores", value: "auto" });
    coresAuto.checked = d.cores === 0;
    const coresFixed = h("input", { type: "radio", name: "pool-cores", value: "fixed" });
    coresFixed.checked = d.cores > 0;
    const coresCount = h("input", { type: "number", min: 1, max: 32, inputmode: "numeric", "aria-label": "Cores per game", value: d.cores > 0 ? d.cores : (typical?.suggested_cores ?? 1) });
    coresCount.disabled = d.cores === 0;
    const setCores = (): void => {
      d.cores = coresFixed.checked ? Math.max(1, Math.round(Number(coresCount.value) || 1)) : 0;
      coresCount.disabled = d.cores === 0;
      renderSaveBar();
      renderHint();
    };
    coresAuto.addEventListener("change", setCores);
    coresFixed.addEventListener("change", setCores);
    coresCount.addEventListener("input", setCores);
    const players = h("select", { id: "pool-players" }, ...Array.from({ length: 15 }, (_, i) => h("option", { value: String(i + 2) }, `${i + 2} players`)));
    players.value = String(Math.min(16, Math.max(2, d.max_players)));
    players.addEventListener("change", () => {
      d.max_players = Number(players.value);
      renderSaveBar();
      void loadHint();
    });
    limits.replaceChildren(
      numberField("pool-games", "Games at once", "More requests wait in the queue.", d.max_games, 0, 64, (value) => (d.max_games = value)),
      h("div", { class: "field" }, h("label", { for: "pool-players" }, "Largest game"), players, h("span", { class: "dim small" }, "Seats in one game, AIs included.")),
      h(
        "div",
        { class: "field span-2" },
        h("span", { class: "field-label" }, "Cores per game"),
        h("div", { class: "inline-choices" }, h("label", { class: "check" }, coresAuto, h("span", {}, "From the map and players (suggested)")), h("label", { class: "check" }, coresFixed, h("span", {}, "Always")), coresCount, h("span", { class: "dim small" }, "cores")),
      ),
      numberField("pool-minutes", "Lobby open for (minutes)", "Without a game by then, it stops.", d.lobby_minutes, 1, 1440, (value) => (d.lobby_minutes = value)),
      numberField("pool-queue", "Longest queue", "Past it, requests are refused.", d.max_queue, 0, 500, (value) => (d.max_queue = value)),
    );
    renderHint();
  }

  async function loadHint(): Promise<void> {
    const api = store.api;
    if (api === null || draft === null) return;
    const key = `${draft.max_players}`;
    if (key === hintKey) return;
    hintKey = key;
    try {
      const [a, b] = await Promise.all([api.plan({ players: Math.min(4, draft.max_players), km: 10, side: "pool" }), api.plan({ players: draft.max_players, km: 20, side: "pool" })]);
      typical = a.estimate;
      largest = b.estimate;
    } catch {
      typical = null;
      largest = null;
    }
    renderHint();
  }

  function renderHint(): void {
    if (draft === null) return;
    const cores = coresOf(draft.cpus);
    const line = (title: string, estimate: Estimate | null): HTMLElement => {
      const need = draft !== null && draft.cores > 0 ? draft.cores : isNumber(estimate?.suggested_cores) ? estimate.suggested_cores : null;
      const fit = need === null || need === 0 ? null : Math.floor(cores / need);
      const limited = fit !== null && draft !== null && draft.max_games > 0 ? Math.min(fit, draft.max_games) : fit;
      return h(
        "li",
        {},
        h("span", { class: "fit-title" }, title),
        need === null ? h("span", { class: "dim" }, "asking the planner…") : h("span", {}, `needs ${plural(need, "core")}${isNumber(estimate?.memory_mb) ? ` and about ${estimate.memory_mb} MB` : ""}: `, h("b", {}, fit === null ? "–" : `${plural(limited ?? 0, "game")} at once`), fit !== null && draft !== null && fit > draft.max_games && draft.max_games > 0 ? h("span", { class: "dim" }, ` (room for ${fit}; the limit is ${draft.max_games})`) : fit === 0 ? h("span", { class: "bad-text" }, " (the pool is too small)") : null),
      );
    };
    hint.replaceChildren(h("h3", { class: "sub-head" }, "What fits"), h("ul", { class: "fit-list" }, line(`A typical game (${Math.min(4, draft.max_players)} players, 10 km map)`, typical), line(`The largest (${draft.max_players} players, 20 km map)`, largest)));
  }

  function renderAccess(): void {
    if (draft === null) return;
    const d = draft;
    const open = h("input", { type: "radio", name: "pool-access", value: "open" });
    open.checked = d.access !== "code";
    const code = h("input", { type: "radio", name: "pool-access", value: "code" });
    code.checked = d.access === "code";
    const codeInput = h("input", { placeholder: "the code players type", spellcheck: "false", autocomplete: "off", maxlength: 40, "aria-label": "Access code", value: d.code });
    codeInput.disabled = d.access !== "code";
    const make = h("button", { type: "button", class: "btn small" }, "Make one");
    make.disabled = d.access !== "code";
    const set = (): void => {
      d.access = code.checked ? "code" : "open";
      if (d.access === "code" && d.code === "") d.code = randomCode();
      renderAccess();
      renderSaveBar();
    };
    open.addEventListener("change", set);
    code.addEventListener("change", set);
    codeInput.addEventListener("input", () => {
      d.code = codeInput.value.trim();
      renderSaveBar();
    });
    make.addEventListener("click", () => {
      d.code = randomCode();
      renderAccess();
      renderSaveBar();
    });
    fill(access, 
      h(
        "div",
        { class: "choice-cards compact" },
        h("label", { class: "choice" }, open, h("span", { class: "choice-body" }, h("strong", {}, "Anyone with the link"), h("span", {}, "Limited per address: a few requests a minute, one live request per player name."))),
        h("label", { class: "choice" }, code, h("span", { class: "choice-body" }, h("strong", {}, "With an access code"), h("span", {}, "Players type the code you hand out with the link."))),
      ),
      h("div", { class: "input-row code-row" }, codeInput, make, d.access === "code" && d.code !== "" ? copyButton(d.code, "Copy the access code") : null),
    );
    const base = store.api?.base ?? "";
    const url = base === "" ? "" : requestLink(base);
    fill(link, 
      h("h3", { class: "sub-head" }, "The request link"),
      url === "" ? h("p", { class: "dim" }, "Not connected.") : h("div", { class: "join-cmd" }, h("a", { class: "cmd", href: url, target: "_blank", rel: "noopener" }, url), copyButton(url, "Copy the request link")),
      base !== "" && loopback(base) ? h("p", { class: "note tone-warn" }, `The link points at ${new URL(base).host}, which only this machine reaches: connect the dashboard with the host's public address to hand it out.`) : null,
      saved?.enabled === false ? h("p", { class: "note tone-warn" }, "Player hosting is off: the page says so and takes no requests.") : null,
    );
  }

  function renderLive(): void {
    const view = store.pool;
    const games = store.lobbies.filter((lobby) => isPoolLobby(lobby) && RUNNING.has(lobby.state));
    const waiting = store.queue.filter((item) => item.side === "pool");
    fill(live, 
      h(
        "div",
        { class: "pool-live" },
        h("div", { class: "pool-numbers" }, h("div", {}, h("span", { class: "big-number" }, `${view?.usage.games ?? games.length}`), h("span", { class: "dim" }, ` of ${view?.pool.max_games ?? "?"} games running`)), h("div", {}, h("span", { class: "big-number" }, String(view?.usage.queued ?? waiting.length)), h("span", { class: "dim" }, " waiting")), h("div", {}, h("span", { class: "big-number" }, String(view?.usage.free_cores ?? "–")), h("span", { class: "dim" }, (view?.usage.free_cores ?? 0) === 1 ? " free core" : " free cores"))),
        games.length === 0
          ? emptyState("No player game runs", saved?.enabled === true ? "Games players ask for show here while they run." : "Turn player hosting on to take requests.")
          : h(
              "ul",
              { class: "pool-games" },
              ...games.map((lobby) => {
                const host = (lobby.seats ?? []).find((seat) => seat.seat === 1)?.name ?? "";
                return h("li", {}, swatch(lobby.id), h("a", { href: `#/lobby/${encodeURIComponent(lobby.id)}` }, displayName(lobby)), stateChip(lobby.state), h("span", { class: "dim small" }, `${host === "" ? "" : `${host} · `}${lobby.map?.name ?? ""} · ${plural((lobby.seats ?? []).length, "seat")} · CPU ${(lobby.cpus ?? []).join(", ")}`));
              }),
            ),
        waiting.length === 0 ? null : h("p", { class: "small" }, `${plural(waiting.length, "request")} waiting: `, waiting.slice(0, 5).map((item) => `#${item.position ?? "?"} ${item.player ?? item.name ?? item.id}`).join(", "), " · ", h("a", { href: "#/queue" }, "manage the queue")),
      ),
    );
  }

  async function loadSettings(): Promise<void> {
    const api = store.api;
    if (api === null || settings !== null) return;
    try {
      settings = await api.settings();
      pruneChosen(options, settings);
      renderSettings();
    } catch (error) {
      settingsBox.replaceChildren(h("p", { class: "dim" }, `The settings didn't load: ${error instanceof Error ? error.message : String(error)}`));
    }
  }

  function renderSettings(): void {
    if (settings === null) return;
    renderOptions(settingsBox, { ...settings, map_options: [] }, null, {
      chosen: options,
      idPrefix: "pool-set-",
      openAll: true,
      onChange: () => {
        settingsMeta.textContent = `${countChanges(settingsBox)} changed from FAF's defaults`;
        renderSaveBar();
      },
    });
    settingsMeta.textContent = `${countChanges(settingsBox)} changed from FAF's defaults`;
    filterOptions(settingsBox, settingsFilter.value);
  }

  function renderHead(): void {
    const view = store.pool;
    switchInput.checked = saved?.enabled === true;
    switchInput.disabled = saved === null;
    switchText.textContent = saved?.enabled === true ? "On: players can ask for a server" : "Off: players can't ask for a server";
    sub.textContent = view === null ? "" : view.pool.enabled ? `${view.usage.games} of ${view.pool.max_games} games running on ${plural(view.pool.cpus.length, "CPU")}, ${view.usage.queued} waiting.` : "Players can't ask for a server now. Pick the pool's CPUs and limits, then turn it on.";
  }

  function renderAll(): void {
    if (!store.poolSupported) {
      body.replaceChildren(emptyState("This host has no player hosting", "Its server-host is older than player hosting: update it to give players a pool to ask for servers on."));
      saveBar.hidden = true;
      return;
    }
    if (draft === null) {
      fill(cpuSummary, h("p", { class: "dim" }, "Loading…"));
      return;
    }
    renderHead();
    machine.update();
    renderCpuSummary();
    renderLimits();
    renderAccess();
    renderLive();
    renderSettings();
    renderSaveBar();
  }

  function fromStore(): void {
    const view = store.pool;
    if (view === null) {
      renderAll();
      return;
    }
    const first = saved === null;
    const unsaved = draft !== null && Object.keys(changes()).length > 0;
    saved = view.pool;
    if (first || !unsaved) {
      draft = { ...view.pool, cpus: [...view.pool.cpus].sort((a, b) => a - b) };
      options.clear();
      for (const [key, value] of Object.entries(view.pool.options)) options.set(key, value);
    }
    if (first) {
      renderAll();
      void loadHint();
      void loadSettings();
    } else {
      renderHead();
      machine.update();
      renderCpuSummary();
      renderLive();
      renderSaveBar();
    }
  }

  return {
    show(): void {
      if (offs.length === 0) offs = [on("pool", fromStore), on("lists", renderLive), on("queue", renderLive), on("host", () => machine.update())];
      fromStore();
    },
    hide(): void {
      for (const off of offs) off();
      offs = [];
    },
  };
}
