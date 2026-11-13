// My games, through the control service: the lobbies with a place for the signed-in player (a seat with its join line,
// or a watch line), the games they asked for with where each stands (queued, its lobby, refused), cancelling one, and
// asking for a new game they host on a host with player hosting on (when the service allows it).

import { ApiError } from "../api.ts";
import { topRole, type ServiceNewRequest, type ServiceRequest } from "../control.ts";
import { byId, h, icon, isNumber, type Child } from "../dom.ts";
import { emptyState, stateChip, timeOf } from "../plane/parts.ts";
import { actions, on, plural, RUNNING, store } from "../plane/store.ts";
import { service } from "../service.ts";
import { FACTIONS } from "../slots.ts";
import { confirmAction, toast } from "../ui.ts";
import { hostMaps, pageHead, type View } from "./common.ts";
import { lobbyTable } from "./lobbies.ts";

const POLL_MS = 5000;
const MAX_SEATS = 16;

const REQUEST_STATE: Record<string, [string, string]> = {
  queued: ["Waiting for room", "warn"],
  starting: ["Starting", "info"],
  lobby: ["Lobby open", "accent"],
  game: ["In game", "ok"],
  ended: ["Ended", "neutral"],
  refused: ["Refused", "bad"],
  cancelled: ["Cancelled", "muted"],
  unknown: ["Host not answering", "warn"],
};

interface SeatDraft {
  kind: "human" | "ai";
  name: string;
  ai: string;
  team: number;
  faction: number;
}

function mapName(request: ServiceRequest): string {
  const map = request.lobby?.map ?? request.map;
  if (typeof map === "string") return map;
  return map?.name ?? map?.id ?? "–";
}

export function gamesView(): View {
  const root = byId<HTMLElement>("view-games");
  const lobbiesBox = h("div", {});
  const requestsBox = h("div", {});
  const requestsMeta = h("span", {});
  const formCard = h("section", { class: "card" });
  root.replaceChildren(
    pageHead("My games", "The lobbies with a place for you, and the games you asked for. Each lobby's page has your own join or watch line."),
    h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Lobbies with a place for you"), h("span", { class: "card-meta" }, "running")), lobbiesBox),
    h("div", { class: "grid-main-side games-grid" }, h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Games you asked for"), requestsMeta), requestsBox), formCard),
  );
  let offs: (() => void)[] = [];
  let timer: number | undefined;
  let requests: ServiceRequest[] = [];
  let loaded = false;
  let loadError = "";

  // ---------------------------------------------------------------- the request form
  const mapInput = h("input", { id: "game-map", spellcheck: "false", autocomplete: "off", placeholder: "scmp_009", list: "game-maps" });
  const mapList = h("datalist", { id: "game-maps" });
  const hostSelect = h("select", { id: "game-host" });
  const seatRows = h("div", { class: "request-seats" });
  const addPlayer = h("button", { type: "button", class: "btn small" }, icon("plus", "icon tiny"), "A player");
  const addAi = h("button", { type: "button", class: "btn small" }, icon("plus", "icon tiny"), "An AI");
  const submit = h("button", { type: "submit", class: "btn primary" }, icon("rocket", "icon"), "Ask for the game");
  const formNote = h("p", { class: "dim small" });
  const form = h(
    "form",
    { class: "request-form", novalidate: true },
    h("div", { class: "field" }, h("label", { for: "game-map" }, "Map ", h("span", { class: "dim" }, "(its id, as in the game's map list)")), mapInput, mapList),
    h("div", { class: "field" }, h("label", { for: "game-host" }, "Host"), hostSelect),
    h("div", { class: "field" }, h("span", { class: "field-label" }, "Seats ", h("span", { class: "dim" }, "(you are seat 1 and host it)")), seatRows, h("div", { class: "btn-row" }, addPlayer, addAi)),
    submit,
    formNote,
  );
  const seats: SeatDraft[] = [{ kind: "ai", name: "", ai: "adaptive", team: 3, faction: 5 }];
  let sending = false;

  function renderSeats(): void {
    const me = service.me;
    const you = h(
      "div",
      { class: "request-seat you" },
      h("span", { class: "slot-badge" }, "1"),
      h("span", {}, h("strong", {}, me?.user.name ?? "You"), h("span", { class: "dim" }, " · host")),
    );
    seatRows.replaceChildren(
      you,
      ...seats.map((seat, index) => {
        const n = index + 2;
        const who =
          seat.kind === "human"
            ? h("input", { placeholder: `Player ${n} (open seat)`, maxlength: 40, spellcheck: "false", "aria-label": `Seat ${n}: player name` })
            : h("input", { placeholder: "adaptive", spellcheck: "false", "aria-label": `Seat ${n}: AI personality`, list: "game-ais" });
        who.value = seat.kind === "human" ? seat.name : seat.ai;
        who.addEventListener("input", () => {
          if (seat.kind === "human") seat.name = who.value;
          else seat.ai = who.value;
        });
        const team = h("select", { "aria-label": `Seat ${n}: team` }, h("option", { value: "1" }, "No team"), ...[1, 2, 3, 4].map((t) => h("option", { value: String(t + 1) }, `Team ${t}`)));
        team.value = String(seat.team);
        team.addEventListener("change", () => (seat.team = Number(team.value)));
        const faction = h("select", { "aria-label": `Seat ${n}: faction` }, ...FACTIONS.map(([value, label]) => h("option", { value: String(value) }, label)));
        faction.value = String(seat.faction);
        faction.addEventListener("change", () => (seat.faction = Number(faction.value)));
        const remove = h("button", { type: "button", class: "btn ghost small", "aria-label": `Remove seat ${n}` }, icon("trash", "icon tiny"));
        remove.addEventListener("click", () => {
          seats.splice(index, 1);
          renderSeats();
        });
        return h("div", { class: "request-seat" }, h("span", { class: "slot-badge" }, String(n)), h("span", { class: "dim small" }, seat.kind === "human" ? "Player" : "AI"), who, team, faction, remove);
      }),
      h("datalist", { id: "game-ais" }, ...["adaptive", "easy", "medium", "rush", "turtle", "tech"].map((key) => h("option", { value: key }))),
    );
    addPlayer.disabled = seats.length + 1 >= MAX_SEATS;
    addAi.disabled = seats.length + 1 >= MAX_SEATS;
  }
  addPlayer.addEventListener("click", () => {
    seats.push({ kind: "human", name: "", ai: "", team: 2, faction: 5 });
    renderSeats();
  });
  addAi.addEventListener("click", () => {
    seats.push({ kind: "ai", name: "", ai: "adaptive", team: 3, faction: 5 });
    renderSeats();
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void ask();
  });

  async function ask(): Promise<void> {
    const control = service.api;
    const map = mapInput.value.trim();
    if (control === null || sending) return;
    if (map === "") {
      toast("bad", "Pick a map", "Type its id, for example scmp_009.");
      mapInput.focus();
      return;
    }
    const request: ServiceNewRequest = {
      map,
      seats: [{ kind: "human", team: 2 }, ...seats.map((seat) => (seat.kind === "human" ? { kind: "human" as const, ...(seat.name.trim() === "" ? {} : { name: seat.name.trim() }), team: seat.team, faction: seat.faction } : { kind: "ai" as const, ai: seat.ai.trim() || "adaptive", team: seat.team, faction: seat.faction }))],
    };
    if (hostSelect.value !== "") request.host = hostSelect.value;
    sending = true;
    submit.disabled = true;
    try {
      const answer = await control.createRequest(request);
      toast("ok", answer.state === "queued" ? `Queued on ${answer.host}` : `Your game is ${answer.state} on ${answer.host}`, answer.state === "queued" && isNumber(answer.position) ? `Place ${answer.position} in its queue: it starts when there is room.` : "");
      await loadRequests();
      actions.refresh();
    } catch (error) {
      const status = error instanceof ApiError ? error.status : 0;
      toast("bad", status === 409 ? "No host takes players' games now" : status === 403 ? "Player hosting is off" : "The game wasn't asked for", error instanceof Error ? error.message : String(error));
    } finally {
      sending = false;
      submit.disabled = false;
    }
  }

  function renderForm(): void {
    const me = service.me;
    if (me === null) return;
    const hosting = service.hosts.filter((host) => host.reachable && host.player_hosting);
    if (!me.player_hosting) {
      formCard.replaceChildren(h("div", { class: "card-head" }, h("h2", {}, "Ask for a game you host")), h("p", { class: "dim" }, "Player hosting through this control service is off: games are made by organisers only."));
      return;
    }
    const sig = JSON.stringify(hosting.map((host) => host.name));
    if (hostSelect.dataset.sig !== sig) {
      hostSelect.dataset.sig = sig;
      const keep = hostSelect.value;
      hostSelect.replaceChildren(h("option", { value: "" }, "Any host with room (shortest queue first)"), ...hosting.map((host) => h("option", { value: host.name }, `${host.name}${host.region ? ` · ${host.region}` : ""}${isNumber(host.pool_queued) && host.pool_queued > 0 ? ` · ${host.pool_queued} waiting` : ""}`)));
      hostSelect.value = hosting.some((host) => host.name === keep) ? keep : "";
    }
    formNote.textContent = hosting.length === 0 ? "No host takes players' games right now: asking now is refused." : `${plural(hosting.length, "host")} take players' games now. You host it in your own lobby screen in the game: start, settings and slots are yours there.`;
    submit.disabled = sending || hosting.length === 0;
    if (!formCard.contains(form)) formCard.replaceChildren(h("div", { class: "card-head" }, h("h2", {}, "Ask for a game you host")), form);
  }

  /** Map ids to suggest: the hosts' lists for those who may read them, else the maps of the lobbies the page sees. */
  async function suggestMaps(): Promise<void> {
    const ids = new Map<string, string>();
    for (const lobby of store.lobbies) if (lobby.map?.id) ids.set(lobby.map.id, lobby.map.name ?? lobby.map.id);
    if (topRole(service.me) !== "player" && service.api !== null) {
      const host = service.hosts.find((item) => item.reachable && item.player_hosting) ?? service.hosts.find((item) => item.reachable);
      if (host !== undefined) {
        try {
          for (const map of await hostMaps(service.api.hostApi(host.name))) ids.set(map.id, map.name ?? map.id);
        } catch {
          // the lobbies' maps are enough
        }
      }
    }
    mapList.replaceChildren(...[...ids.entries()].map(([id, name]) => h("option", { value: id }, name)));
  }

  // ---------------------------------------------------------------- lists
  async function loadRequests(): Promise<void> {
    const control = service.api;
    if (control === null) return;
    try {
      requests = await control.requests(AbortSignal.timeout(POLL_MS));
      loadError = "";
    } catch (error) {
      loadError = error instanceof Error ? error.message : String(error);
    }
    loaded = true;
    renderRequests();
  }

  async function cancel(request: ServiceRequest, button: HTMLButtonElement): Promise<void> {
    const control = service.api;
    if (control === null) return;
    const ok = await confirmAction("Cancel this game?", request.state === "queued" ? "It leaves the queue and never starts." : "Its lobby stops before the game, and everyone in it is disconnected.", "Cancel it");
    if (!ok) return;
    button.disabled = true;
    try {
      await control.cancelRequest(request.ref);
      toast("ok", "Cancelled");
    } catch (error) {
      toast("bad", "Couldn't cancel it", error instanceof Error ? error.message : String(error));
    } finally {
      button.disabled = false;
    }
    await loadRequests();
    actions.refresh();
  }

  function renderRequests(): void {
    const list = [...requests].sort((a, b) => String(b.created ?? "").localeCompare(String(a.created ?? "")));
    const live = list.filter((request) => ["queued", "starting", "lobby", "game"].includes(request.state)).length;
    requestsMeta.textContent = list.length === 0 ? "" : `${live} live of ${list.length}`;
    if (!loaded) {
      requestsBox.replaceChildren(h("p", { class: "dim" }, "Loading…"));
      return;
    }
    if (loadError !== "") {
      requestsBox.replaceChildren(h("p", { class: "form-error" }, `Your requests didn't load: ${loadError}`));
      return;
    }
    requestsBox.replaceChildren(
      list.length === 0
        ? h("p", { class: "dim" }, service.me?.player_hosting ? "None yet. Ask for one with the form." : "None.")
        : h(
            "ul",
            { class: "request-list" },
            ...list.map((request) => {
              const [label, tone] = REQUEST_STATE[request.state] ?? [request.state, "neutral"];
              const lobbyKey = request.lobby?.id ? `${request.host}/${request.lobby.id}` : null;
              const parts: Child[] = [
                h("div", { class: "request-head" }, h("span", { class: `chip tone-${tone}` }, h("span", { class: "chip-dot", "aria-hidden": "true" }), label), h("strong", {}, mapName(request)), h("span", { class: "dim small" }, `on ${request.host} · asked at ${timeOf(request.created)}`)),
              ];
              if (request.state === "queued") parts.push(h("p", { class: "small" }, isNumber(request.position) ? `Place ${request.position} in ${request.host}'s queue: it starts when a game ends and there is room.` : "In the queue."));
              if (request.reason) parts.push(h("p", { class: "small bad-text" }, request.reason));
              const actionsRow = h("div", { class: "row-actions" });
              if (lobbyKey !== null && RUNNING.has(request.lobby?.state ?? request.state)) actionsRow.append(h("a", { class: "btn small primary", href: `#/lobby/${encodeURIComponent(lobbyKey)}` }, "Open its lobby"));
              if (["queued", "starting", "lobby"].includes(request.state)) {
                const stop = h("button", { type: "button", class: "btn small danger" }, "Cancel…");
                stop.addEventListener("click", () => void cancel(request, stop));
                actionsRow.append(stop);
              }
              if (request.lobby?.state) parts.push(h("p", { class: "small" }, "Its lobby: ", stateChip(request.lobby.state), request.lobby.name ? ` ${request.lobby.name}` : ""));
              parts.push(actionsRow);
              return h("li", { class: "request-item" }, ...parts);
            }),
          ),
    );
  }

  function renderLobbies(): void {
    const mine = store.lobbies.filter((lobby) => RUNNING.has(lobby.state) && ((lobby.service?.you !== undefined && lobby.service?.you !== null) || (lobby.service?.origin === "hosted" && lobby.service.can_stop)));
    lobbiesBox.replaceChildren(mine.length === 0 ? emptyState("No lobby has a place for you now", "When an organiser seats you, or a game you asked for opens, it shows here with its page and your join line.") : lobbyTable(mine, true));
  }

  return {
    show(): void {
      if (offs.length === 0) {
        offs = [
          on("lists", renderLobbies),
          on("service", () => {
            renderForm();
            renderLobbies();
          }),
        ];
      }
      renderSeats();
      renderForm();
      renderLobbies();
      renderRequests();
      void loadRequests();
      void suggestMaps();
      window.clearInterval(timer);
      timer = window.setInterval(() => void loadRequests(), POLL_MS);
    },
    hide(): void {
      for (const off of offs) off();
      offs = [];
      window.clearInterval(timer);
      timer = undefined;
    },
  };
}
