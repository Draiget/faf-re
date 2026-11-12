// Queue: what waits for room, in both queues: the player requests (the pool's queue) and the operator's lobbies made
// with "queue if full". Each item's place, map, seats, what it needs and what it waits for; move it up one place or
// cancel it. When a lobby ends the host starts the first item of a side that fits.

import type { QueueItem } from "../api.ts";
import { byId, h, icon, isNumber, num } from "../dom.ts";
import { mapArt } from "../maps.ts";
import { waitingText } from "../plane/alerts.ts";
import { emptyState, timeOf } from "../plane/parts.ts";
import { actions, ageSeconds, duration, on, plural, store } from "../plane/store.ts";
import { confirmAction, toast } from "../ui.ts";
import { hostPreview, knownMap, pageHead, type View } from "./common.ts";

async function cancel(item: QueueItem, button: HTMLButtonElement): Promise<void> {
  const api = store.api;
  if (api === null) return;
  const player = item.side === "pool";
  const ok = await confirmAction(`Cancel ${item.name ?? item.id}?`, player ? `${item.player ?? "The player"}'s request is refused; their page says it was cancelled.` : "It leaves the queue and never starts.", "Cancel it");
  if (!ok) return;
  button.disabled = true;
  try {
    await api.cancelQueued(item.id);
    toast("ok", `Cancelled ${item.name ?? item.id}`);
  } catch (error) {
    toast("bad", "Couldn't cancel it", error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
  }
  actions.refresh();
}

async function moveUp(item: QueueItem, button: HTMLButtonElement): Promise<void> {
  const api = store.api;
  if (api === null) return;
  button.disabled = true;
  try {
    await api.moveUp(item.id);
  } catch (error) {
    toast("bad", "Couldn't move it", error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
  }
  actions.refresh();
}

function table(items: QueueItem[]): HTMLElement {
  return h(
    "div",
    { class: "table-wrap" },
    h(
      "table",
      { class: "grid-table queue-table" },
      h("thead", {}, h("tr", {}, ...["Place", "Game", "Map", "Seats", "Needs", "Waits for", "Waiting", ""].map((text) => h("th", { scope: "col" }, text)))),
      h(
        "tbody",
        {},
        ...items.map((item, index) => {
          const map = knownMap(item.map?.id);
          const thumb = map === undefined ? h("span", { class: "map-art tiny no-preview" }, h("span", { class: "map-art-size" }, isNumber(item.map?.km) ? `${item.map.km}` : "?")) : mapArt(map, hostPreview);
          thumb.classList.add("tiny");
          const up = h("button", { type: "button", class: "btn small", title: "One place earlier", "aria-label": `Move ${item.name ?? item.id} up one place` }, icon("chevron", "icon tiny rot90"), "Up");
          up.disabled = index === 0;
          up.addEventListener("click", () => void moveUp(item, up));
          const stop = h("button", { type: "button", class: "btn small danger" }, "Cancel…");
          stop.addEventListener("click", () => void cancel(item, stop));
          const est = item.estimate;
          const waited = ageSeconds(item.created);
          return h(
            "tr",
            {},
            h("td", { "data-label": "Place" }, h("span", { class: "queue-place" }, `#${item.position ?? index + 1}`)),
            h("td", { "data-label": "Game" }, h("div", { class: "lobby-name-text" }, h("strong", {}, item.name ?? item.id), h("span", { class: "dim small" }, item.player ? `asked for by ${item.player}` : item.kind === "custom" ? "custom lobby" : "tournament lobby"))),
            h("td", { "data-label": "Map" }, h("div", { class: "lobby-name-cell" }, thumb, h("span", {}, item.map?.name ?? item.map?.id ?? "–", isNumber(item.map?.km) ? h("span", { class: "dim" }, ` · ${item.map.km} km`) : null))),
            h("td", { "data-label": "Seats" }, isNumber(item.seats) ? String(item.seats) : "–"),
            h("td", { "data-label": "Needs" }, est === null || est === undefined ? "–" : `${isNumber(est.suggested_cores) ? plural(est.suggested_cores, "core") : "? cores"}${isNumber(est.memory_mb) ? ` · ${num(est.memory_mb)} MB` : ""}`),
            h("td", { "data-label": "Waits for" }, h("span", { class: "chip tone-warn" }, icon("timer", "icon tiny"), waitingText(item.waiting_for))),
            h("td", { "data-label": "Waiting" }, h("span", {}, duration(waited), h("span", { class: "dim small" }, ` · since ${timeOf(item.created)}`))),
            h("td", { "data-label": "" }, h("div", { class: "row-actions" }, up, stop)),
          );
        }),
      ),
    ),
  );
}

export function queueView(): View {
  const root = byId<HTMLElement>("view-queue");
  const sub = h("span", {});
  const pool = h("div", {});
  const operator = h("div", {});
  const poolMeta = h("span", {});
  const operatorMeta = h("span", {});
  root.replaceChildren(
    pageHead("Queue", sub),
    h(
      "div",
      { class: "stack" },
      h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Player requests"), h("span", { class: "card-meta" }, poolMeta)), h("p", { class: "dim small section-help" }, "Games players asked for on the request page. They start on the player-hosting pool, first come first served, when a game place is free (the pool runs a set number of games at once) and its cores fit."), pool),
      h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Operator lobbies"), h("span", { class: "card-meta" }, operatorMeta)), h("p", { class: "dim small section-help" }, "Lobbies created here with “Queue it” that didn't fit. They start on the CPUs outside the pool."), operator),
    ),
  );
  let off: (() => void) | null = null;

  function render(): void {
    if (!store.queueSupported) {
      sub.textContent = "This host has no queue.";
      pool.replaceChildren();
      operator.replaceChildren();
      return;
    }
    const items = store.queue;
    const poolItems = items.filter((item) => item.side === "pool").sort((a, b) => (a.position ?? 0) - (b.position ?? 0));
    const operatorItems = items.filter((item) => item.side !== "pool").sort((a, b) => (a.position ?? 0) - (b.position ?? 0));
    const view = store.pool;
    sub.textContent = items.length === 0 ? "Nothing waits. When a lobby ends, the host starts the first queued game that fits." : `${plural(items.length, "game")} waiting. When a lobby ends, the host starts the first queued game of its side that fits.`;
    poolMeta.textContent = view === null ? plural(poolItems.length, "waiting", "waiting") : `${poolItems.length} waiting · ${view.usage.games} of ${view.pool.max_games} games running${view.pool.max_queue > 0 ? ` · room for ${Math.max(0, view.pool.max_queue - poolItems.length)} more` : ""}`;
    operatorMeta.textContent = plural(operatorItems.length, "waiting", "waiting");
    pool.replaceChildren(poolItems.length === 0 ? emptyState("No player waits", view?.pool.enabled === false ? "Player hosting is off: players can't ask for a server." : "Requests that don't fit right away wait here.") : table(poolItems));
    operator.replaceChildren(operatorItems.length === 0 ? emptyState("No lobby waits", "Create a lobby with “Queue it” and it waits here when it doesn't fit.") : table(operatorItems));
  }

  return {
    show(): void {
      off ??= on("queue", render);
      render();
    },
    hide(): void {
      off?.();
      off = null;
    },
  };
}
