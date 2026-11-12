// Overview: the machine at a glance. Key numbers with their trend (CPU, memory, network, lobbies, queue, player
// hosting), the machine map by NUMA node (load, which lobby each CPU runs, the pool's CPUs), the network links, what
// needs attention, the running lobbies, the queue and what changed recently.

import { seriesColor, sparkline } from "../chart.ts";
import { byId, h, icon, isNumber, num } from "../dom.ts";
import { recentEvents } from "../host.ts";
import { currentAlerts, waitingText } from "../plane/alerts.ts";
import { MachineMap } from "../plane/machine.ts";
import { emptyState, gb, meter, rate } from "../plane/parts.ts";
import { ageSeconds, cpuLoad, duration, isPoolLobby, kindOf, on, plural, RUNNING, store } from "../plane/store.ts";
import { card, kpi, last, pageHead, sumSeries, type View } from "./common.ts";
import { lobbyTable } from "./lobbies.ts";

export function overviewView(): View {
  const root = byId<HTMLElement>("view-overview");
  const sub = h("span", {});
  const kpis = h("div", { class: "kpis" });
  const machine = new MachineMap({ mode: "view" });
  const links = h("div", { class: "links" });
  const alertsBox = h("div", {});
  const eventsBox = h("div", {});
  const lobbiesBox = h("div", {});
  const queueBox = h("div", {});
  const lobbiesMeta = h("span", {});
  const queueMeta = h("span", {});
  root.replaceChildren(
    pageHead("Overview", sub, h("a", { class: "btn", href: "#/hosting" }, icon("users", "icon"), "Player hosting"), h("a", { class: "btn primary", href: "#/create" }, icon("plus", "icon"), "Create lobby")),
    kpis,
    h(
      "div",
      { class: "grid-main-side" },
      h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Machine"), h("span", { class: "card-meta" }, "Each cell is a CPU; cells side by side in a box share one physical core. Click a used CPU to open its lobby.")), machine.root, h("h3", { class: "sub-head" }, "Network"), links),
      h("div", { class: "stack" }, card("Needs attention", null, alertsBox), card("Recent changes", h("span", {}, "while this page is open"), eventsBox)),
    ),
    h("div", { class: "grid-main-side" }, h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Running lobbies"), h("span", { class: "card-meta" }, lobbiesMeta, " ", h("a", { href: "#/lobbies" }, "All lobbies"))), lobbiesBox), h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Queue"), h("span", { class: "card-meta" }, queueMeta, " ", h("a", { href: "#/queue" }, "Open the queue"))), queueBox)),
  );
  let offs: (() => void)[] = [];

  function renderKpis(): void {
    const info = store.info;
    if (info === null) return;
    const m = store.metrics;
    const cpus = info.cpus;
    const load = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
    const total = info.memory_mb?.total;
    const available = info.memory_mb?.available;
    const usedMem = isNumber(total) && isNumber(available) ? total - available : null;
    const linksList = info.links ?? [];
    const out = linksList.reduce((sum, link) => sum + (isNumber(link.out_kbps) ? link.out_kbps : 0), 0);
    const inn = linksList.reduce((sum, link) => sum + (isNumber(link.in_kbps) ? link.in_kbps : 0), 0);
    const outSeries = m === null ? [] : sumSeries(Object.values(m.net).map((link) => link.out_kbps));
    const running = store.lobbies.filter((lobby) => RUNNING.has(lobby.state));
    const pool = store.pool;
    const queued = store.queue.length;
    const nodes = info.nodes?.length ?? 1;
    sub.textContent = `${info.name ?? "Host"} · ${info.cpu_model ?? "CPU model unknown"} · ${plural(cpus.length, "CPU")} on ${plural(nodes, "NUMA node")}${isNumber(total) ? ` · ${gb(total)} memory` : ""}`;
    kpis.replaceChildren(
      kpi("CPU", `${Math.round(load)}%`, "busy, all CPUs, last 10 s", m === null ? null : sparkline(m.cpu, seriesColor(0), 100), "#/metrics", load > 85 ? "bad" : load > 70 ? "warn" : ""),
      kpi("Memory", usedMem === null ? "–" : gb(usedMem), isNumber(total) && isNumber(available) ? `used of ${gb(total)} · ${gb(available)} free` : "unknown", m === null ? null : sparkline(m.mem_used_mb, seriesColor(1), isNumber(total) ? total : undefined), "#/metrics"),
      kpi("Network", `↑ ${rate(out)}`, `↓ ${rate(inn)} · ${plural(linksList.length, "link")}`, m === null ? null : sparkline(outSeries, seriesColor(2)), "#/metrics"),
      kpi("Lobbies", String(running.length), `${running.filter((lobby) => kindOf(lobby) === "tournament").length} tournament · ${running.filter((lobby) => kindOf(lobby) === "custom" && !isPoolLobby(lobby)).length} custom · ${running.filter(isPoolLobby).length} from players`, null, "#/lobbies"),
      kpi("Queue", String(queued), queued === 0 ? "nothing waits" : `${store.queue.filter((item) => item.side === "pool").length} player requests · ${store.queue.filter((item) => item.side !== "pool").length} operator lobbies`, null, "#/queue", queued > 0 ? "warn" : ""),
      kpi(
        "Player hosting",
        pool === null ? "–" : pool.pool.enabled ? "On" : "Off",
        pool === null ? (store.poolSupported ? "…" : "not on this host") : pool.pool.enabled ? `${pool.usage.games} of ${pool.pool.max_games} games · ${plural(pool.pool.cpus.length, "CPU")}` : "players can't ask for a server",
        null,
        "#/hosting",
        pool?.pool.enabled === true ? "ok" : "",
      ),
    );
  }

  function renderLinks(): void {
    const list = store.info?.links ?? [];
    links.replaceChildren(
      ...(list.length === 0
        ? [h("p", { class: "dim small" }, "The host reports no network links.")]
        : list.map((link) => {
            const capacity = isNumber(link.speed_mbps) && link.speed_mbps > 0 ? link.speed_mbps * 125 : 0;
            const out = isNumber(link.out_kbps) ? link.out_kbps : 0;
            const ratio = capacity > 0 ? out / capacity : 0;
            return h(
              "div",
              { class: "link" },
              h("div", { class: "link-head" }, h("strong", {}, link.name), h("span", { class: "dim small" }, isNumber(link.speed_mbps) ? (link.speed_mbps >= 1000 ? `${num(link.speed_mbps / 1000, 1)} Gbit/s` : `${link.speed_mbps} Mbit/s`) : "speed unknown")),
              h("div", { class: "link-rates small" }, h("span", {}, "sending ", h("b", {}, rate(link.out_kbps))), h("span", {}, "receiving ", h("b", {}, rate(link.in_kbps)))),
              capacity > 0 ? meter(`${link.name} sending`, out, capacity, `${rate(out)} of ${rate(capacity)}`, ratio > 0.9 ? "bad" : ratio > 0.7 ? "warn" : "") : null,
            );
          })),
    );
  }

  function renderAlerts(): void {
    const list = currentAlerts();
    alertsBox.replaceChildren(
      list.length === 0
        ? h("p", { class: "ok-line" }, icon("check", "icon"), "Nothing needs attention.")
        : h("ul", { class: "alert-list" }, ...list.map((alert) => h("li", { class: `alert tone-${alert.tone}` }, icon(alert.tone === "bad" ? "ban" : "warn", "icon"), alert.href === undefined ? h("span", {}, alert.text) : h("a", { href: alert.href }, alert.text)))),
    );
    const items = recentEvents.slice(0, 10);
    eventsBox.replaceChildren(
      items.length === 0
        ? h("p", { class: "dim small" }, "Lobbies starting, ending or failing, and the queue moving, show here as they happen.")
        : h(
            "ul",
            { class: "change-list" },
            ...items.map((event) =>
              h(
                "li",
                { class: `change tone-${event.tone}` },
                h("span", { class: "chip-dot", "aria-hidden": "true" }),
                event.lobby === undefined ? h("span", {}, event.text) : h("a", { href: `#/lobby/${encodeURIComponent(event.lobby)}` }, event.text),
                h("time", { class: "dim small" }, new Date(event.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })),
              ),
            ),
          ),
    );
  }

  function renderLists(): void {
    const running = store.lobbies.filter((lobby) => RUNNING.has(lobby.state)).sort((a, b) => String(b.started_at ?? b.created ?? "").localeCompare(String(a.started_at ?? a.created ?? "")));
    lobbiesMeta.textContent = `${running.length} running`;
    lobbiesBox.replaceChildren(running.length === 0 ? emptyState("Nothing is running", "Create a lobby, or turn on player hosting so players can ask for one.") : lobbyTable(running, true));
    const queue = store.queue;
    queueMeta.textContent = store.queueSupported ? `${queue.length} waiting` : "";
    queueBox.replaceChildren(
      !store.queueSupported
        ? h("p", { class: "dim" }, "This host has no queue.")
        : queue.length === 0
          ? h("p", { class: "ok-line" }, icon("check", "icon"), "Nothing waits: every lobby asked for has started.")
          : h(
              "ol",
              { class: "queue-mini" },
              ...queue.slice(0, 8).map((item) =>
                h(
                  "li",
                  {},
                  h("span", { class: `side-chip side-${item.side === "pool" ? "pool" : "operator"}` }, item.side === "pool" ? "Player" : "Operator"),
                  h("span", { class: "queue-mini-name" }, h("b", {}, `#${item.position ?? "?"}`), ` ${item.name ?? item.id}`),
                  h("span", { class: "dim small" }, `${item.map?.name ?? ""} · waits for ${waitingText(item.waiting_for)} · ${duration(ageSeconds(item.created))}`),
                ),
              ),
            ),
    );
  }

  function renderAll(): void {
    renderKpis();
    machine.update();
    renderLinks();
    renderAlerts();
    renderLists();
  }

  return {
    show(): void {
      if (offs.length === 0) {
        offs = [on("host", () => {
          renderKpis();
          machine.update();
          renderLinks();
        }), on("lists", () => {
          machine.update();
          renderLists();
          renderKpis();
        }), on("pool", () => machine.update()), on("queue", renderLists), on("metrics", renderKpis), on("alerts", renderAlerts)];
      }
      renderAll();
    },
    hide(): void {
      for (const off of offs) off();
      offs = [];
    },
  };
}
