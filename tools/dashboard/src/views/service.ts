// The overview through the control service: every host it follows (reachable or not and why, the machine, its load and
// memory, its lobbies, player hosting), key numbers over them, what needs attention, the running lobbies and what
// changed. A host filter narrows the hosts and lobbies here and on the lobby list. Players see the hosts without their
// machines (the service gives organisers and admins those).

import { canOrganise, topRole, type ServiceHost } from "../control.ts";
import { byId, fill, h, icon, isNumber, type Child } from "../dom.ts";
import { currentAlerts } from "../plane/alerts.ts";
import { emptyState, gb, meter } from "../plane/parts.ts";
import { ageSeconds, duration, on, plural, RUNNING, store } from "../plane/store.ts";
import { hostError, runningOn, service } from "../service.ts";
import { card, kpi, pageHead, type View } from "./common.ts";
import { lobbyTable } from "./lobbies.ts";

/** Chips to show every host or one; the choice is shared by the overview and the lobby list. */
export function hostChips(onChange: () => void): HTMLElement {
  const box = h("div", { class: "seg-chips host-chips", role: "group", "aria-label": "Host" });
  const hosts = service.hosts;
  const chip = (name: string, text: Child, count: number, title: string, bad = false): HTMLButtonElement => {
    const button = h("button", { type: "button", class: `seg-chip${bad ? " bad" : ""}`, "aria-pressed": String(service.hostFilter === name), title }, text, h("span", { class: "seg-count" }, String(count)));
    button.addEventListener("click", () => {
      service.hostFilter = name;
      onChange();
    });
    return button;
  };
  const running = (name: string): number => store.lobbies.filter((lobby) => RUNNING.has(lobby.state) && (name === "" || lobby.service?.host === name)).length;
  box.append(chip("", "All hosts", running(""), "Every host the service follows: lobbies running"));
  for (const host of hosts) {
    box.append(chip(host.name, h("span", { class: "host-chip-text" }, h("span", { class: `dot ${host.reachable ? "ok" : "bad"}`, "aria-hidden": "true" }), host.name), running(host.name), host.reachable ? `${host.name}${host.region ? ` (${host.region})` : ""}: lobbies running` : `${host.name} doesn't answer`, !host.reachable));
  }
  if (service.hostFilter !== "" && !hosts.some((host) => host.name === service.hostFilter)) service.hostFilter = "";
  return box;
}

function age(time: string | undefined): string {
  const seconds = ageSeconds(time);
  return seconds === null ? "never" : seconds < 5 ? "just now" : `${duration(seconds)} ago`;
}

function hostCard(host: ServiceHost, organiser: boolean): HTMLElement {
  const running = runningOn(host.name);
  const state = host.reachable ? h("span", { class: "chip tone-ok" }, h("span", { class: "chip-dot", "aria-hidden": "true" }), "Answers") : h("span", { class: "chip tone-bad" }, h("span", { class: "chip-dot", "aria-hidden": "true" }), "No answer");
  const body: Child[] = [];
  if (!host.reachable) {
    const why = hostError(host);
    body.push(
      h("p", { class: "small" }, "The control service can't reach it. Its lobbies stay listed, marked as not current, until it answers again."),
      why === "" ? null : h("p", { class: "host-error" }, why),
    );
  } else if (organiser) {
    const load = isNumber(host.load) ? host.load : null;
    const total = host.memory_total_mb;
    const available = host.memory_available_mb;
    const used = isNumber(total) && isNumber(available) ? total - available : null;
    body.push(
      h("p", { class: "dim small host-machine" }, `${host.machine ?? host.name} · ${host.cpu_model ?? "CPU model unknown"}`),
      h("p", { class: "small" }, `${plural(host.cpus ?? 0, "CPU")} on ${plural(host.nodes ?? 1, "NUMA node")}${isNumber(total) ? ` · ${gb(total)} memory` : ""}`),
      h(
        "div",
        { class: "host-meters" },
        h("div", { class: "host-meter" }, h("span", { class: "host-meter-label" }, "CPU", h("b", {}, load === null ? "–" : `${Math.round(load)}%`)), meter(`${host.name} CPU`, load ?? 0, 100, `${Math.round(load ?? 0)}% busy`, (load ?? 0) > 85 ? "bad" : (load ?? 0) > 70 ? "warn" : "")),
        h(
          "div",
          { class: "host-meter" },
          h("span", { class: "host-meter-label" }, "Memory", h("b", {}, used === null ? "–" : `${gb(used)}${isNumber(total) ? ` / ${gb(total)}` : ""}`)),
          meter(`${host.name} memory`, used ?? 0, isNumber(total) ? total : 1, used === null ? "unknown" : `${gb(used)} used`, isNumber(total) && isNumber(available) && available / total < 0.1 ? "bad" : ""),
        ),
      ),
    );
  }
  const games = isNumber(host.pool_games) ? `${host.pool_games}${isNumber(host.pool_max_games) && host.pool_max_games > 0 ? ` of ${host.pool_max_games}` : ""} games` : "";
  const queued = isNumber(host.pool_queued) && host.pool_queued > 0 ? ` · ${host.pool_queued} waiting` : "";
  body.push(
    h(
      "dl",
      { class: "host-facts" },
      h("div", {}, h("dt", {}, "Lobbies running"), h("dd", {}, String(host.reachable ? host.lobbies : running.length))),
      h("div", {}, h("dt", {}, "Player hosting"), h("dd", {}, host.player_hosting ? `On${games === "" ? "" : ` · ${games}`}${queued}` : "Off")),
      organiser ? h("div", {}, h("dt", {}, "Last look"), h("dd", {}, age(host.checked))) : null,
    ),
  );
  const show = h("button", { type: "button", class: "btn small" }, "Its lobbies");
  show.addEventListener("click", () => {
    service.hostFilter = host.name;
    location.hash = "#/lobbies";
  });
  const actions: Child[] = [show];
  if (organiser && host.reachable && canOrganiseSomething()) actions.push(h("a", { class: "btn small primary", href: `#/create/host=${encodeURIComponent(host.name)}` }, icon("plus", "icon tiny"), "Create here"));
  return h(
    "article",
    { class: `card host-card${host.reachable ? "" : " unreachable"}${service.hostFilter === host.name ? " picked" : ""}` },
    h("div", { class: "host-card-head" }, h("h3", {}, icon("server", "icon"), host.name), host.region ? h("span", { class: "chip tiny tone-neutral" }, host.region) : null, state),
    ...body,
    h("div", { class: "host-actions" }, ...actions),
  );
}

function canOrganiseSomething(): boolean {
  const me = service.me;
  return canOrganise(me, "") || (me?.tournaments ?? []).some((tournament) => canOrganise(me, tournament.id));
}

export function serviceView(): View {
  const root = byId<HTMLElement>("view-service");
  const sub = h("span", {});
  const kpis = h("div", { class: "kpis" });
  const chipsBox = h("div", {});
  const hostsBox = h("div", { class: "host-grid" });
  const alertsBox = h("div", {});
  const changesBox = h("div", {});
  const lobbiesBox = h("div", {});
  const lobbiesMeta = h("span", {});
  const createLink = h("a", { class: "btn primary", href: "#/create" }, icon("plus", "icon"), "Create lobby");
  const gamesLink = h("a", { class: "btn", href: "#/games" }, icon("crown", "icon"), "My games");
  root.replaceChildren(
    pageHead("Overview", sub, gamesLink, createLink),
    kpis,
    h("section", { class: "card" }, h("div", { class: "card-head wrap" }, h("h2", {}, "Hosts"), chipsBox), hostsBox),
    h("div", { class: "grid-main-side" }, h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Running lobbies"), h("span", { class: "card-meta" }, lobbiesMeta, " ", h("a", { href: "#/lobbies" }, "All lobbies"))), lobbiesBox), h("div", { class: "stack" }, card("Needs attention", null, alertsBox), card("Recent changes", h("span", {}, "while this page is open"), changesBox))),
  );
  let offs: (() => void)[] = [];

  function render(): void {
    const me = service.me;
    const organiser = topRole(me) !== "player";
    const hosts = service.hosts;
    const up = hosts.filter((host) => host.reachable);
    const shownHosts = service.hostFilter === "" ? hosts : hosts.filter((host) => host.name === service.hostFilter);
    const lobbies = store.lobbies.filter((lobby) => service.hostFilter === "" || lobby.service?.host === service.hostFilter);
    const running = lobbies.filter((lobby) => RUNNING.has(lobby.state));
    const games = running.filter((lobby) => lobby.state === "game").length;
    const players = running.reduce((sum, lobby) => sum + (lobby.seats ?? []).filter((seat) => seat.kind === "human").length, 0);
    const mine = running.filter((lobby) => lobby.service?.you !== undefined && lobby.service?.you !== null).length;
    const hosting = up.filter((host) => host.player_hosting).length;
    const loads = up.map((host) => host.load).filter(isNumber);
    createLink.hidden = !canOrganiseSomething();
    gamesLink.hidden = !(me?.player_hosting === true || mine > 0);
    sub.textContent = `The control service follows ${plural(hosts.length, "host")}${service.live ? "" : " (reconnecting…)"}. ${organiser ? "Machines, lobbies and player hosting on each." : "Each host's lobbies and player hosting; machine details are for organisers."}`;
    fill(
      kpis,
      kpi("Hosts", `${up.length} / ${hosts.length}`, up.length === hosts.length ? "every host answers" : `${hosts.length - up.length} not answering`, null, undefined, up.length < hosts.length ? "bad" : ""),
      organiser ? kpi("Load", loads.length === 0 ? "–" : `${Math.round(loads.reduce((sum, load) => sum + load, 0) / loads.length)}%`, "mean CPU busy, answering hosts", null, undefined, loads.some((load) => load > 85) ? "warn" : "") : null,
      kpi("Lobbies", String(running.length), `${games} in game · ${running.length - games} in the lobby or starting`, null, "#/lobbies"),
      kpi("Players", String(players), "in seats of running lobbies"),
      kpi("Player hosting", `${hosting} / ${up.length}`, hosting === 0 ? "no host takes players' games now" : `${plural(hosting, "host")} take players' games`, null, undefined, hosting > 0 ? "ok" : ""),
      kpi("Your lobbies", String(mine), mine === 0 ? "you have no seat in a running lobby" : "with a seat or watch line for you", null, "#/games"),
    );
    chipsBox.replaceChildren(hosts.length > 1 ? hostChips(render) : h("span", { class: "card-meta" }, organiser ? "Load is the mean over the last 10 s." : ""));
    hostsBox.replaceChildren(...(hosts.length === 0 ? [emptyState("No hosts", service.live ? "The service's configuration lists no hosts." : "Waiting for the service's first answer…")] : shownHosts.map((host) => hostCard(host, organiser))));
    lobbiesMeta.textContent = `${running.length} running${service.hostFilter === "" ? "" : ` on ${service.hostFilter}`}`;
    lobbiesBox.replaceChildren(running.length === 0 ? emptyState("Nothing is running", canOrganiseSomething() ? "Create a lobby: the service puts it on the host you pick, or the least loaded one that fits." : "Lobbies show here as they start.") : lobbyTable(running, true));
    renderAlerts();
  }

  function renderAlerts(): void {
    const list = currentAlerts();
    alertsBox.replaceChildren(
      list.length === 0
        ? h("p", { class: "ok-line" }, icon("check", "icon"), "Nothing needs attention.")
        : h("ul", { class: "alert-list" }, ...list.map((alert) => h("li", { class: `alert tone-${alert.tone}` }, icon(alert.tone === "bad" ? "ban" : "warn", "icon"), alert.href === undefined ? h("span", {}, alert.text) : h("a", { href: alert.href }, alert.text)))),
    );
    const items = service.changes.slice(0, 10);
    changesBox.replaceChildren(
      items.length === 0
        ? h("p", { class: "dim small" }, "Lobbies starting, ending or failing, and hosts going quiet, show here as they happen.")
        : h(
            "ul",
            { class: "change-list" },
            ...items.map((change) =>
              h(
                "li",
                { class: `change tone-${change.tone}` },
                h("span", { class: "chip-dot", "aria-hidden": "true" }),
                change.lobby === undefined ? h("span", {}, change.text) : h("a", { href: `#/lobby/${encodeURIComponent(change.lobby)}` }, change.text),
                h("time", { class: "dim small" }, new Date(change.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })),
              ),
            ),
          ),
    );
  }

  return {
    show(): void {
      if (offs.length === 0) offs = [on("service", render), on("host", render), on("lists", render), on("alerts", renderAlerts)];
      render();
    },
    hide(): void {
      for (const off of offs) off();
      offs = [];
    },
  };
}
