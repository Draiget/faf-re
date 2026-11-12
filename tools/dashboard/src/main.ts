// The dashboard: one page for a machine's server-host, full width and height. A top bar (the host, its CPU, memory and
// network now with their trend, what needs attention, the connection), a navigation (Overview, Lobbies, Create
// lobby, Queue, Player hosting, Logs, Metrics, and the running lobbies), and the views (views/*.ts; a lobby's own page
// is plane/lobby.ts). The page talks to server-host only; host.ts polls it.

import "./style.css";
import "./app.css";
import { ApiError, HostApi } from "./api.ts";
import { seriesColor, sparkline } from "./chart.ts";
import { byId, fill, h, icon, isNumber } from "./dom.ts";
import { startHost, stopHost } from "./host.ts";
import { currentAlerts } from "./plane/alerts.ts";
import { closeLobby, openLobby, openLobbyId, type LobbyTab } from "./plane/lobby.ts";
import { gb, rate } from "./plane/parts.ts";
import { colour, cpuLoad, displayName, on, RUNNING, store } from "./plane/store.ts";
import { forgetHostData, hostMaps, sumSeries, type View } from "./views/common.ts";
import { createView } from "./views/create.ts";
import { hostingView } from "./views/hosting.ts";
import { lobbiesView } from "./views/lobbies.ts";
import { logsView } from "./views/logs.ts";
import { metricsView } from "./views/metrics.ts";
import { overviewView } from "./views/overview.ts";
import { queueView } from "./views/queue.ts";

const STORE_URL = "faf-dashboard.url";
const STORE_TOKEN = "faf-dashboard.token";
const STORE_THEME = "faf-dashboard.theme";
const CONNECT_TIME_MS = 5000;
/** server-host's port unless its --listen says otherwise. */
const HOST_PORT = 27180;

function readStore(storage: () => Storage, key: string): string {
  try {
    return storage().getItem(key) ?? "";
  } catch {
    return "";
  }
}

function writeStore(storage: () => Storage, key: string, value: string): void {
  try {
    storage().setItem(key, value);
  } catch {
    // private window or blocked storage: the page works without it
  }
}

const session = (): Storage => sessionStorage;
const local = (): Storage => localStorage;

// ---------------------------------------------------------------- elements

const urlInput = byId<HTMLInputElement>("url");
const tokenInput = byId<HTMLInputElement>("token");
const connectForm = byId<HTMLFormElement>("connect-form");
const connectButton = byId<HTMLButtonElement>("connect");
const connectSummary = byId<HTMLElement>("connect-summary");
const connectError = byId<HTMLElement>("connect-error");
const connection = byId<HTMLAnchorElement>("connection");
const connectionText = byId<HTMLElement>("connection-text");
const brandSub = byId<HTMLElement>("brand-sub");
const themeButton = byId<HTMLButtonElement>("theme");
const health = byId<HTMLElement>("top-health");
const alertsLink = byId<HTMLAnchorElement>("top-alerts");
const navLobbies = byId<HTMLElement>("nav-lobbies");
const BRAND_SUB = brandSub.textContent ?? "";

for (const slot of document.querySelectorAll<HTMLElement>("[data-icon]")) slot.replaceChildren(icon(slot.dataset.icon ?? "dot"));

// ---------------------------------------------------------------- theme

type Theme = "auto" | "light" | "dark";
const THEME_NEXT: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
const THEME_LABEL: Record<Theme, string> = { auto: "automatic", light: "light", dark: "dark" };
const THEME_ICON: Record<Theme, string> = { auto: "auto", light: "sun", dark: "moon" };

function applyTheme(theme: Theme): void {
  if (theme === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  themeButton.replaceChildren(icon(THEME_ICON[theme]));
  const label = `Theme: ${THEME_LABEL[theme]} (switch to ${THEME_LABEL[THEME_NEXT[theme]]})`;
  themeButton.setAttribute("aria-label", label);
  themeButton.title = label;
  themeButton.dataset.theme = theme;
}

{
  const stored = readStore(local, STORE_THEME);
  applyTheme(stored === "light" || stored === "dark" ? stored : "auto");
}
themeButton.addEventListener("click", () => {
  const next = THEME_NEXT[(themeButton.dataset.theme as Theme | undefined) ?? "auto"];
  applyTheme(next);
  writeStore(local, STORE_THEME, next);
});

// ---------------------------------------------------------------- connection state

type ConnState = "idle" | "busy" | "ok" | "bad";

function setConnection(state: ConnState, text: string, detail = text): void {
  connection.className = `pill pill-${state}`;
  connectionText.textContent = text;
  connection.title = `${detail} (click to change the host or token)`;
}

function setConnectError(text: string): void {
  connectError.textContent = text;
  connectError.hidden = text === "";
}

function setConnected(on: boolean): void {
  document.body.dataset.connected = String(on);
  if (!on) brandSub.textContent = BRAND_SUB;
}

/**
 * Where the host is when nothing is stored: `VITE_HOST_URL` (from `.env.local` or the environment, for development),
 * else this page's own machine on server-host's port.
 */
function defaultUrl(): string {
  const fromEnv = (import.meta.env.VITE_HOST_URL ?? "").trim();
  if (fromEnv !== "") return fromEnv;
  const name = location.hostname === "" ? "127.0.0.1" : location.hostname;
  return `${location.protocol === "https:" ? "https" : "http"}://${name}:${HOST_PORT}`;
}

/** `VITE_HOST_TOKEN`, in the dev server only: a build never carries a token. */
function defaultToken(): string {
  return import.meta.env.DEV ? (import.meta.env.VITE_HOST_TOKEN ?? "").trim() : "";
}

urlInput.value = readStore(local, STORE_URL) || readStore(session, STORE_URL) || defaultUrl();
tokenInput.value = readStore(session, STORE_TOKEN) || defaultToken();

// ---------------------------------------------------------------- views and routing

let hostApi: HostApi | null = null;
const views: Record<string, View> = {
  overview: overviewView(),
  lobbies: lobbiesView(),
  create: createView(),
  queue: queueView(),
  hosting: hostingView(),
  logs: logsView(),
  metrics: metricsView(),
};
let current = "";
const TITLES: Record<string, string> = { overview: "Overview", lobbies: "Lobbies", create: "Create lobby", queue: "Queue", hosting: "Player hosting", logs: "Logs", metrics: "Metrics", connect: "Connect" };

function showSection(name: string): void {
  for (const section of document.querySelectorAll<HTMLElement>("main > .view")) section.hidden = section.dataset.view !== name;
  for (const link of document.querySelectorAll<HTMLElement>("[data-nav]")) {
    const on = link.dataset.nav === name;
    link.classList.toggle("current", on);
    if (on) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

/** `#/<view>[/<arg>]`, `#/lobby/<id>[/log|/metrics]`; anything else is the overview. Not connected: the connect view. */
function route(): void {
  const parts = location.hash.replace(/^#\/?/, "").split("/").map((part) => decodeURIComponent(part));
  const head = parts[0] ?? "";
  let name = head === "" ? "overview" : head;
  if (hostApi === null || name === "connect") name = "connect";
  else if (name !== "lobby" && views[name] === undefined) name = "overview";
  if (name !== "lobby" && openLobbyId() !== null) closeLobby();
  if (current !== name && views[current] !== undefined) views[current]?.hide();
  const changed = current !== name;
  current = name;
  showSection(name);
  if (name === "lobby") {
    const id = parts[1] ?? "";
    const tab: LobbyTab = parts[2] === "log" ? "log" : parts[2] === "metrics" ? "metrics" : "game";
    for (const link of navLobbies.querySelectorAll<HTMLElement>("a")) link.classList.toggle("current", link.dataset.id === id);
    openLobby(id, tab);
  } else {
    for (const link of navLobbies.querySelectorAll<HTMLElement>("a")) link.classList.remove("current");
    views[name]?.show(parts.slice(1).join("/") || null);
    document.title = `${TITLES[name] ?? "Dashboard"} · FAF Server`;
    if (name === "connect") {
      connectSummary.textContent = hostApi === null ? "The machine's server-host, with its address and admin token." : `Connected to ${hostApi.base}. Connect again to change the host or token.`;
    }
  }
  if (changed) window.scrollTo({ top: 0 });
}

window.addEventListener("hashchange", route);

// ---------------------------------------------------------------- the top bar and the navigation's live parts

function renderHealth(): void {
  const info = store.info;
  if (info === null) {
    health.replaceChildren();
    return;
  }
  const m = store.metrics;
  const cpus = info.cpus;
  const load = cpus.length === 0 ? 0 : cpus.reduce((sum, cpu) => sum + cpuLoad(cpu), 0) / cpus.length;
  const total = info.memory_mb?.total;
  const available = info.memory_mb?.available;
  const used = isNumber(total) && isNumber(available) ? total - available : null;
  const out = (info.links ?? []).reduce((sum, link) => sum + (isNumber(link.out_kbps) ? link.out_kbps : 0), 0);
  const recent = (values: (number | null)[]): (number | null)[] => values.slice(-150);
  const item = (label: string, value: string, spark: SVGElement | null, title: string): HTMLElement => h("a", { class: "health-item", href: "#/metrics", title }, h("span", { class: "health-label" }, label), h("span", { class: "health-value" }, value), spark);
  health.replaceChildren(
    item("CPU", `${Math.round(load)}%`, m === null ? null : sparkline(recent(m.cpu), seriesColor(0), 100), "All CPUs busy, last 5 minutes"),
    item("Memory", used === null ? "–" : `${gb(used)}${isNumber(total) ? ` / ${gb(total)}` : ""}`, m === null ? null : sparkline(recent(m.mem_used_mb), seriesColor(1), isNumber(total) ? total : undefined), "Memory in use, last 5 minutes"),
    item("Sending", rate(out), m === null ? null : sparkline(recent(sumSeries(Object.values(m.net).map((link) => link.out_kbps))), seriesColor(2)), "All links sending, last 5 minutes"),
  );
}

function renderAlerts(): void {
  const list = currentAlerts();
  alertsLink.hidden = hostApi === null;
  const bad = list.some((alert) => alert.tone === "bad");
  alertsLink.className = `top-alerts${list.length === 0 ? " none" : bad ? " tone-bad" : " tone-warn"}`;
  alertsLink.title = list.length === 0 ? "Nothing needs attention" : list.map((alert) => alert.text).join("\n");
  alertsLink.replaceChildren(icon(list.length === 0 ? "check" : "warn"), h("span", {}, list.length === 0 ? "All good" : `${list.length} ${list.length === 1 ? "alert" : "alerts"}`));
}

function renderNav(): void {
  const running = store.lobbies.filter((lobby) => RUNNING.has(lobby.state));
  byId<HTMLElement>("nav-count-lobbies").textContent = hostApi === null ? "" : String(running.length);
  const queued = store.queue.length;
  const queueCount = byId<HTMLElement>("nav-count-queue");
  queueCount.textContent = hostApi === null || queued === 0 ? "" : String(queued);
  queueCount.classList.toggle("warn", queued > 0);
  const pool = store.pool;
  const hosting = byId<HTMLElement>("nav-count-hosting");
  hosting.textContent = hostApi === null || pool === null ? "" : pool.pool.enabled ? "on" : "off";
  hosting.classList.toggle("on", pool?.pool.enabled === true);
  const openId = openLobbyId();
  fill(navLobbies, 
    running.length === 0 ? h("span", { class: "nav-empty" }, "No lobby running") : h("span", { class: "nav-group" }, "Running"),
    ...running.slice(0, 12).map((lobby) => {
      const dot = h("span", { class: "swatch", "aria-hidden": "true" });
      dot.style.setProperty("--swatch", colour(lobby.id));
      return h("a", { class: `nav-lobby${lobby.id === openId ? " current" : ""}`, href: `#/lobby/${encodeURIComponent(lobby.id)}`, "data-id": lobby.id, title: `${displayName(lobby)}: ${lobby.state}` }, dot, h("span", { class: "nav-lobby-name" }, displayName(lobby)), h("span", { class: `nav-lobby-state state-${lobby.state}` }, lobby.state === "game" ? "game" : lobby.state === "lobby" ? "lobby" : lobby.state));
    }),
    running.length > 12 ? h("a", { class: "nav-more", href: "#/lobbies" }, `${running.length - 12} more`) : null,
  );
}

on("host", renderHealth);
on("metrics", renderHealth);
on("alerts", renderAlerts);
on("lists", renderNav);
on("pool", renderNav);
on("queue", renderNav);

function hostHealth(error: string | null, unauthorized: boolean): void {
  if (hostApi === null) return;
  if (error === null) setConnection("ok", store.info?.name ?? "Connected", `connected to server-host at ${hostApi.base}`);
  else setConnection("bad", unauthorized ? "Token refused" : "No answer", error);
}

// ---------------------------------------------------------------- connect

function setConnecting(busy: boolean, label: string): void {
  connectButton.disabled = busy;
  connectButton.classList.toggle("busy", busy);
  connectButton.textContent = label;
  urlInput.disabled = busy;
  tokenInput.disabled = busy;
}

connectForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void connect();
});

function disconnect(): void {
  closeLobby();
  for (const view of Object.values(views)) view.hide();
  current = "";
  stopHost();
  forgetHostData();
  hostApi = null;
  setConnected(false);
  renderNav();
  renderHealth();
}

/** Why `url` didn't answer as a server-host, for people. */
function failure(url: string, error: unknown): { short: string; why: string } {
  if (error instanceof ApiError && error.status === 401) {
    return { short: "Token refused", why: `server-host at ${url} refused the admin token: it is the content of the file its --token-file names.` };
  }
  if (error instanceof ApiError && error.status === 404) {
    return { short: "Not a host", why: `${url} answered, but not as server-host (no /api/v1/host). The dashboard talks to server-host, which listens on port ${HOST_PORT} unless its --listen says otherwise; a lone server's --rest address isn't one.` };
  }
  if (error instanceof ApiError) return { short: "Refused", why: `${url}: ${error.message}` };
  const timeout = error instanceof DOMException && error.name === "TimeoutError";
  return {
    short: "No answer",
    why: `No answer from ${url}${timeout ? ` within ${CONNECT_TIME_MS / 1000} s` : ""}. server-host listens on port ${HOST_PORT} unless its --listen says otherwise: check the address, that server-host runs there, and that its --cors-origin is this page's origin (${location.origin}).`,
  };
}

async function connect(): Promise<void> {
  if (connectButton.disabled) return;
  const url = urlInput.value.trim().replace(/\/+$/, "");
  const token = tokenInput.value.trim();
  if (!/^https?:\/\/.+/.test(url)) {
    setConnectError(`The address starts with http:// or https://, for example http://${location.hostname || "127.0.0.1"}:${HOST_PORT}.`);
    urlInput.focus();
    return;
  }
  if (token === "") {
    setConnectError("The admin token is empty: it is the content of the file server-host's --token-file names.");
    tokenInput.focus();
    return;
  }
  disconnect();
  writeStore(local, STORE_URL, url);
  writeStore(session, STORE_TOKEN, token);
  setConnectError("");
  setConnecting(true, "Connecting…");
  setConnection("busy", "Connecting…", `connecting to ${url}`);
  try {
    const host = new HostApi(url, token);
    const info = await host.host(AbortSignal.timeout(CONNECT_TIME_MS));
    hostApi = host;
    setConnected(true);
    startHost(host, info, { onHealth: hostHealth });
    void hostMaps().catch(() => undefined);
    setConnection("ok", info.name ?? "Connected", `connected to server-host at ${host.base}`);
    brandSub.textContent = host.base.replace(/^https?:\/\//, "");
    setConnecting(false, "Connect");
    if (/^#\/?connect/.test(location.hash)) location.hash = "#/";
    route();
  } catch (error) {
    disconnect();
    const { short, why } = failure(url, error);
    setConnection("bad", short, why);
    setConnectError(why);
    setConnecting(false, "Connect");
    route();
  }
}

// ---------------------------------------------------------------- start

setConnected(false);
renderNav();
route();
// With an address and a token at hand (this tab's, or the dev server's defaults), connect right away.
if (tokenInput.value.trim() !== "") void connect();
