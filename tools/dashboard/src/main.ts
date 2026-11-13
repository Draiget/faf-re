// The dashboard, full width and height, in one of two modes. On one machine's server-host (its admin token): a top bar
// (the host, its CPU, memory and network now with their trend, what needs attention, the connection), a navigation
// (Overview, Lobbies, Create lobby, Queue, Player hosting, Logs, Metrics, and the running lobbies) and the views
// (views/*.ts; a lobby's own page is plane/lobby.ts); host.ts polls it. On the control service (signed in with FAF): the
// same views across every host it follows, limited by the viewer's role, live from its event stream (service.ts); the
// overview is the hosts (views/service.ts) and players find their own games under My games (views/games.ts).

import "./style.css";
import "./app.css";
import { ApiError, HostApi } from "./api.ts";
import { seriesColor, sparkline } from "./chart.ts";
import { ControlApi, topRole } from "./control.ts";
import { byId, fill, h, icon, isNumber } from "./dom.ts";
import { startHost, stopHost } from "./host.ts";
import { currentAlerts } from "./plane/alerts.ts";
import { closeLobby, openLobby, openLobbyId, type LobbyTab } from "./plane/lobby.ts";
import { gb, rate } from "./plane/parts.ts";
import { colour, cpuLoad, displayName, on, RUNNING, store, type Mode } from "./plane/store.ts";
import { service, startService, stopService } from "./service.ts";
import { toast } from "./ui.ts";
import { forgetHostData, hostMaps, sumSeries, type View } from "./views/common.ts";
import { createView } from "./views/create.ts";
import { gamesView } from "./views/games.ts";
import { hostingView } from "./views/hosting.ts";
import { lobbiesView } from "./views/lobbies.ts";
import { logsView } from "./views/logs.ts";
import { metricsView } from "./views/metrics.ts";
import { overviewView } from "./views/overview.ts";
import { queueView } from "./views/queue.ts";
import { serviceView } from "./views/service.ts";

const STORE_URL = "faf-dashboard.url";
const STORE_SERVICE_URL = "faf-dashboard.service-url";
const STORE_MODE = "faf-dashboard.mode";
const STORE_TOKEN = "faf-dashboard.token";
const STORE_THEME = "faf-dashboard.theme";
const CONNECT_TIME_MS = 5000;
const PROBE_MS = 3000;
/** server-host's port unless its --listen says otherwise. */
const HOST_PORT = 27180;
/** The control service's port unless its listen says otherwise. */
const SERVICE_PORT = 27190;

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
const topUser = byId<HTMLElement>("top-user");
const urlLabel = byId<HTMLElement>("url-label");
const urlDetected = byId<HTMLElement>("url-detected");
const tokenField = byId<HTMLElement>("token-field");
const serviceHelp = byId<HTMLElement>("service-help");
const connectNote = byId<HTMLElement>("connect-note");
const kindInputs = [...document.querySelectorAll<HTMLInputElement>('input[name="connect-kind"]')];
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
  connection.title = `${detail} (click to change the connection)`;
}

function setConnectError(text: string): void {
  connectError.textContent = text;
  connectError.hidden = text === "";
}

function setConnected(on: boolean): void {
  document.body.dataset.connected = String(on);
  if (!on) brandSub.textContent = BRAND_SUB;
}

/** Shows the mode on the page: what the navigation and the top bar offer follows it, and the viewer's role. */
function showMode(): void {
  document.body.dataset.mode = store.mode;
  document.body.dataset.role = store.mode === "service" ? topRole(service.me) : "admin";
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

/** Where the control service is when nothing is stored: `VITE_SERVICE_URL`, else this page's machine on its port. */
function defaultServiceUrl(): string {
  const fromEnv = (import.meta.env.VITE_SERVICE_URL ?? "").trim();
  if (fromEnv !== "") return fromEnv;
  const name = location.hostname === "" ? "localhost" : location.hostname;
  return `${location.protocol === "https:" ? "https" : "http"}://${name}:${SERVICE_PORT}`;
}

/** `VITE_HOST_TOKEN`, in the dev server only: a build never carries a token. */
function defaultToken(): string {
  return import.meta.env.DEV ? (import.meta.env.VITE_HOST_TOKEN ?? "").trim() : "";
}

let kind: Mode = readStore(local, STORE_MODE) === "service" ? "service" : "host";
const hostUrl = (): string => readStore(local, STORE_URL) || readStore(session, STORE_URL) || defaultUrl();
const serviceUrl = (): string => readStore(local, STORE_SERVICE_URL) || defaultServiceUrl();

/** The connect form for one kind: its address, and the token only for a host. */
function showKind(next: Mode, fillUrl: boolean): void {
  kind = next;
  for (const input of kindInputs) input.checked = input.value === next;
  const forService = next === "service";
  urlLabel.textContent = forService ? "Control service address" : "server-host address";
  urlInput.placeholder = forService ? `http://<service>:${SERVICE_PORT}` : `http://<host>:${HOST_PORT}`;
  tokenField.hidden = forService;
  serviceHelp.hidden = !forService;
  connectNote.textContent = forService ? "The address is kept in this browser; the service keeps your session (a cookie only it reads)." : "The address is kept in this browser; the token only for this tab.";
  if (fillUrl) urlInput.value = forService ? serviceUrl() : hostUrl();
  setConnectError("");
  renderConnectButton();
}

let signInNeeded = false;

function renderConnectButton(): void {
  connectButton.replaceChildren(kind === "service" && signInNeeded ? "Sign in with FAF" : "Connect");
}

for (const input of kindInputs) {
  input.addEventListener("change", () => {
    if (!input.checked) return;
    signInNeeded = false;
    urlDetected.textContent = "";
    showKind(input.value === "service" ? "service" : "host", true);
  });
}

// An address typed or pasted: ask it what it is, and switch the form to match (the radio stays the user's to change).
let probeTimer: number | undefined;
let probeSeq = 0;
urlInput.addEventListener("input", () => {
  window.clearTimeout(probeTimer);
  urlDetected.textContent = "";
  signInNeeded = false;
  renderConnectButton();
  probeTimer = window.setTimeout(() => void probe(), 500);
});

async function probe(): Promise<void> {
  const url = urlInput.value.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/.+/.test(url)) return;
  const seq = ++probeSeq;
  try {
    const answer = await new ControlApi(url).health(AbortSignal.timeout(PROBE_MS));
    if (seq !== probeSeq) return;
    urlDetected.textContent = `A control service: ${answer.hosts_reachable} of ${answer.hosts} ${answer.hosts === 1 ? "host" : "hosts"} answering.`;
    if (kind !== "service") showKind("service", false);
  } catch {
    if (seq !== probeSeq) return;
    if (kind === "service") urlDetected.textContent = "No control service answers there yet (or it doesn't allow this page's origin).";
  }
}

urlInput.value = kind === "service" ? serviceUrl() : hostUrl();
tokenInput.value = readStore(session, STORE_TOKEN) || defaultToken();
showKind(kind, false);

// ---------------------------------------------------------------- views and routing

let hostApi: HostApi | null = null;
let control: ControlApi | null = null;
const views: Record<string, View> = {
  overview: overviewView(),
  lobbies: lobbiesView(),
  create: createView(),
  queue: queueView(),
  hosting: hostingView(),
  logs: logsView(),
  metrics: metricsView(),
  service: serviceView(),
  games: gamesView(),
};
let current = "";
const TITLES: Record<string, string> = { overview: "Overview", service: "Overview", lobbies: "Lobbies", create: "Create lobby", queue: "Queue", hosting: "Player hosting", logs: "Logs", metrics: "Metrics", games: "My games", connect: "Connect" };
/** Views of one host only; through the service they go to the overview. */
const HOST_ONLY = new Set(["queue", "hosting", "logs", "metrics"]);

const connected = (): boolean => (store.mode === "service" ? control !== null && service.me !== null : hostApi !== null);

function showSection(name: string): void {
  for (const section of document.querySelectorAll<HTMLElement>("main > .view")) section.hidden = section.dataset.view !== name;
  const nav = name === "service" ? "overview" : name;
  for (const link of document.querySelectorAll<HTMLElement>("[data-nav]")) {
    const on = link.dataset.nav === nav;
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
  if (!connected() || name === "connect") name = "connect";
  else if (name !== "lobby" && views[name] === undefined) name = "overview";
  if (store.mode === "service") {
    if (name === "overview" || HOST_ONLY.has(name)) name = "service";
  } else if (name === "service" || name === "games") name = "overview";
  if (name !== "lobby" && openLobbyId() !== null) closeLobby();
  if (current !== name && views[current] !== undefined) views[current]?.hide();
  const changed = current !== name;
  current = name;
  showSection(name);
  if (name === "lobby") {
    const id = parts[1] ?? "";
    const tab: LobbyTab = store.mode === "service" ? "game" : parts[2] === "log" ? "log" : parts[2] === "metrics" ? "metrics" : "game";
    for (const link of navLobbies.querySelectorAll<HTMLElement>("a")) link.classList.toggle("current", link.dataset.id === id);
    openLobby(id, tab);
  } else {
    for (const link of navLobbies.querySelectorAll<HTMLElement>("a")) link.classList.remove("current");
    views[name]?.show(parts.slice(1).join("/") || null);
    document.title = `${TITLES[name] ?? "Dashboard"} · FAF Server`;
    if (name === "connect") {
      connectSummary.textContent = !connected()
        ? "One machine's server-host with its admin token, or the control service for every host, signed in with FAF."
        : store.mode === "service"
          ? `Signed in to the control service at ${control?.base ?? ""}. Connect again to change it, or connect to one host.`
          : `Connected to ${hostApi?.base ?? ""}. Connect again to change the host or token, or connect to a control service.`;
    }
  }
  if (changed) window.scrollTo({ top: 0 });
}

window.addEventListener("hashchange", route);

// ---------------------------------------------------------------- the top bar and the navigation's live parts

function renderHealth(): void {
  if (store.mode === "service") {
    renderServiceHealth();
    return;
  }
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

/** Through the service: the hosts answering, their mean load (organisers see it), the lobbies running. */
function renderServiceHealth(): void {
  const hosts = service.hosts;
  if (service.me === null) {
    health.replaceChildren();
    return;
  }
  const up = hosts.filter((host) => host.reachable);
  const loads = up.map((host) => host.load).filter(isNumber);
  const running = store.lobbies.filter((lobby) => RUNNING.has(lobby.state)).length;
  const item = (label: string, value: string, title: string, href = "#/"): HTMLElement => h("a", { class: "health-item", href, title }, h("span", { class: "health-label" }, label), h("span", { class: "health-value" }, value));
  fill(
    health,
    item("Hosts", `${up.length} / ${hosts.length}`, "Hosts answering, of those the service follows"),
    loads.length === 0 ? null : item("Load", `${Math.round(loads.reduce((sum, load) => sum + load, 0) / loads.length)}%`, "Mean CPU busy over the answering hosts, last 10 s"),
    item("Lobbies", String(running), "Lobbies running on every host", "#/lobbies"),
  );
}

function renderAlerts(): void {
  const list = currentAlerts();
  alertsLink.hidden = !connected();
  const bad = list.some((alert) => alert.tone === "bad");
  alertsLink.className = `top-alerts${list.length === 0 ? " none" : bad ? " tone-bad" : " tone-warn"}`;
  alertsLink.title = list.length === 0 ? "Nothing needs attention" : list.map((alert) => alert.text).join("\n");
  alertsLink.replaceChildren(icon(list.length === 0 ? "check" : "warn"), h("span", {}, list.length === 0 ? "All good" : `${list.length} ${list.length === 1 ? "alert" : "alerts"}`));
}

function renderNav(): void {
  const running = store.lobbies.filter((lobby) => RUNNING.has(lobby.state));
  byId<HTMLElement>("nav-count-lobbies").textContent = connected() ? String(running.length) : "";
  const queued = store.queue.length;
  const queueCount = byId<HTMLElement>("nav-count-queue");
  queueCount.textContent = hostApi === null || queued === 0 ? "" : String(queued);
  queueCount.classList.toggle("warn", queued > 0);
  const pool = store.pool;
  const hosting = byId<HTMLElement>("nav-count-hosting");
  hosting.textContent = hostApi === null || pool === null ? "" : pool.pool.enabled ? "on" : "off";
  hosting.classList.toggle("on", pool?.pool.enabled === true);
  const mine = store.mode === "service" ? running.filter((lobby) => lobby.service?.you || (lobby.service?.origin === "hosted" && lobby.service.can_stop)).length : 0;
  byId<HTMLElement>("nav-count-games").textContent = mine === 0 ? "" : String(mine);
  const openId = openLobbyId();
  fill(
    navLobbies,
    running.length === 0 ? h("span", { class: "nav-empty" }, "No lobby running") : h("span", { class: "nav-group" }, "Running"),
    ...running.slice(0, 12).map((lobby) => {
      const dot = h("span", { class: "swatch", "aria-hidden": "true" });
      dot.style.setProperty("--swatch", colour(lobby.id));
      const where = lobby.service === undefined || lobby.service === null ? "" : ` on ${lobby.service.host}`;
      return h(
        "a",
        { class: `nav-lobby${lobby.id === openId ? " current" : ""}`, href: `#/lobby/${encodeURIComponent(lobby.id)}`, "data-id": lobby.id, title: `${displayName(lobby)}${where}: ${lobby.state}` },
        dot,
        h("span", { class: "nav-lobby-name" }, displayName(lobby)),
        h("span", { class: `nav-lobby-state state-${lobby.state}` }, lobby.state === "game" ? "game" : lobby.state === "lobby" ? "lobby" : lobby.state),
      );
    }),
    running.length > 12 ? h("a", { class: "nav-more", href: "#/lobbies" }, `${running.length - 12} more`) : null,
  );
}

/** Who is signed in to the service, their role, and signing out. */
function renderUser(): void {
  const me = service.me;
  topUser.hidden = store.mode !== "service" || me === null;
  if (me === null) {
    topUser.replaceChildren();
    return;
  }
  const role = topRole(me);
  const out = h("button", { type: "button", class: "btn small ghost" }, "Sign out");
  out.addEventListener("click", () => void signOut(out));
  const roleText = role === "admin" ? "Admin" : role === "organiser" ? "Organiser" : "Player";
  const roleTitle =
    role === "admin" ? "Everything on every host" : role === "organiser" ? "Makes and runs organised lobbies of the tournaments you organise" : "Sees the hosts and lobbies, and your own place in them";
  topUser.replaceChildren(h("span", { class: "top-user-name", title: `FAF user ${me.user.uid}` }, icon("users", "icon tiny"), me.user.name || `FAF user ${me.user.uid}`), h("span", { class: `chip tiny role-chip role-${role}`, title: roleTitle }, roleText), out);
  showMode();
}

on("host", renderHealth);
on("metrics", renderHealth);
on("alerts", renderAlerts);
on("lists", () => {
  renderNav();
  if (store.mode === "service") renderHealth();
});
on("pool", renderNav);
on("queue", renderNav);
on("service", () => {
  renderUser();
  renderHealth();
  renderAlerts();
  if (store.mode === "service" && control !== null) {
    const up = service.hosts.filter((host) => host.reachable).length;
    if (service.live) setConnection("ok", `${up} of ${service.hosts.length} ${service.hosts.length === 1 ? "host" : "hosts"}`, `signed in to the control service at ${control.base}, live`);
  }
});

function hostHealth(error: string | null, unauthorized: boolean): void {
  if (hostApi === null) return;
  if (error === null) setConnection("ok", store.info?.name ?? "Connected", `connected to server-host at ${hostApi.base}`);
  else setConnection("bad", unauthorized ? "Token refused" : "No answer", error);
}

function serviceHealth(error: string | null, signedOut: boolean): void {
  if (control === null) return;
  if (error === null) return; // the "service" topic draws the live state
  if (signedOut) {
    toast("warn", "Signed out", "The session ended: sign in again.");
    disconnect();
    signInNeeded = true;
    showKind("service", true);
    setConnection("bad", "Signed out", "the control service's session ended");
    location.hash = "#/connect";
    route();
    return;
  }
  setConnection("bad", "Reconnecting", `the control service's event stream broke: ${error}`);
}

// ---------------------------------------------------------------- connect

function setConnecting(busy: boolean, label: string): void {
  connectButton.disabled = busy;
  connectButton.classList.toggle("busy", busy);
  connectButton.textContent = label;
  urlInput.disabled = busy;
  tokenInput.disabled = busy;
  for (const input of kindInputs) input.disabled = busy;
  if (!busy) renderConnectButton();
}

connectForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (kind === "service") void connectService(false);
  else void connect();
});

function disconnect(): void {
  closeLobby();
  for (const view of Object.values(views)) view.hide();
  current = "";
  stopHost();
  stopService();
  forgetHostData();
  hostApi = null;
  control = null;
  setConnected(false);
  showMode();
  renderUser();
  renderNav();
  renderHealth();
}

/** Why `url` didn't answer as a server-host, for people. */
function failure(url: string, error: unknown): { short: string; why: string } {
  if (error instanceof ApiError && error.status === 401) {
    return { short: "Token refused", why: `server-host at ${url} refused the admin token: it is the content of the file its --token-file names.` };
  }
  if (error instanceof ApiError && error.status === 404) {
    return { short: "Not a host", why: `${url} answered, but not as server-host (no /api/v1/host). The dashboard talks to server-host, which listens on port ${HOST_PORT} unless its --listen says otherwise; a lone server's --rest address isn't one. For a control service, pick Control service above.` };
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
  writeStore(local, STORE_MODE, "host");
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
    showMode();
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

/** Why the control service at `url` didn't answer, for people. */
function serviceFailure(url: string, error: unknown): string {
  if (error instanceof ApiError && error.status === 404) return `${url} answered, but not as a control service (no /api/v1/health). For one machine's server-host, pick One host above.`;
  if (error instanceof ApiError) return `${url}: ${error.message}`;
  return `No answer from ${url}. The control service listens on port ${SERVICE_PORT} unless its listen says otherwise: check the address, that it runs, and that its cors_origin is this page's origin (${location.origin}).`;
}

/**
 * Connects to the control service: is it one, and who is signed in. Signed in, the dashboard opens on it; else the
 * button signs in with FAF (the service sends the browser back here). `quiet`: at page load, no error when signed out.
 */
async function connectService(quiet: boolean): Promise<void> {
  if (connectButton.disabled) return;
  const url = urlInput.value.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/.+/.test(url)) {
    setConnectError(`The address starts with http:// or https://, for example http://${location.hostname || "localhost"}:${SERVICE_PORT}.`);
    urlInput.focus();
    return;
  }
  const api = new ControlApi(url);
  if (signInNeeded && !quiet) {
    writeStore(local, STORE_SERVICE_URL, url);
    writeStore(local, STORE_MODE, "service");
    location.href = api.loginUrl(`${location.origin}${location.pathname}${location.search}#/`);
    return;
  }
  disconnect();
  writeStore(local, STORE_SERVICE_URL, url);
  writeStore(local, STORE_MODE, "service");
  setConnectError("");
  setConnecting(true, "Connecting…");
  setConnection("busy", "Connecting…", `connecting to ${url}`);
  try {
    await api.health(AbortSignal.timeout(CONNECT_TIME_MS));
  } catch (error) {
    const why = serviceFailure(url, error);
    setConnection("bad", "No answer", why);
    if (!quiet) setConnectError(why);
    setConnecting(false, "Connect");
    route();
    return;
  }
  try {
    const me = await api.me(AbortSignal.timeout(CONNECT_TIME_MS));
    control = api;
    signInNeeded = false;
    setConnected(true);
    startService(api, me, { onHealth: serviceHealth });
    showMode();
    renderUser();
    setConnection("busy", "Loading…", `signed in to the control service at ${api.base}`);
    brandSub.textContent = `Control service · ${api.base.replace(/^https?:\/\//, "")}`;
    setConnecting(false, "Connect");
    if (/^#\/?connect/.test(location.hash)) location.hash = "#/";
    route();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      signInNeeded = true;
      setConnection("idle", "Not signed in", `the control service at ${url} answers; sign in with FAF`);
      urlDetected.textContent = "A control service. Sign in with your FAF account to go on.";
    } else {
      const why = serviceFailure(url, error);
      setConnection("bad", "Refused", why);
      if (!quiet) setConnectError(why);
    }
    setConnecting(false, "Connect");
    route();
  }
}

async function signOut(button: HTMLButtonElement): Promise<void> {
  const api = control;
  if (api === null) return;
  button.disabled = true;
  try {
    await api.logout();
  } catch (error) {
    toast("bad", "Couldn't sign out", error instanceof Error ? error.message : String(error));
    button.disabled = false;
    return;
  }
  disconnect();
  signInNeeded = true;
  showKind("service", true);
  setConnection("idle", "Signed out", "signed out of the control service");
  toast("ok", "Signed out");
  location.hash = "#/connect";
  route();
}

// ---------------------------------------------------------------- start

setConnected(false);
showMode();
renderNav();
route();
// With an address and a token at hand (this tab's, or the dev server's defaults), connect right away; a control service
// is asked who is signed in (coming back from the sign-in, the session is there).
if (kind === "service") void connectService(true);
else if (tokenInput.value.trim() !== "") void connect();
