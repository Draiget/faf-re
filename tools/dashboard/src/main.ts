// The dashboard: one page for a machine's server-host. It opens on the control plane (the machine, its tournament
// lobbies and open slots, the configuration panel; host.ts) before anything is connected, and a lobby opens inside it
// (`#/lobby/<id>`, plane/lobby.ts) through the host's proxy. The page talks to server-host only.

import "./style.css";
import { ApiError, HostApi } from "./api.ts";
import { byId, icon } from "./dom.ts";
import { startHost, stopHost } from "./host.ts";
import { closeLobby, openLobby, openLobbyId } from "./plane/lobby.ts";

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
const connectToggle = byId<HTMLButtonElement>("connect-toggle");
const connectSummary = byId<HTMLElement>("connect-summary");
const connectError = byId<HTMLElement>("connect-error");
const connection = byId<HTMLElement>("connection");
const connectionText = byId<HTMLElement>("connection-text");
const brandSub = byId<HTMLElement>("brand-sub");
const themeButton = byId<HTMLButtonElement>("theme");
const overview = byId<HTMLElement>("overview");
const lobbyView = byId<HTMLElement>("lobby-view");
const hostName = byId<HTMLElement>("plane-host-name");
const BRAND_SUB = brandSub.textContent ?? "";

// ---------------------------------------------------------------- theme

type Theme = "auto" | "light" | "dark";
const THEME_NEXT: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
const THEME_LABEL: Record<Theme, string> = { auto: "automatic", light: "light", dark: "dark" };
const THEME_ICON: Record<Theme, string> = { auto: "auto", light: "sun", dark: "moon" };

function applyTheme(theme: Theme): void {
  if (theme === "auto") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
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
  connection.title = detail;
}

function setConnectError(text: string): void {
  connectError.textContent = text;
  connectError.hidden = text === "";
}

function setFormOpen(open: boolean): void {
  connectForm.hidden = !open;
  connectToggle.setAttribute("aria-expanded", String(open));
  connectToggle.textContent = open ? "Hide" : "Change";
}

connectToggle.addEventListener("click", () => {
  const open = connectForm.hidden !== false;
  setFormOpen(open);
  if (open) urlInput.focus();
});

/** Connected or not: the plane's sections show their content or their empty state. */
function setConnected(on: boolean): void {
  document.body.dataset.connected = String(on);
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-configure]")) button.disabled = !on;
  if (!on) {
    hostName.textContent = "Not connected";
    brandSub.textContent = BRAND_SUB;
  }
}

// ---------------------------------------------------------------- the address and token to start from

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

/** `#/lobby/<id>` opens that lobby inside the plane; anything else shows the overview. */
function route(): void {
  const match = /^#\/lobby\/(.+)$/.exec(location.hash);
  const id = match?.[1] === undefined ? null : decodeURIComponent(match[1]);
  if (id === null || hostApi === null) {
    if (openLobbyId() !== null) closeLobby();
    overview.hidden = false;
    lobbyView.hidden = true;
    document.title = "FAF Server Dashboard";
    return;
  }
  const changed = id !== openLobbyId();
  openLobby(id);
  overview.hidden = true;
  lobbyView.hidden = false;
  if (changed) window.scrollTo({ top: 0 });
}

window.addEventListener("hashchange", route);

function hostHealth(error: string | null, unauthorized: boolean): void {
  if (hostApi === null) return;
  if (error === null) {
    setConnection("ok", "Connected", `connected to server-host at ${hostApi.base}`);
  } else {
    setConnection("bad", unauthorized ? "Token refused" : "No answer", error);
  }
}

// ---------------------------------------------------------------- connect

function setConnecting(on: boolean, label: string): void {
  connectButton.disabled = on;
  connectButton.classList.toggle("busy", on);
  connectButton.textContent = label;
  urlInput.disabled = on;
  tokenInput.disabled = on;
}

connectForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void connect();
});

function disconnect(): void {
  closeLobby();
  stopHost();
  hostApi = null;
  setConnected(false);
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
  if (connectButton.disabled) {
    return; // a connection attempt is under way
  }
  const url = urlInput.value.trim().replace(/\/+$/, "");
  const token = tokenInput.value.trim();
  if (!/^https?:\/\/.+/.test(url)) {
    setConnection("bad", "Not connected", "the address starts with http:// or https://");
    setConnectError(`The address starts with http:// or https://, for example http://${location.hostname || "127.0.0.1"}:${HOST_PORT}.`);
    urlInput.focus();
    return;
  }
  if (token === "") {
    setConnection("bad", "Not connected", "the admin token is empty");
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
  hostName.textContent = "Connecting…";
  try {
    const host = new HostApi(url, token);
    const info = await host.host(AbortSignal.timeout(CONNECT_TIME_MS));
    hostApi = host;
    setConnected(true);
    startHost(host, info, { onHealth: hostHealth, onLobbies: () => undefined });
    setConnection("ok", "Connected", `connected to server-host at ${host.base}`);
    const name = info.name ?? "";
    brandSub.textContent = `${name === "" ? "server-host" : name} · ${host.base.replace(/^https?:\/\//, "")}`;
    connectSummary.textContent = `Connected to ${name === "" ? "server-host" : name} at ${host.base}`;
    connectToggle.hidden = false;
    setFormOpen(false);
    setConnecting(false, "Reconnect");
    route();
  } catch (error) {
    disconnect();
    const { short, why } = failure(url, error);
    setConnection("bad", short, why);
    setConnectError(why);
    connectSummary.textContent = "Connect to the machine's server-host with its address and admin token";
    setFormOpen(true);
    setConnecting(false, "Connect");
    route();
  }
}

// ---------------------------------------------------------------- start

setConnected(false);
route();
// With an address and a token at hand (this tab's, or the dev server's defaults), connect right away.
if (tokenInput.value.trim() !== "") void connect();
