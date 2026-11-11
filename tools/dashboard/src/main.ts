// The dashboard's page (plan WP17.4): connect to a server's REST API with its admin token, watch the lobby or game,
// run the control ops, and follow the event stream.

import "./style.css";
import { ApiError, ServerApi, type Seat, type ServerEvent, type Status } from "./api.ts";

const STORE_URL = "faf-dashboard.url";
const STORE_TOKEN = "faf-dashboard.token";
const MAX_EVENTS = 300;

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) {
    throw new Error(`no #${id}`);
  }
  return found as T;
}

function readStore(key: string): string {
  try {
    return sessionStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function writeStore(key: string, value: string): void {
  try {
    sessionStorage.setItem(key, value);
  } catch {
    // private window or blocked storage: the page works without it
  }
}

const urlInput = element<HTMLInputElement>("url");
const tokenInput = element<HTMLInputElement>("token");
const connectButton = element<HTMLButtonElement>("connect");
const connection = element<HTMLElement>("connection");
const phase = element<HTMLElement>("phase");
const seatsBody = element<HTMLTableSectionElement>("seats");
const answer = element<HTMLElement>("answer");
const eventsList = element<HTMLOListElement>("events");
const showLog = element<HTMLInputElement>("show-log");

urlInput.value = readStore(STORE_URL) || "http://127.0.0.1:27181";
tokenInput.value = readStore(STORE_TOKEN);

let api: ServerApi | null = null;
let refresh: number | undefined;
let stream: AbortController | null = null;

function setConnection(text: string, ok: boolean): void {
  connection.textContent = text;
  connection.className = ok ? "ok" : "bad";
}

function cell(row: HTMLTableRowElement, text: string, className = ""): void {
  const td = row.insertCell();
  td.textContent = text;
  if (className !== "") {
    td.className = className;
  }
}

function seatState(seat: Seat): string {
  if (seat.gone) return "gone";
  if (seat.lost) return "lost";
  if (seat.away) return "away";
  if (!seat.joined) return "not joined";
  return seat.loaded === false ? "loading" : "here";
}

function showStatus(status: Status): void {
  const parts = [`phase: ${status.phase}`];
  if (status.host !== undefined) parts.push(`host: ${status.host}`);
  if (status.beat !== undefined) parts.push(`beat ${status.beat} (${Math.floor(status.beat / 600)}:${String(Math.floor((status.beat % 600) / 10)).padStart(2, "0")})`);
  if (status.paused) parts.push("paused");
  phase.textContent = parts.join(" · ");
  seatsBody.replaceChildren();
  for (const seat of status.seats ?? []) {
    const row = seatsBody.insertRow();
    cell(row, String(seat.uid));
    cell(row, seat.name);
    const state = seatState(seat);
    cell(row, state, state === "here" ? "ok" : "warn");
    cell(row, seat.ready === undefined || seat.ready === "" ? "–" : seat.ready);
    cell(row, seat.ping_ms === undefined || seat.ping_ms === null ? "–" : `${seat.ping_ms} ms`);
    cell(row, seat.slot === undefined ? "–" : String(seat.slot));
  }
}

async function poll(): Promise<void> {
  if (api === null) return;
  try {
    showStatus(await api.status());
    setConnection(`connected to ${api.base}`, true);
  } catch (error) {
    setConnection(error instanceof ApiError && error.status === 401 ? "the admin token was refused" : `no answer from ${api.base}`, false);
  }
}

function addEvent(event: ServerEvent): void {
  const { event: name, ...fields } = event;
  const item = document.createElement("li");
  item.className = name === "log" ? "log" : "event";
  item.hidden = name === "log" && !showLog.checked;
  const time = new Date().toLocaleTimeString();
  item.textContent = name === "log" ? `${time} ${String(fields.text ?? "")}` : `${time} ${name} ${JSON.stringify(fields)}`;
  eventsList.prepend(item);
  while (eventsList.children.length > MAX_EVENTS) {
    eventsList.lastElementChild?.remove();
  }
  if (name !== "log") {
    void poll(); // something changed: the table follows at once
  }
}

function follow(current: ServerApi): void {
  stream?.abort();
  const controller = new AbortController();
  stream = controller;
  current.events(addEvent, controller.signal).catch(() => {
    if (!controller.signal.aborted) {
      setTimeout(() => {
        if (stream === controller) follow(current); // the server went away: try again
      }, 3000);
    }
  });
}

const CONNECT_TIME_MS = 5000;

function setConnecting(on: boolean, label: string): void {
  connectButton.disabled = on;
  connectButton.classList.toggle("busy", on);
  connectButton.textContent = label;
  urlInput.disabled = on;
  tokenInput.disabled = on;
}

connectButton.addEventListener("click", () => void connect());

async function connect(): Promise<void> {
  if (connectButton.disabled) {
    return; // a connection attempt is under way
  }
  const url = urlInput.value.trim();
  if (!/^https?:\/\/.+/.test(url)) {
    setConnection("the REST address starts with http:// or https://", false);
    return;
  }
  if (tokenInput.value.trim() === "") {
    setConnection("the admin token is empty", false);
    return;
  }
  // What ran before stops: the old server's table and events don't mix with the new one's.
  window.clearInterval(refresh);
  stream?.abort();
  stream = null;
  api = null;
  writeStore(STORE_URL, url);
  writeStore(STORE_TOKEN, tokenInput.value.trim());
  setConnecting(true, "Connecting…");
  setConnection(`connecting to ${url} …`, true);
  connection.className = "busy";
  const candidate = new ServerApi(url, tokenInput.value.trim());
  try {
    const status = await candidate.status(AbortSignal.timeout(CONNECT_TIME_MS));
    api = candidate;
    showStatus(status);
    setConnection(`connected to ${candidate.base}`, true);
    refresh = window.setInterval(() => void poll(), 2000);
    follow(candidate);
    setConnecting(false, "Reconnect");
  } catch (error) {
    let why = `no answer from ${url}: check the address and port, and that the server runs with --rest`;
    if (error instanceof ApiError && error.status === 401) {
      why = "the admin token was refused";
    } else if (error instanceof DOMException && error.name === "TimeoutError") {
      why = `no answer from ${url} within ${CONNECT_TIME_MS / 1000} s`;
    } else if (error instanceof ApiError) {
      why = error.message;
    }
    setConnection(why, false);
    setConnecting(false, "Connect");
  }
}

showLog.addEventListener("change", () => {
  for (const item of eventsList.querySelectorAll<HTMLLIElement>("li.log")) {
    item.hidden = !showLog.checked;
  }
});

async function run(op: string, fields: Record<string, unknown> = {}): Promise<void> {
  if (api === null) {
    answer.textContent = "connect first";
    return;
  }
  try {
    const result = await api.op(op, fields);
    answer.textContent = result.ok ? `${op}: done ${JSON.stringify(result)}` : `${op}: refused: ${result.error ?? "?"}`;
    answer.className = result.ok ? "ok" : "bad";
  } catch (error) {
    answer.textContent = `${op}: ${error instanceof Error ? error.message : String(error)}`;
    answer.className = "bad";
  }
  void poll();
}

function value(id: string): string {
  return element<HTMLInputElement>(id).value.trim();
}

for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-op]")) {
  button.addEventListener("click", () => {
    const op = button.dataset.op ?? "";
    switch (op) {
      case "set_options":
        void run(op, { options: value("options") });
        break;
      case "eject":
        void run(op, { uid: Number(value("eject-uid")), reason: value("eject-reason") });
        break;
      case "allow":
      case "disallow":
        void run(op, { address: value("address") });
        break;
      case "end":
        void run(op, { results: value("results"), reason: value("end-reason") });
        break;
      default:
        void run(op);
    }
  });
}
