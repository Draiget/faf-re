// A log viewer: lines with their time and level, a text filter, a level filter (everything, warnings and errors,
// errors), and follow (keep the newest line in view). `followLobbyLog` and `followHostLog` feed one from the host:
// a lobby's log is read once and then streamed; the host's own log is read again every few seconds.

import { ApiError, type HostApi, type LogLine } from "./api.ts";
import { h, icon } from "./dom.ts";

const MAX_LINES = 5000;
type Level = "all" | "warn" | "error";
const RANK: Record<string, number> = { TRACE: 0, DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3, FATAL: 3, PANIC: 3 };

export class LogView {
  readonly root: HTMLElement;
  private readonly body: HTMLElement;
  private readonly filter: HTMLInputElement;
  private readonly count: HTMLElement;
  private readonly status: HTMLElement;
  private readonly follow: HTMLInputElement;
  private readonly levelButtons = new Map<Level, HTMLButtonElement>();
  private level: Level = "all";
  private total = 0;

  constructor(options: { tall?: boolean } = {}) {
    this.filter = h("input", { type: "search", placeholder: "Filter lines", spellcheck: "false", "aria-label": "Filter the log's lines" });
    this.filter.addEventListener("input", () => this.applyFilter());
    const levels = h("div", { class: "seg-chips", role: "group", "aria-label": "Which lines" });
    for (const [level, text] of [["all", "All lines"], ["warn", "Warnings and errors"], ["error", "Errors"]] as [Level, string][]) {
      const button = h("button", { type: "button", class: "seg-chip", "aria-pressed": String(level === this.level) }, text);
      button.addEventListener("click", () => {
        this.level = level;
        for (const [key, other] of this.levelButtons) other.setAttribute("aria-pressed", String(key === level));
        this.applyFilter();
      });
      this.levelButtons.set(level, button);
      levels.append(button);
    }
    this.follow = h("input", { type: "checkbox", checked: true });
    this.follow.checked = true;
    this.follow.addEventListener("change", () => {
      if (this.follow.checked) this.scrollToEnd();
    });
    this.count = h("span", { class: "dim small log-count" });
    this.status = h("span", { class: "log-status" });
    this.body = h("div", { class: `log-body${options.tall === true ? " tall" : ""}`, role: "log", "aria-live": "off", tabindex: "0" });
    this.body.addEventListener("scroll", () => {
      // Scrolling up stops following; back at the end follows again.
      const atEnd = this.body.scrollHeight - this.body.scrollTop - this.body.clientHeight < 24;
      if (this.follow.checked !== atEnd) this.follow.checked = atEnd;
    });
    this.root = h(
      "div",
      { class: "logview" },
      h("div", { class: "log-tools" }, h("div", { class: "log-search" }, icon("terminal", "icon"), this.filter), levels, h("label", { class: "check" }, this.follow, h("span", {}, "Follow new lines")), this.status, this.count),
      this.body,
    );
  }

  setStatus(text: string, tone: "live" | "idle" | "bad" = "idle"): void {
    this.status.className = `log-status tone-${tone === "live" ? "ok" : tone === "bad" ? "bad" : "neutral"}`;
    this.status.replaceChildren(h("span", { class: "chip-dot", "aria-hidden": "true" }), text);
  }

  private row(line: LogLine): HTMLElement {
    const level = (line.level ?? "").toUpperCase();
    const node = h(
      "div",
      { class: `log-line level-${level.toLowerCase() || "none"}`, "data-rank": String(RANK[level] ?? 1) },
      h("span", { class: "log-time" }, shortTime(line.time)),
      h("span", { class: "log-level" }, level === "" ? "" : level),
      h("span", { class: "log-msg" }, level === "" ? line.text : line.text.replace(new RegExp(`^\\s*${level}\\s*`), "")),
    );
    node.hidden = !this.matches(node);
    return node;
  }

  private matches(node: HTMLElement): boolean {
    const rank = Number(node.dataset.rank ?? "1");
    if (this.level === "warn" && rank < 2) return false;
    if (this.level === "error" && rank < 3) return false;
    const query = this.filter.value.trim().toLowerCase();
    return query === "" || (node.textContent ?? "").toLowerCase().includes(query);
  }

  private applyFilter(): void {
    let shown = 0;
    for (const node of this.body.children) {
      const show = this.matches(node as HTMLElement);
      (node as HTMLElement).hidden = !show;
      if (show) shown += 1;
    }
    this.renderCount(shown);
    if (this.follow.checked) this.scrollToEnd();
  }

  private renderCount(shown?: number): void {
    const visible = shown ?? [...this.body.children].filter((node) => !(node as HTMLElement).hidden).length;
    this.count.textContent = visible === this.total ? `${this.total} lines` : `${visible} of ${this.total} lines`;
  }

  private scrollToEnd(): void {
    this.body.scrollTop = this.body.scrollHeight;
  }

  setLines(lines: LogLine[], emptyText = "No lines yet."): void {
    const rows = lines.slice(-MAX_LINES).map((line) => this.row(line));
    this.total = rows.length;
    this.body.replaceChildren(...(rows.length === 0 ? [h("p", { class: "dim log-empty" }, emptyText)] : rows));
    this.renderCount();
    if (this.follow.checked) this.scrollToEnd();
  }

  append(line: LogLine): void {
    this.body.querySelector(".log-empty")?.remove();
    this.body.append(this.row(line));
    this.total += 1;
    while (this.body.children.length > MAX_LINES) {
      this.body.firstElementChild?.remove();
      this.total -= 1;
    }
    this.renderCount();
    if (this.follow.checked) this.scrollToEnd();
  }
}

function shortTime(time: string | null | undefined): string {
  if (typeof time !== "string" || time === "") return "";
  const match = /(\d{2}:\d{2}:\d{2})/.exec(time);
  return match?.[1] ?? time;
}

/** Reads a lobby's log into `view`, then follows its stream (again after a drop) until the returned stop runs. */
export function followLobbyLog(api: HostApi, id: string, view: LogView, live: () => boolean): () => void {
  const controller = new AbortController();
  let stopped = false;
  const open = (): void => {
    if (stopped) return;
    if (!live()) {
      view.setStatus("Not running: the log as it ended", "idle");
      return;
    }
    view.setStatus("Connecting…", "idle");
    api
      .lobbyLogStream(id, (line) => view.append(line), controller.signal, () => view.setStatus("Live", "live"))
      .then(retry, (error: unknown) => {
        if (error instanceof ApiError && error.status === 404) {
          view.setStatus("No live stream on this host: read again every 5 s", "idle");
          poll();
          return;
        }
        retry();
      });
  };
  const retry = (): void => {
    if (stopped) return;
    view.setStatus("Reconnecting…", "bad");
    window.setTimeout(open, 3000);
  };
  let pollTimer: number | undefined;
  const poll = (): void => {
    if (stopped) return;
    pollTimer = window.setTimeout(() => {
      void api.lobbyLog(id, 1000).then((lines) => !stopped && view.setLines(lines), () => undefined).finally(poll);
    }, 5000);
  };
  view.setStatus("Loading…", "idle");
  api.lobbyLog(id, 1000, controller.signal).then(
    (lines) => {
      if (stopped) return;
      view.setLines(lines, "The lobby's server has written nothing yet.");
      open();
    },
    (error: unknown) => {
      if (stopped) return;
      const missing = error instanceof ApiError && error.status === 404;
      view.setLines([], missing ? "This host doesn't keep lobby logs, or this lobby has none." : `The log didn't load: ${error instanceof Error ? error.message : String(error)}`);
      view.setStatus(missing ? "No log" : "Failed", "bad");
    },
  );
  return () => {
    stopped = true;
    controller.abort();
    window.clearTimeout(pollTimer);
  };
}

/**
 * Reads the host's own log into `view`, then follows its stream until the returned stop runs; a host without the
 * stream is read again every 3 s.
 */
export function followHostLog(api: HostApi, view: LogView): () => void {
  const controller = new AbortController();
  let stopped = false;
  let streamTimer: number | undefined;
  const stream = (): void => {
    if (stopped) return;
    api.hostLogStream((line) => view.append(line), controller.signal, () => view.setStatus("Live", "live")).then(
      () => {
        if (stopped) return;
        view.setStatus("Reconnecting…", "bad");
        streamTimer = window.setTimeout(stream, 3000);
      },
      (error: unknown) => {
        if (stopped) return;
        if (error instanceof ApiError && error.status === 404) {
          poll();
          return;
        }
        view.setStatus("Reconnecting…", "bad");
        streamTimer = window.setTimeout(stream, 3000);
      },
    );
  };
  view.setStatus("Loading…", "idle");
  api.hostLog(1000, AbortSignal.timeout(5000)).then(
    (lines) => {
      if (stopped) return;
      view.setLines(lines, "The host has written nothing yet.");
      stream();
    },
    (error: unknown) => {
      if (stopped) return;
      const missing = error instanceof ApiError && error.status === 404;
      view.setLines([], missing ? "This host doesn't serve its own log." : `The log didn't load: ${error instanceof Error ? error.message : String(error)}`);
      view.setStatus(missing ? "No log" : "Failed", "bad");
    },
  );
  let stopPoll: (() => void) | null = null;
  const poll = (): void => {
    stopPoll = pollHostLog(api, view);
  };
  return () => {
    stopped = true;
    controller.abort();
    window.clearTimeout(streamTimer);
    stopPoll?.();
  };
}

/** Reads the host's own log into `view` every 3 s until the returned stop runs. */
function pollHostLog(api: HostApi, view: LogView): () => void {
  let stopped = false;
  let timer: number | undefined;
  let last = "";
  const read = (): void => {
    void api
      .hostLog(1000, AbortSignal.timeout(5000))
      .then(
        (lines) => {
          if (stopped) return;
          const signature = `${lines.length}|${lines.at(-1)?.text ?? ""}|${lines.at(-1)?.time ?? ""}`;
          if (signature !== last) {
            last = signature;
            view.setLines(lines, "The host has written nothing yet.");
          }
          view.setStatus("Live (read every 3 s)", "live");
        },
        (error: unknown) => {
          if (stopped) return;
          const missing = error instanceof ApiError && error.status === 404;
          if (missing) view.setLines([], "This host doesn't serve its own log.");
          view.setStatus(missing ? "No log" : "Not answering", "bad");
        },
      )
      .finally(() => {
        if (!stopped) timer = window.setTimeout(read, 3000);
      });
  };
  view.setStatus("Loading…", "idle");
  read();
  return () => {
    stopped = true;
    window.clearTimeout(timer);
  };
}
