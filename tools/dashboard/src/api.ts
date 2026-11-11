// The dedicated server's REST API (plan WP17.11, docs/SWITCHES.md `--rest`): status, the armies of a running game,
// control ops, and the event stream, each with the admin token as a bearer token. No browser-only API here, so Node
// runs it too (scripts/smoke.ts).

export interface Seat {
  uid: number;
  name: string;
  joined: boolean;
  loaded?: boolean;
  lost?: boolean;
  gone?: boolean;
  away?: boolean;
  ping_ms?: number | null;
  /** In the lobby: "yes", "no", or "" before the player's lobby set it. */
  ready?: string;
  /** The lobby slot the host's lobby gave it; 0 before. */
  slot?: number;
  speed_limit?: number | null;
  camera_updates?: number;
  backlog_kb?: number;
  behind_beats?: number;
  /** "" before the launch, then "loading", "rules", "loaded". */
  load?: string;
  /** "same", "differs", "missing", or "" before the verdict. */
  content?: string;
  /** "allowed", "outside", "missing", or "" before the verdict. */
  mods?: string;
  ui_mods?: string[];
  [key: string]: unknown;
}

export interface Status {
  id: number;
  ok: true;
  phase: "lobby" | "game" | string;
  host?: number;
  started?: boolean;
  beat?: number;
  paused?: boolean;
  seats?: Seat[];
  /** The configured start-when-ready countdown in seconds; 0 or absent when off. */
  start_when_ready_seconds?: number;
  /** Seconds left of a running countdown; present only while one runs. */
  countdown_seconds?: number;
  [key: string]: unknown;
}

export interface Resource {
  stored?: number | null;
  income?: number | null;
  storage?: number | null;
}

export interface Army {
  /** The army's number, from 1. */
  army: number;
  name?: string | null;
  team?: number | null;
  /** 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim. */
  faction?: number | null;
  human?: boolean | null;
  /** Humans only. */
  uid?: number | null;
  score?: number | null;
  mass?: Resource | null;
  energy?: Resource | null;
  units?: { count?: number | null; cap?: number | null } | null;
  acu?: { alive?: boolean | null; health?: number | null; max_health?: number | null; enhancements?: string[] | null } | null;
  /** The sim's result once known, e.g. "victory 10". */
  result?: string | null;
  [key: string]: unknown;
}

export interface Armies {
  ok: true;
  beat?: number;
  armies: Army[];
  [key: string]: unknown;
}

export interface Answer {
  ok: boolean;
  error?: string;
  [key: string]: unknown;
}

export interface ServerEvent {
  event: string;
  [key: string]: unknown;
}

// Plain fields, not constructor parameter properties: Node runs this file by stripping types only.
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** The answer's JSON, or `ok: false` when its body isn't JSON (a proxy's error page, say). */
async function readAnswer(response: Response): Promise<Answer> {
  try {
    return (await response.json()) as Answer;
  } catch {
    return { ok: false };
  }
}

export class ServerApi {
  readonly base: string;
  private readonly token: string;

  constructor(base: string, token: string) {
    this.base = base.replace(/\/+$/, "");
    this.token = token;
  }

  private headers(json: boolean): Record<string, string> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}` };
    if (json) {
      headers["Content-Type"] = "application/json";
    }
    return headers;
  }

  /** `GET /api/v1/status`: the lobby or the game, with its seats. `signal` gives up on it (a time limit, say). */
  async status(signal?: AbortSignal): Promise<Status> {
    const response = await fetch(`${this.base}/api/v1/status`, { headers: this.headers(false), signal });
    const body = await readAnswer(response);
    if (!response.ok || !body.ok) {
      throw new ApiError(body.error ?? `status: HTTP ${response.status}`, response.status);
    }
    return body as Status;
  }

  /**
   * `GET /api/v1/armies`: each army of the running game (score, resources, units, ACU). Throws `ApiError` with 400
   * ("no game yet") in the lobby, and 404 from a server without this endpoint.
   */
  async armies(signal?: AbortSignal): Promise<Armies> {
    const response = await fetch(`${this.base}/api/v1/armies`, { headers: this.headers(false), signal });
    const body = await readAnswer(response);
    if (!response.ok || !body.ok) {
      throw new ApiError(body.error ?? `armies: HTTP ${response.status}`, response.status);
    }
    const armies = body as Armies;
    return { ...armies, armies: Array.isArray(armies.armies) ? armies.armies : [] };
  }

  /**
   * `POST /api/v1/ops/<op>` with the op's fields: the server's answer, `ok` false with its `error` when it refused
   * (HTTP 400). A missing or wrong token, or a server that isn't there, throws.
   */
  async op(name: string, fields: Record<string, unknown> = {}): Promise<Answer> {
    const response = await fetch(`${this.base}/api/v1/ops/${encodeURIComponent(name)}`, {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify(fields),
    });
    const body = await readAnswer(response);
    if (response.status === 401) {
      throw new ApiError(body.error ?? "the admin token was refused", 401);
    }
    if (!body.ok && body.error === undefined && !response.ok) {
      body.error = `HTTP ${response.status}`;
    }
    return body;
  }

  /**
   * `GET /api/v1/events`, read until `signal` aborts or the server closes it: each Server-Sent Event's JSON to
   * `onEvent`. Read with fetch, as the browser's EventSource can't send the token. `onOpen` runs once the stream is
   * established.
   */
  async events(onEvent: (event: ServerEvent) => void, signal: AbortSignal, onOpen?: () => void): Promise<void> {
    const response = await fetch(`${this.base}/api/v1/events`, { headers: this.headers(false), signal });
    if (!response.ok || response.body === null) {
      throw new ApiError(`events: HTTP ${response.status}`, response.status);
    }
    onOpen?.();
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffered = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        return;
      }
      buffered = (buffered + decoder.decode(value, { stream: true })).replace(/\r\n/g, "\n");
      // An event ends at a blank line; its `data:` lines hold the JSON.
      let end = buffered.indexOf("\n\n");
      while (end >= 0) {
        const block = buffered.slice(0, end);
        buffered = buffered.slice(end + 2);
        const data = block
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (data !== "") {
          try {
            onEvent(JSON.parse(data) as ServerEvent);
          } catch {
            // not JSON: ignored, as the stream's comments are
          }
        }
        end = buffered.indexOf("\n\n");
      }
    }
  }
}
