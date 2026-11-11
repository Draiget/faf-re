// The dedicated server's REST API (plan WP17.11, docs/SWITCHES.md `--rest`): status, control ops, and the event
// stream, each with the admin token as a bearer token. No browser-only API here, so Node runs it too
// (scripts/smoke.ts).

export interface Seat {
  uid: number;
  name: string;
  joined: boolean;
  loaded?: boolean;
  lost?: boolean;
  gone?: boolean;
  away?: boolean;
  ping_ms?: number | null;
  ready?: string;
  slot?: number;
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
    const body = (await response.json()) as Answer;
    if (!response.ok || !body.ok) {
      throw new ApiError(body.error ?? `status: HTTP ${response.status}`, response.status);
    }
    return body as Status;
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
    const body = (await response.json()) as Answer;
    if (response.status === 401) {
      throw new ApiError(body.error ?? "the admin token was refused", 401);
    }
    return body;
  }

  /**
   * `GET /api/v1/events`, read until `signal` aborts or the server closes it: each Server-Sent Event's JSON to
   * `onEvent`. Read with fetch, as the browser's EventSource can't send the token.
   */
  async events(onEvent: (event: ServerEvent) => void, signal: AbortSignal): Promise<void> {
    const response = await fetch(`${this.base}/api/v1/events`, { headers: this.headers(false), signal });
    if (!response.ok || response.body === null) {
      throw new ApiError(`events: HTTP ${response.status}`, response.status);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffered = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        return;
      }
      buffered += decoder.decode(value, { stream: true });
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
