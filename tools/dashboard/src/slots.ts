// The slots editor: one row per start spot of the map, each a player (named, or open to whoever gets its join line),
// an AI with its personality, or empty; with team and faction. Its marks go on the map preview, its seats to the host
// with each seat's start spot. Shared by the create flow and the public request page.

import type { NewSeat } from "./api.ts";
import { h, icon } from "./dom.ts";
import type { SpotMark } from "./maps.ts";

export type SlotKind = "human" | "ai" | "empty";

export interface SlotDraft {
  kind: SlotKind;
  name: string;
  uid: string;
  ai: string;
  /** 1 UEF, 2 Aeon, 3 Cybran, 4 Seraphim, 5 random. */
  faction: number;
  /** FAF's numbering: 1 = no team, 2 = team 1, ... */
  team: number;
}

export interface SlotsOptions {
  /** The AI personalities: [key, label]. */
  ais(): [string, string][];
  /** Spot 1 is the requester's own seat: always a player, named by `hostName`. */
  hostName?: () => string;
  /** The most filled seats allowed (the pool's player limit). */
  maxSeats?: () => number;
  /** Offer a uid field for players (the operator's lobbies). */
  uid?: boolean;
  /** A tournament's player list: every player needs a FAF id from it (the control service refuses others). */
  uidRule?: () => UidRule | null;
  onChange(): void;
}

export interface UidRule {
  /** The FAF ids allowed in a player's seat. */
  allowed: number[];
  /** Whose list it is, for the messages: "Spring Cup's player list". */
  list: string;
}

let datalistSeq = 0;

export const FACTIONS: [number, string][] = [
  [5, "Random"],
  [1, "UEF"],
  [2, "Aeon"],
  [3, "Cybran"],
  [4, "Seraphim"],
];

function select(label: string, choices: [string, string][], value: string, onChange: (value: string) => void, className = ""): HTMLSelectElement {
  const node = h("select", { "aria-label": label, class: className }, ...choices.map(([choice, text]) => h("option", { value: choice }, text)));
  node.value = choices.some(([choice]) => choice === value) ? value : (choices[0]?.[0] ?? "");
  node.addEventListener("change", () => onChange(node.value));
  return node;
}

export class SlotsEditor {
  readonly root: HTMLElement;
  slots: SlotDraft[] = [];
  selected = 0;
  private readonly rows: HTMLElement;
  private readonly summary: HTMLElement;
  private readonly options: SlotsOptions;
  private readonly allowedList: HTMLDataListElement;

  constructor(options: SlotsOptions) {
    this.options = options;
    this.rows = h("div", { class: "slot-rows", role: "list" });
    this.summary = h("span", { class: "dim small" });
    this.allowedList = h("datalist", { id: `slot-uids-${++datalistSeq}` });
    const split = h("button", { type: "button", class: "btn small" }, icon("users", "icon tiny"), "Two teams: odd vs even spots");
    split.addEventListener("click", () => {
      this.slots.forEach((slot, index) => (slot.team = index % 2 === 0 ? 2 : 3));
      this.changed();
    });
    const noTeams = h("button", { type: "button", class: "btn small ghost" }, "No teams");
    noTeams.addEventListener("click", () => {
      for (const slot of this.slots) slot.team = 1;
      this.changed();
    });
    const fill = h("button", { type: "button", class: "btn small ghost" }, "Fill empty spots with AI");
    fill.addEventListener("click", () => {
      const ai = this.defaultAi();
      for (const slot of this.slots) {
        if (slot.kind !== "empty") continue;
        if (this.filled() >= this.limit()) break;
        slot.kind = "ai";
        slot.ai = ai;
      }
      this.changed();
    });
    const clear = h("button", { type: "button", class: "btn small ghost" }, "Clear");
    clear.addEventListener("click", () => {
      this.slots.forEach((slot, index) => {
        if (index === 0 && this.options.hostName !== undefined) return;
        slot.kind = "empty";
      });
      this.changed();
    });
    this.root = h(
      "div",
      { class: "slots" },
      h("div", { class: "slots-tools" }, this.summary, h("div", { class: "slots-buttons" }, split, noTeams, fill, clear)),
      h("div", { class: "slot-head", "aria-hidden": "true" }, h("span", {}, "Spot"), h("span", {}, "Who"), h("span", {}, "Name or AI"), h("span", {}, "Team"), h("span", {}, "Faction")),
      this.rows,
      this.allowedList,
    );
  }

  private limit(): number {
    return this.options.maxSeats?.() ?? Number.POSITIVE_INFINITY;
  }

  filled(): number {
    return this.slots.filter((slot) => slot.kind !== "empty").length;
  }

  private defaultAi(): string {
    const keys = this.options.ais().map(([key]) => key);
    return keys.includes("adaptive") ? "adaptive" : (keys[0] ?? "adaptive");
  }

  /** A new map: as many rows as it has spots, keeping what was set on the spots both have. */
  setSpots(count: number, fresh: (index: number) => SlotKind): void {
    const next: SlotDraft[] = [];
    for (let i = 0; i < count; i++) {
      next.push(this.slots[i] ?? { kind: fresh(i), name: "", uid: "", ai: this.defaultAi(), faction: 5, team: i % 2 === 0 ? 2 : 3 });
    }
    if (this.options.hostName !== undefined && next[0] !== undefined) next[0].kind = "human";
    // Over the limit (a smaller pool, fewer spots): the last filled ones empty.
    for (let i = next.length - 1; i >= 0 && next.filter((slot) => slot.kind !== "empty").length > this.limit(); i--) {
      const slot = next[i];
      if (slot !== undefined && !(i === 0 && this.options.hostName !== undefined)) slot.kind = "empty";
    }
    this.slots = next;
    this.selected = Math.min(this.selected, Math.max(0, count - 1));
    this.render();
  }

  /** Spot `n` (from 1) clicked on the map: its row is picked and focused. */
  focusSpot(n: number): void {
    this.selected = n - 1;
    this.render();
    this.rows.querySelectorAll<HTMLElement>(".slot-row")[n - 1]?.querySelector<HTMLElement>("select, input")?.focus();
    this.options.onChange();
  }

  private changed(): void {
    this.render();
    this.options.onChange();
  }

  marks(): SpotMark[] {
    const ais = new Map(this.options.ais());
    return this.slots.map((slot, index) => {
      const host = index === 0 && this.options.hostName !== undefined;
      const label =
        slot.kind === "empty" ? "" : slot.kind === "ai" ? (ais.get(slot.ai) ?? slot.ai).replace(/ · \d+$/, "") : host ? `${this.options.hostName?.() || "You"} (host)` : slot.name.trim() || "Open seat";
      return { label, kind: slot.kind, team: slot.team, selected: index === this.selected };
    });
  }

  /** The filled seats for the host, each on its spot. */
  seats(): NewSeat[] {
    const out: NewSeat[] = [];
    this.slots.forEach((slot, index) => {
      if (slot.kind === "empty") return;
      const seat: NewSeat = { kind: slot.kind, seat: index + 1, faction: slot.faction, team: slot.team };
      if (slot.kind === "ai") seat.ai = slot.ai;
      else {
        const name = index === 0 && this.options.hostName !== undefined ? this.options.hostName() : slot.name.trim();
        if (name !== "") seat.name = name;
        const uid = Number(slot.uid);
        if (slot.uid.trim() !== "" && Number.isInteger(uid) && uid > 0) seat.uid = uid;
      }
      out.push(seat);
    });
    return out;
  }

  /** Why the seats can't go to the host yet, or "". */
  problem(): string {
    if (this.slots.every((slot) => slot.kind !== "human")) return "Give at least one spot to a player: a game of AIs alone has nobody to host or watch it.";
    if (this.filled() > this.limit()) return `At most ${this.limit()} seats here.`;
    const rule = this.options.uidRule?.() ?? null;
    const seen = new Set<number>();
    for (const [index, slot] of this.slots.entries()) {
      if (slot.kind !== "human") continue;
      const raw = slot.uid.trim();
      if (raw !== "" && !(Number.isInteger(Number(raw)) && Number(raw) > 0)) return `Spot ${index + 1}'s uid is a whole number above 0.`;
      if (rule !== null && raw === "") return `Spot ${index + 1}: a tournament's seats are for its listed players: give the player's FAF id (uid).`;
      if (rule !== null && !rule.allowed.includes(Number(raw))) return `Spot ${index + 1}: FAF user ${raw} isn't on ${rule.list}.`;
      if (raw !== "" && seen.has(Number(raw))) return `FAF user ${raw} has two spots.`;
      if (raw !== "") seen.add(Number(raw));
    }
    return "";
  }

  render(): void {
    const rule = this.options.uidRule?.() ?? null;
    this.allowedList.replaceChildren(...(rule?.allowed ?? []).map((uid) => h("option", { value: String(uid) })));
    const ais = this.options.ais();
    const full = this.filled() >= this.limit();
    const humans = this.slots.filter((slot) => slot.kind === "human").length;
    const bots = this.slots.filter((slot) => slot.kind === "ai").length;
    this.summary.textContent = `${humans} ${humans === 1 ? "player" : "players"}, ${bots} ${bots === 1 ? "AI" : "AIs"}, ${this.slots.length - humans - bots} empty of ${this.slots.length} spots${Number.isFinite(this.limit()) ? ` · up to ${this.limit()} seats` : ""}`;
    this.rows.replaceChildren(
      ...this.slots.map((slot, index) => {
        const n = index + 1;
        const host = index === 0 && this.options.hostName !== undefined;
        if (slot.kind === "ai" && !ais.some(([key]) => key === slot.ai)) slot.ai = ais[0]?.[0] ?? slot.ai;
        const kinds: [string, string][] = host ? [["human", "You (host)"]] : [["human", "Player"], ["ai", "AI"], ["empty", "Empty"]];
        const kind = select(`Spot ${n}: who`, kinds, slot.kind, (value) => {
          const next = value === "ai" ? "ai" : value === "human" ? "human" : "empty";
          if (slot.kind === "empty" && next !== "empty" && full) {
            this.render();
            return;
          }
          slot.kind = next;
          this.selected = index;
          this.changed();
        });
        kind.disabled = host;
        let who: HTMLElement;
        if (slot.kind === "human") {
          if (host) {
            who = h("span", { class: "slot-host" }, this.options.hostName?.() || "Your name, above");
          } else {
            const name = h("input", { placeholder: "Open: anyone with its join line", spellcheck: "false", autocomplete: "off", "aria-label": `Spot ${n}: player name`, maxlength: 40 });
            name.value = slot.name;
            name.addEventListener("input", () => {
              slot.name = name.value;
              this.options.onChange();
            });
            const parts: HTMLElement[] = [name];
            if (this.options.uid === true) {
              const rule = this.options.uidRule?.() ?? null;
              const uid = h("input", {
                type: "number",
                inputmode: "numeric",
                placeholder: rule === null ? "uid" : "uid *",
                class: "slot-uid",
                list: rule === null ? null : this.allowedList.id,
                "aria-label": `Spot ${n}: uid${rule === null ? " (optional)" : ` (required, from ${rule.list})`}`,
                title: rule === null ? "The player's FAF id (optional)" : `The player's FAF id, from ${rule.list}`,
              });
              uid.value = slot.uid;
              uid.addEventListener("input", () => {
                slot.uid = uid.value;
                this.options.onChange();
              });
              parts.push(uid);
            }
            who = h("span", { class: "slot-who" }, ...parts);
          }
        } else if (slot.kind === "ai") {
          who = select(`Spot ${n}: AI personality`, ais, slot.ai, (value) => {
            slot.ai = value;
            this.options.onChange();
          });
        } else {
          who = h("span", { class: "dim small slot-empty" }, full ? "Nobody (the seat limit is reached)" : "Nobody plays here");
        }
        const off = slot.kind === "empty";
        const team = select(`Spot ${n}: team`, [["1", "No team"], ...[1, 2, 3, 4, 5, 6, 7, 8].map((t): [string, string] => [String(t + 1), `Team ${t}`])], String(slot.team), (value) => {
          slot.team = Number(value);
          this.changed();
        });
        const faction = select(`Spot ${n}: faction`, FACTIONS.map(([value, label]): [string, string] => [String(value), label]), String(slot.faction), (value) => {
          slot.faction = Number(value);
          this.options.onChange();
        });
        team.disabled = off;
        faction.disabled = off;
        const badge = h("span", { class: "slot-badge" }, String(n));
        badge.style.setProperty("--team", slot.team > 1 && !off ? `var(--series-${((slot.team - 2) % 8) + 1})` : "var(--line-strong)");
        const row = h("div", { class: `slot-row kind-${slot.kind}${index === this.selected ? " selected" : ""}`, role: "listitem" }, badge, kind, who, team, faction);
        row.addEventListener("focusin", () => {
          if (this.selected === index) return;
          this.selected = index;
          for (const [i, other] of [...this.rows.children].entries()) other.classList.toggle("selected", i === index);
          this.options.onChange();
        });
        return row;
      }),
    );
  }
}
