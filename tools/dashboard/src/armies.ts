// The live game panel: one card per army from `GET /api/v1/armies`, grouped by team.

import type { Army, Resource } from "./api.ts";
import { faction, h, icon, isNumber, num, resultTone, words } from "./dom.ts";

function meter(kind: string, label: string, value: unknown, max: unknown, detail: Node | string, tone = ""): HTMLElement {
  const has = isNumber(value) && isNumber(max) && max > 0;
  const ratio = has ? Math.min(1, Math.max(0, (value as number) / (max as number))) : 0;
  const bar = h("div", {
    class: `bar ${kind}${tone === "" ? "" : ` tone-${tone}`}`,
    role: "meter",
    "aria-label": label,
    "aria-valuemin": 0,
    "aria-valuemax": has ? (max as number) : 100,
    "aria-valuenow": has ? (value as number) : 0,
    "aria-valuetext": has ? `${num(value)} of ${num(max)}` : "unknown",
  });
  const fill = h("span", { class: "fill" });
  fill.style.width = `${(ratio * 100).toFixed(1)}%`;
  bar.append(fill);
  return h(
    "div",
    { class: `meter-row ${kind}` },
    h("div", { class: "meter-head" }, h("span", { class: "meter-label" }, label), h("span", { class: "meter-value" }, detail)),
    bar,
  );
}

function resource(kind: "mass" | "energy", label: string, value: Resource | null | undefined): HTMLElement {
  const income = value?.income;
  const detail = h(
    "span",
    {},
    h("b", {}, num(value?.stored)),
    h("span", { class: "dim" }, ` / ${num(value?.storage)}`),
    " ",
    h("span", { class: `rate${isNumber(income) && income < 0 ? " negative" : ""}` }, isNumber(income) ? `${income >= 0 ? "+" : ""}${num(income, 1)}/s` : "–"),
  );
  return meter(kind, label, value?.stored, value?.storage, detail);
}

function acu(army: Army): HTMLElement {
  const commander = army.acu;
  if (commander === null || commander === undefined) {
    return h("div", { class: "acu" }, meter("health", "ACU", null, null, "–"));
  }
  if (commander.alive === false) {
    return h("div", { class: "acu destroyed" }, h("div", { class: "acu-dead" }, icon("x"), "ACU destroyed"));
  }
  const health = commander.health;
  const max = commander.max_health;
  const ratio = isNumber(health) && isNumber(max) && max > 0 ? health / max : NaN;
  const tone = Number.isNaN(ratio) ? "" : ratio <= 0.25 ? "bad" : ratio <= 0.5 ? "warn" : "ok";
  const detail = h(
    "span",
    {},
    h("b", {}, num(health)),
    h("span", { class: "dim" }, ` / ${num(max)}`),
    Number.isNaN(ratio) ? "" : h("span", { class: `pct tone-${tone}` }, ` ${Math.round(ratio * 100)}%`),
  );
  const enhancements = (commander.enhancements ?? []).filter((name): name is string => typeof name === "string" && name !== "");
  return h(
    "div",
    { class: "acu" },
    meter("health", "ACU health", health, max, detail, tone),
    enhancements.length === 0
      ? h("div", { class: "chips muted-chips" }, h("span", { class: "chip ghost" }, "no upgrades"))
      : h("ul", { class: "chips", "aria-label": "ACU upgrades" }, ...enhancements.map((name) => h("li", { class: "chip upgrade" }, words(name)))),
  );
}

function card(army: Army): HTMLElement {
  const side = faction(army.faction);
  const name = army.name ?? `Army ${army.army}`;
  const destroyed = army.acu?.alive === false;
  const result = typeof army.result === "string" && army.result !== "" ? army.result : null;
  const units = army.units;
  const capRatio = isNumber(units?.count) && isNumber(units?.cap) && units.cap > 0 ? units.count / units.cap : 0;
  return h(
    "article",
    { class: `army-card faction-${side?.key ?? "none"}${destroyed ? " is-destroyed" : ""}`, "aria-label": `${name}, army ${army.army}` },
    h(
      "header",
      { class: "army-head" },
      h("span", { class: "faction-badge", title: side?.name ?? "faction unknown" }, side?.short ?? "?"),
      h(
        "div",
        { class: "army-title" },
        h("strong", { class: "army-name" }, name),
        h("span", { class: "sub" }, `Army ${army.army}`, isNumber(army.uid) ? ` · uid ${army.uid}` : "", side ? ` · ${side.name}` : ""),
      ),
      army.human === true
        ? h("span", { class: "tag human" }, "Human")
        : army.human === false
          ? h("span", { class: "tag ai" }, "AI")
          : null,
    ),
    h(
      "div",
      { class: "army-score" },
      h("span", { class: "score-label" }, "Score"),
      h("span", { class: "score-value" }, num(army.score)),
      result === null ? null : h("span", { class: `result-chip tone-${resultTone(result)}` }, icon(resultTone(result) === "bad" ? "flag" : "trophy"), result),
    ),
    h(
      "div",
      { class: "meters" },
      resource("mass", "Mass", army.mass),
      resource("energy", "Energy", army.energy),
      meter(
        "units",
        "Units",
        units?.count,
        units?.cap,
        h("span", {}, h("b", {}, num(units?.count)), h("span", { class: "dim" }, ` / ${num(units?.cap)}`)),
        capRatio >= 0.95 ? "bad" : capRatio >= 0.8 ? "warn" : "",
      ),
    ),
    acu(army),
  );
}

/** The armies grouped by team, teams in order; armies without a team last. */
export function renderArmies(target: HTMLElement, armies: Army[]): void {
  const teams = new Map<number | null, Army[]>();
  for (const army of armies) {
    const team = isNumber(army.team) ? army.team : null;
    const list = teams.get(team) ?? [];
    list.push(army);
    teams.set(team, list);
  }
  const order = [...teams.keys()].sort((a, b) => (a === null ? 1 : b === null ? -1 : a - b));
  const groups = order.map((team) => {
    const list = (teams.get(team) ?? []).sort((a, b) => a.army - b.army);
    const score = list.reduce((sum, army) => sum + (isNumber(army.score) ? army.score : 0), 0);
    return h(
      "section",
      { class: "team", "aria-label": team === null ? "No team" : `Team ${team}` },
      h(
        "div",
        { class: "team-head" },
        h("h3", {}, team === null ? "No team" : `Team ${team}`),
        h("span", { class: "team-meta" }, `${list.length} ${list.length === 1 ? "army" : "armies"} · score ${num(score)}`),
      ),
      h("div", { class: "army-grid" }, ...list.map(card)),
    );
  });
  target.replaceChildren(...groups);
}
