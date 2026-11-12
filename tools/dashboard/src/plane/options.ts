// FAF's game settings as a form (plan WP17.20), shared by the operator's configuration panel (config.ts), a running
// lobby's settings (lobby.ts) and the player's claim page (claim.ts): options grouped into rules, teams, AI and other, the map's own options for adaptive
// maps, each with its default shown, changed values marked and a reset; a filter over all of them. Only values that
// differ from their defaults are kept in `chosen`.

import type { SettingKey, SettingOption, Settings } from "../api.ts";
import { h } from "../dom.ts";

const GROUPS: [string, string][] = [
  ["rules", "Rules"],
  ["units", "Units"],
  ["teams", "Teams"],
  ["ai", "AI"],
  ["other", "Other"],
];

/** The usual options, for a host that doesn't list its settings yet. */
export const FALLBACK_OPTIONS: SettingOption[] = [
  { key: "Victory", label: "Victory Condition", group: "rules", default: "demoralization", values: [{ key: "demoralization", text: "Assassination" }, { key: "domination", text: "Supremacy" }, { key: "eradication", text: "Annihilation" }, { key: "sandbox", text: "Sandbox" }] },
  { key: "Share", label: "Share Conditions", group: "rules", default: "FullShare", values: [{ key: "FullShare", text: "Full Share" }, { key: "ShareUntilDeath", text: "Share Until Death" }, { key: "PartialShare", text: "Partial Share" }, { key: "TransferToKiller", text: "Transfer To Killer" }, { key: "Defectors", text: "Defectors" }, { key: "CivilianDeserter", text: "Civilian Deserter" }] },
  { key: "FogOfWar", label: "Fog of War", group: "rules", default: "explored", values: [{ key: "explored", text: "Explored" }, { key: "none", text: "None" }] },
  { key: "GameSpeed", label: "Game Speed", group: "rules", default: "normal", values: [{ key: "normal", text: "Normal" }, { key: "fast", text: "Fast" }, { key: "adjustable", text: "Adjustable" }] },
  { key: "CheatsEnabled", label: "Cheating", group: "rules", default: "false", values: [{ key: "false", text: "Off" }, { key: "true", text: "On" }] },
  { key: "Timeouts", label: "Allowed Pauses", group: "rules", default: "3", values: [{ key: "0", text: "None" }, { key: "3", text: "Three" }, { key: "-1", text: "Infinite" }] },
  { key: "NoRushOption", label: "No Rush Timer", group: "rules", default: "Off", values: [{ key: "Off", text: "Off" }, ...["1", "2", "3", "4", "5", "10", "15", "20", "25", "30", "35", "40", "45", "50", "55", "60"].map((m) => ({ key: m, text: `${m} minutes` }))] },
  { key: "UnitCap", label: "Unit Cap", group: "units", default: "1000", values: ["125", "250", "375", "500", "625", "750", "875", "1000", "1250", "1500"].map((x) => ({ key: x, text: x })) },
  { key: "PrebuiltUnits", label: "Prebuilt Units", group: "units", default: "Off", values: [{ key: "Off", text: "Off" }, { key: "On", text: "On" }] },
];

export function sameKey(a: SettingKey | null | undefined, b: SettingKey | null | undefined): boolean {
  return a !== null && a !== undefined && b !== null && b !== undefined && String(a) === String(b);
}

export interface OptionsForm {
  /** The values that differ from their defaults, by option key. */
  chosen: Map<string, SettingKey>;
  /** Starting values someone else picked (an open slot's, by its operator), marked on their option. */
  preset?: ReadonlyMap<string, SettingKey>;
  /** What the preset is called on the option, e.g. "slot". */
  presetLabel?: string;
  /** The fields' id prefix (default "set-"): two forms on one page need different ones. */
  idPrefix?: string;
  /** Runs after every change by the user. */
  onChange(): void;
}

/** Drops chosen values the settings no longer have (another map's options, a value that went away). */
export function pruneChosen(chosen: Map<string, SettingKey>, settings: Settings): void {
  const valid = new Map<string, SettingOption>();
  for (const option of [...settings.options, ...settings.map_options]) valid.set(option.key, option);
  for (const [key, value] of [...chosen]) {
    const option = valid.get(key);
    if (option === undefined || !option.values.some((candidate) => sameKey(candidate.key, value))) chosen.delete(key);
  }
}

function optionField(option: SettingOption, form: OptionsForm): HTMLElement {
  const { chosen } = form;
  const id = `${form.idPrefix ?? "set-"}${option.key}`;
  const select = h("select", { id, "data-key": option.key });
  const defaultIndex = option.values.findIndex((value) => sameKey(value.key, option.default));
  const preset = form.preset?.get(option.key);
  const presetIndex = preset === undefined ? -1 : option.values.findIndex((value) => sameKey(value.key, preset));
  const presetLabel = form.presetLabel ?? "preset";
  option.values.forEach((value, index) => {
    const text = value.text ?? String(value.key);
    const marks = [index === defaultIndex ? "default" : "", index === presetIndex && index !== defaultIndex ? presetLabel : ""].filter((mark) => mark !== "");
    select.append(h("option", { value: String(index), title: value.help ?? "" }, marks.length > 0 ? `${text} (${marks.join(", ")})` : text));
  });
  const current = chosen.get(option.key);
  const currentIndex = current === undefined ? defaultIndex : option.values.findIndex((value) => sameKey(value.key, current));
  select.value = String(Math.max(0, currentIndex));
  const reset = h("button", { type: "button", class: "reset", "aria-label": `Reset ${option.label ?? option.key} to its default`, title: "Back to the default" }, "↺");
  const helpId = `${id}-help`;
  const help = option.help ? h("span", { id: helpId, class: "sr-only" }, option.help) : null;
  if (help !== null) select.setAttribute("aria-describedby", helpId);
  const presetChip = presetIndex >= 0 && presetIndex !== defaultIndex ? h("span", { class: "chip tiny tone-info preset-chip", title: `The ${presetLabel}'s starting value: ${option.values[presetIndex]?.text ?? String(preset)}` }, presetLabel) : null;
  const field = h(
    "div",
    { class: "field setting", "data-search": `${option.label ?? ""} ${option.key}`.toLowerCase(), title: option.help ?? "" },
    h("label", { for: id }, h("span", { class: "changed-dot", "aria-hidden": "true" }), option.label ?? option.key, presetChip),
    h("div", { class: "setting-row" }, select, reset),
    help,
  );
  const sync = (): void => {
    const changed = chosen.has(option.key);
    field.classList.toggle("changed", changed);
    reset.hidden = !changed;
    const value = option.values[Number(select.value)];
    select.title = value?.help ?? option.help ?? "";
  };
  select.addEventListener("change", () => {
    const value = option.values[Number(select.value)];
    if (value === undefined || sameKey(value.key, option.default)) chosen.delete(option.key);
    else chosen.set(option.key, value.key);
    sync();
    form.onChange();
  });
  reset.addEventListener("click", () => {
    chosen.delete(option.key);
    select.value = String(Math.max(0, defaultIndex));
    sync();
    form.onChange();
    select.focus();
  });
  sync();
  return field;
}

/**
 * Draws the settings into `box` as collapsible groups (the first and the map's open). `mapTitle` names the map group;
 * null leaves the map's own options out.
 */
export function renderOptions(box: HTMLElement, settings: Settings, mapTitle: string | null, form: OptionsForm): void {
  const groups: { id: string; title: string; options: SettingOption[] }[] = [];
  for (const [id, title] of GROUPS) {
    const options = settings.options.filter((option) => (option.group ?? "other") === id);
    if (options.length > 0) groups.push({ id, title, options });
  }
  const others = settings.options.filter((option) => !GROUPS.some(([id]) => id === (option.group ?? "other")));
  if (others.length > 0) groups.push({ id: "more", title: "More", options: others });
  if (mapTitle !== null && settings.map_options.length > 0) {
    groups.push({ id: "map", title: `Map options (${mapTitle})`, options: settings.map_options });
  }
  box.replaceChildren(
    ...groups.map((group, index) =>
      h(
        "details",
        { class: `set-group${group.id === "map" ? " map-group" : ""}`, "data-group": group.id, open: index === 0 || group.id === "map" },
        h("summary", {}, h("span", { class: "set-title" }, group.title), h("span", { class: "set-count dim small" })),
        h("div", { class: "set-grid" }, ...group.options.map((option) => optionField(option, form))),
      ),
    ),
  );
}

/** Updates each group's count line; the number of changed settings shown. */
export function countChanges(box: HTMLElement): number {
  let total = 0;
  for (const group of box.querySelectorAll<HTMLDetailsElement>(".set-group")) {
    const fields = group.querySelectorAll(".setting");
    const changed = group.querySelectorAll(".setting.changed").length;
    total += changed;
    const count = group.querySelector(".set-count");
    if (count !== null) count.textContent = `${fields.length}${changed > 0 ? ` · ${changed} changed` : ""}`;
    group.classList.toggle("has-changes", changed > 0);
  }
  return total;
}

/** Shows the settings whose label or key holds the query, opening the groups that have one. */
export function filterOptions(box: HTMLElement, text: string): void {
  const query = text.trim().toLowerCase();
  for (const group of box.querySelectorAll<HTMLDetailsElement>(".set-group")) {
    let shown = 0;
    for (const field of group.querySelectorAll<HTMLElement>(".setting")) {
      const match = query === "" || (field.dataset.search ?? "").includes(query);
      field.hidden = !match;
      if (match) shown += 1;
    }
    group.hidden = shown === 0;
    if (query !== "" && shown > 0) group.open = true;
  }
}
