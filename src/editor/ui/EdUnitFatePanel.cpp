// The Properties panel's unit: which group holds it, what becomes of it in a game (a unit, a wreck, only when the
// map's script creates its group, or never), its wreck's value, and the switch that makes it a wreck from the start.

#include <algorithm>
#include <cmath>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdGroupOptions.h"
#include "editor/doc/EdUnitFate.h"
#include "editor/doc/EdUnitWrecks.h"
#include "editor/doc/EdUnits.h"
#include "editor/ui/EdHelp.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  void EdShell::DrawUnitSpawn(
    const SelectionProperties& unit,
    const UnitGroup& root,
    const std::string& current,
    const bool civilian,
    const std::string& fateText,
    const std::vector<std::string>& lobbyLines
  )
  {
    // "Spawns": where the unit is in a game, as a choice (user ask 2026-11-11: edit the adaptive groups, not only read
    // about them): from the start as a unit or a wreck, or in a group the map's script creates, with the lobby setting
    // that brings it in. A group no setting makes yet comes with the _options.lua change that does (a value added to
    // its option, or the option written), checked by reading the script again with it (doc/EdGroupOptions).
    std::vector<std::vector<std::string>> groupPaths;
    {
      std::vector<std::string> at;
      const std::function<void(const UnitGroup&)> walk = [&](const UnitGroup& group) {
        for (const UnitGroup& child : group.groups) {
          at.push_back(child.name);
          groupPaths.push_back(at);
          walk(child);
          at.pop_back();
        }
      };
      walk(root);
    }
    static std::string cachedKey;
    static std::vector<SpawnTarget> targets;
    std::string key = mDocument.Script() + '\x1f' + mDocument.OptionsText() + '\x1f' + unit.owner;
    for (const std::vector<std::string>& groupPath : groupPaths) {
      key += '\x1e';
      for (const std::string& name : groupPath) {
        key += name + '/';
      }
    }
    if (key != cachedKey) {
      cachedKey = std::move(key);
      targets = SpawnTargets(mDocument.Script(), mDocument.OptionsText(), unit.owner, groupPaths);
    }

    // The units it applies to: the selection's units of this army when this one is among them, else this one.
    std::vector<std::string> names;
    bool inSelection = false;
    for (const auto& [owner, name] : mTools.UnitSelection()) {
      inSelection = inSelection || (owner == unit.owner && name == unit.name);
    }
    if (inSelection) {
      for (const auto& [owner, name] : mTools.UnitSelection()) {
        if (owner == unit.owner) {
          names.push_back(name);
        }
      }
    } else {
      names.push_back(unit.name);
    }
    const auto kind = [](const SpawnTarget& target) {
      return target.wreck && target.unit ? "wrecks or live units" : target.wreck ? "as wrecks" : "as live units";
    };
    // The sentence: when it appears, and as what.
    std::string preview = current == "INITIAL"
      ? std::string(
          civilian ? "From the start, as a live unit (unless Civilians is \"removed\")"
                   : "From the start, as a live unit"
        )
      : current == "WRECKAGE" ? std::string("From the start, as a wreck")
      : current.empty()       ? std::string("Never: it's in no group")
                              : "Never: nothing creates " + current;
    bool never = current.empty() || (current != "INITIAL" && current != "WRECKAGE");
    std::string optionKey;
    for (const SpawnTarget& target : targets) {
      if (target.path.back() != current) {
        continue;
      }
      const char* const as = target.wreck && target.unit ? " (wreck or unit)" : target.wreck ? " (wreck)" : " (unit)";
      never = target.rule.Never();
      preview = never                 ? "Never: " + target.when.substr(target.when.rfind("never: ", 0) == 0 ? 7 : 0)
        : target.when == "every game" ? std::string("In every game") + as
                                      : "When " + target.when + as;
      optionKey = target.rule.keys.empty() ? std::string() : target.rule.keys.front();
    }

    const float labelWidth = ImGui::CalcTextSize("Location X").x + ImGui::GetStyle().ItemSpacing.x * 2.0f;
    ImGui::AlignTextToFramePadding();
    ImGui::SetCursorPosX(
      ImGui::GetCursorPosX() + labelWidth - ImGui::CalcTextSize("Appears").x - ImGui::GetStyle().ItemSpacing.x
    );
    ImGui::TextDisabled("Appears");
    ImGui::SameLine(labelWidth + ImGui::GetStyle().WindowPadding.x);
    const float optionWidth = optionKey.empty()
      ? 0.0f
      : ImGui::CalcTextSize("Option...").x + ImGui::GetStyle().FramePadding.x * 2.0f + ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetNextItemWidth(-optionWidth - 1.0f);
    const auto move = [&](const std::vector<std::string>& to) {
      EdTools::UnitGroupAsk ask;
      ask.army = unit.owner;
      ask.names = names;
      ask.path = to;
      mTools.AskUnitGroup(std::move(ask));
    };
    if (const std::string asked = std::exchange(mSpawnAsk, std::string()); !asked.empty()) {
      bool found = asked == "INITIAL" || asked == "WRECKAGE";
      if (found) {
        move({asked});
      }
      for (const SpawnTarget& target : targets) {
        if (!found && target.path.back() == asked) {
          found = true;
          move(target.path);
          if (!target.optionsWith.empty()) {
            mDocument.SetOptionsText(target.optionsWith);
          }
          gpg::Logf(
            "editor: /unitspawn %s: %zu unit(s) moved; %s%s",
            asked.c_str(),
            names.size(),
            target.when.c_str(),
            target.optionsChange.empty() ? "" : ("; " + target.optionsChange).c_str()
          );
        }
      }
      if (!found) {
        gpg::Warnf("editor: /unitspawn %s: not a group %s's units can spawn in", asked.c_str(), unit.owner.c_str());
      }
    }
    if (never) {
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
    }
    const bool open = ImGui::BeginCombo("##spawns", preview.c_str(), ImGuiComboFlags_HeightLarge);
    if (never) {
      ImGui::PopStyleColor();
    }
    if (!open && ImGui::IsItemHovered()) {
      ImGui::BeginTooltip();
      ImGui::PushTextWrapPos(ImGui::GetFontSize() * 30.0f);
      ImGui::TextUnformatted(fateText.c_str());
      for (const std::string& line : lobbyLines) {
        ImGui::TextUnformatted(line.c_str());
      }
      ImGui::TextDisabled(
        "Click to change where %s %s in a game (Ctrl+Z undoes it)",
        names.size() == 1 ? "it" : "the selected units",
        names.size() == 1 ? "is" : "are"
      );
      ImGui::PopTextWrapPos();
      ImGui::EndTooltip();
    }
    if (open) {
      ImGui::SeparatorText("Whatever the lobby options");
      if (ImGui::Selectable("From the start, as a live unit (INITIAL)", current == "INITIAL")) {
        move({"INITIAL"});
      }
      if (ImGui::Selectable("From the start, as a wreck (WRECKAGE)", current == "WRECKAGE")) {
        move({"WRECKAGE"});
      }
      ImGui::SeparatorText("When a lobby option asks for it");
      if (targets.empty()) {
        ImGui::TextDisabled("The map's script creates no groups for %s.", unit.owner.c_str());
      }
      for (const SpawnTarget& target : targets) {
        const std::string& name = target.path.back();
        std::string label = (target.optionsWith.empty() ? "" : "+ ") +
          std::string(target.when == "every game" ? "In every game" : "When " + target.when) + ": " + name +
          (target.exists ? "" : " (new group)") + ", " + kind(target);
        ImGui::PushID(name.c_str());
        if (ImGui::Selectable(label.c_str(), name == current)) {
          move(target.path);
          if (!target.optionsWith.empty()) {
            mDocument.SetOptionsText(target.optionsWith);
          }
        }
        if (ImGui::IsItemHovered()) {
          ImGui::BeginTooltip();
          for (const std::string& line : DescribeLobbyRule(
                 target.rule,
                 ParseLobbyOptions(target.optionsWith.empty() ? mDocument.OptionsText() : target.optionsWith)
               )) {
            ImGui::TextUnformatted(line.c_str());
          }
          if (!target.optionsWith.empty()) {
            ImGui::TextColored(
              ImVec4(0.95f, 0.75f, 0.30f, 1.0f),
              "Picking it %s in _options.lua (its own undo step).",
              target.optionsChange.c_str()
            );
          }
          ImGui::EndTooltip();
        }
        ImGui::PopID();
      }
      ImGui::EndCombo();
    }
    if (!optionKey.empty()) {
      ImGui::SameLine();
      if (ImGui::Button("Option...")) {
        OpenAdaptiveWindow(optionKey);
      }
      ImGui::SetItemTooltip(
        "The lobby option %s in the Adaptive Map window: its choices, what each puts on the map", optionKey.c_str()
      );
    }
  }

  void EdShell::DrawUnitFate(
    const SelectionProperties& unit
  )
  {
    // The Properties panel's rows: labels right-aligned in a column as wide as "Location X".
    const float labelWidth = ImGui::CalcTextSize("Location X").x + ImGui::GetStyle().ItemSpacing.x * 2.0f;
    const auto row = [&](const char* const label) {
      ImGui::AlignTextToFramePadding();
      const float width = ImGui::CalcTextSize(label).x;
      ImGui::SetCursorPosX(ImGui::GetCursorPosX() + labelWidth - width - ImGui::GetStyle().ItemSpacing.x);
      ImGui::TextDisabled("%s", label);
      ImGui::SameLine(labelWidth + ImGui::GetStyle().WindowPadding.x);
    };
    // The army's group tree, and the groups from its root down to the unit.
    UnitGroup root;
    std::vector<std::string> path;
    for (const SaveEntry& army : mDocument.SaveData().Armies()) {
      std::string error;
      if (army.name == unit.owner && ParseUnitGroup(army.Get("Units"), root, error)) {
        path = UnitGroupPath(root, unit.name);
      }
    }
    std::string where;
    for (const std::string& group : path) {
      where += (where.empty() ? "" : " / ") + group;
    }
    row("Group");
    ImGui::TextUnformatted(where.empty() ? "(none)" : where.c_str());

    // A civilian army: not one of the lobby's player slots.
    bool civilian = true;
    for (const ScenarioTeam& team : mDocument.Teams()) {
      civilian = civilian && std::find(team.armies.begin(), team.armies.end(), unit.owner) == team.armies.end();
    }
    const UnitFate fate = FateOfUnit(path, civilian, mDocument.Script());
    // A group the script creates: which lobby option decides it, and what each of its values does (user report: Dual
    // Gap's wrecks are a lobby option the panel didn't name). Read again only when the script, options or group change.
    const bool byScript = fate.kind == UnitFate::Kind::ScriptUnit || fate.kind == UnitFate::Kind::ScriptWreck ||
      fate.kind == UnitFate::Kind::ScriptEither;
    static std::string cachedScript;
    static std::string cachedOptions;
    static std::string cachedGroup;
    static std::vector<std::string> lobbyLines;
    static bool lobbyNever = false;
    if (
      byScript &&
      (cachedGroup != fate.group || cachedScript != mDocument.Script() || cachedOptions != mDocument.OptionsText())
    ) {
      cachedGroup = fate.group;
      cachedScript = mDocument.Script();
      cachedOptions = mDocument.OptionsText();
      const std::vector<LobbyOptionInfo> options = ParseLobbyOptions(cachedOptions);
      const GroupLobbyRule rule = LobbyRuleOfGroup(cachedScript, options, fate.group);
      lobbyLines = DescribeLobbyRule(rule, options);
      lobbyNever = rule.scriptNames && rule.Never();
    }
    const bool wreck = fate.kind == UnitFate::Kind::Wreck || fate.kind == UnitFate::Kind::ScriptWreck;
    (void)lobbyNever;
    // When it appears in a game, as one line that is also the choice (user ask 2026-11-11: a shorter, editable view).
    DrawUnitSpawn(
      unit,
      root,
      fate.kind == UnitFate::Kind::Unit      ? "INITIAL"
        : fate.kind == UnitFate::Kind::Wreck ? "WRECKAGE"
                                             : fate.group,
      civilian,
      fate.text,
      byScript ? lobbyLines : std::vector<std::string>{}
    );

    // The wreck's value, as Unit.lua's CreateWreckageProp makes it (under water: its ground below the map's water).
    const bool underwater = UnderWater(mDocument, unit.position[0], unit.position[2]);
    if (const BlueprintWreck value = UnitBlueprintWreck(unit.type, underwater); value.known) {
      row(wreck ? "Wreck" : "Its wreck");
      if (!value.wreck.exists) {
        ImGui::TextDisabled("none (the blueprint has no wreckage)");
      } else {
        ImGui::Text(
          "%.0f mass, %.0f energy%s", value.wreck.mass, value.wreck.energy, underwater ? " (under water: x0.6)" : ""
        );
        ImGui::SetItemTooltip(
          "Build cost %.0f mass, %.0f energy, times the blueprint's Wreckage MassMult and EnergyMult, the mass "
          "times 0.9 / 0.8 / 0.7 / 0.6 for tech 1 / 2 / 3 / experimental, and both times 0.6 under water (FAF's "
          "Unit.lua).%s",
          value.buildMass,
          value.buildEnergy,
          wreck ? "" : " What it leaves when it dies in the game."
        );
      }
    }

    HelpNote(
      "A map's units are only data until something creates their group: the game makes each army's INITIAL group as "
      "units and its WRECKAGE group as wrecks when the game starts; any other group appears only if the map's "
      "script creates it (FAF's ScenarioUtilities.lua)."
    );
  }
} // namespace faf::editor
