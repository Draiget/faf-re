// The Properties panel's unit: which group holds it, what becomes of it in a game (a unit, a wreck, only when the
// map's script creates its group, or never), its wreck's value, and the switch that makes it a wreck from the start.

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnitFate.h"
#include "editor/doc/EdUnitWrecks.h"
#include "editor/doc/EdUnits.h"
#include "editor/ui/EdHelp.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  void EdShell::DrawUnitFate(const SelectionProperties& unit)
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
    row("In a game");
    ImGui::PushTextWrapPos(0.0f);
    const bool wreck = fate.kind == UnitFate::Kind::Wreck || fate.kind == UnitFate::Kind::ScriptWreck;
    ImGui::TextColored(fate.kind == UnitFate::Kind::Never ? ImVec4(0.95f, 0.75f, 0.30f, 1.0f) : ImGui::GetStyleColorVec4(ImGuiCol_Text), "%s",
                       fate.text.c_str());
    ImGui::PopTextWrapPos();

    // The wreck's value, as Unit.lua's CreateWreckageProp makes it (under water: its ground below the map's water).
    const bool underwater = UnderWater(mDocument, unit.position[0], unit.position[2]);
    if (const BlueprintWreck value = UnitBlueprintWreck(unit.type, underwater); value.known) {
      row(wreck ? "Wreck" : "Its wreck");
      if (!value.wreck.exists) {
        ImGui::TextDisabled("none (the blueprint has no wreckage)");
      } else {
        ImGui::Text("%.0f mass, %.0f energy%s", value.wreck.mass, value.wreck.energy, underwater ? " (under water: x0.6)" : "");
        ImGui::SetItemTooltip("Build cost %.0f mass, %.0f energy, times the blueprint's Wreckage MassMult and EnergyMult, the mass "
                              "times 0.9 / 0.8 / 0.7 / 0.6 for tech 1 / 2 / 3 / experimental, and both times 0.6 under water (FAF's "
                              "Unit.lua).%s",
                              value.buildMass, value.buildEnergy, wreck ? "" : " What it leaves when it dies in the game.");
      }
    }

    // "Wreck": whether it becomes one in a game, as the file has it (user: a checkbox with the real state). The editor
    // changes it only between the start groups, WRECKAGE and INITIAL; for a group the map's script creates, the script's
    // CreateArmyGroup(..., true) decides, so the box shows it and the button moves the unit to the start groups instead.
    // Ctrl+Z undoes a move.
    const auto ask = [&](const bool toWreck) {
      EdTools::UnitWreckAsk change;
      change.army = unit.owner;
      change.names = {unit.name};
      change.wreck = toWreck;
      mTools.AskUnitWreck(std::move(change));
    };
    const bool startGroup = fate.kind == UnitFate::Kind::Unit || fate.kind == UnitFate::Kind::Wreck;
    bool isWreck = wreck;
    ImGui::BeginDisabled(!startGroup);
    // Either way, as a lobby option picks: the box shows a mixed state.
    ImGui::PushItemFlag(ImGuiItemFlags_MixedValue, fate.kind == UnitFate::Kind::ScriptEither);
    if (ImGui::Checkbox("Wreck", &isWreck) && startGroup) {
      ask(isWreck);
    }
    ImGui::PopItemFlag();
    ImGui::EndDisabled();
    if (startGroup) {
      ImGui::SetItemTooltip(isWreck ? "A wreck from the start: in %s's WRECKAGE group. Off: moves it to INITIAL, a live unit from the start."
                                    : "A live unit from the start: in %s's INITIAL group. On: moves it to WRECKAGE, a wreck from the start.",
                            unit.owner.c_str());
    } else if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip(fate.kind == UnitFate::Kind::Never          ? "Never in a game: nothing creates %s."
                        : fate.kind == UnitFate::Kind::ScriptEither ? "The map's script creates %s as wrecks or as live units, as a lobby "
                                                                      "option picks: the script decides, not the group."
                        : wreck ? "The map's script creates %s as wrecks (CreateArmyGroup(..., true)): the script decides, not the group."
                                : "The map's script creates %s as live units: the script decides, not the group.",
                        fate.group.empty() ? "its group" : fate.group.c_str());
    }
    if (!startGroup) {
      ImGui::SameLine();
      if (ImGui::Button("Move to the start groups")) {
        ask(wreck); // the same kind it is now, from the start whatever the lobby options
      }
      ImGui::SetItemTooltip("Moves it from %s to %s's %s group: %s from the start, whatever the lobby options. Ctrl+Z undoes it.",
                            fate.group.empty() ? "(no group)" : fate.group.c_str(), unit.owner.c_str(), wreck ? "WRECKAGE" : "INITIAL",
                            wreck ? "a wreck" : "a unit");
    }
    HelpNote("A map's units are only data until something creates their group: the game makes each army's INITIAL group as "
             "units and its WRECKAGE group as wrecks when the game starts; any other group appears only if the map's "
             "script creates it (FAF's ScenarioUtilities.lua).");
  }
} // namespace faf::editor
