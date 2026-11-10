// The Properties panel's unit: which group holds it, what becomes of it in a game (a unit, a wreck, only when the
// map's script creates its group, or never), its wreck's value, and the switch that makes it a wreck from the start.

#include <algorithm>
#include <cmath>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "editor/doc/EdUnitFate.h"
#include "editor/doc/EdUnits.h"
#include "editor/ui/EdHelp.h"
#include "imgui.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"

namespace faf::editor
{
  namespace
  {
    /** A unit blueprint's costs and its `.bp` text, read once per blueprint id. */
    struct BlueprintFacts
    {
      bool found = false;
      double mass = 0.0;
      double energy = 0.0;
      std::string text;
    };

    const BlueprintFacts& FactsOf(const std::string& id)
    {
      static std::map<std::string, BlueprintFacts> cache;
      if (const auto found = cache.find(id); found != cache.end()) {
        return found->second;
      }
      BlueprintFacts facts;
      if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
        moho::RResId resId{};
        resId.name.assign(id.c_str());
        if (const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(resId); blueprint != nullptr) {
          facts.mass = blueprint->Economy.BuildCostMass;
          facts.energy = blueprint->Economy.BuildCostEnergy;
          facts.found = ReadGameFile(blueprint->mSource.c_str(), facts.text);
        }
      }
      // An empty entry until the rules are built: asked again next time.
      if (!facts.found) {
        static BlueprintFacts none;
        none = facts;
        return none;
      }
      return cache.emplace(id, std::move(facts)).first->second;
    }
  } // namespace

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
    const BlueprintFacts& facts = FactsOf(unit.type);
    if (facts.found) {
      bool underwater = false;
      if (const moho::CWldMap* const map = mDocument.Map(); map != nullptr && map->mTerrainRes != nullptr && mDocument.Facts().water) {
        const float ground = map->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(unit.position[0]), static_cast<std::int32_t>(unit.position[2]));
        underwater = ground < mDocument.Facts().waterElevation;
      }
      const WreckValue value = WreckOfUnit(facts.text, facts.mass, facts.energy, underwater);
      row(wreck ? "Wreck" : "Its wreck");
      if (!value.exists) {
        ImGui::TextDisabled("none (the blueprint has no wreckage)");
      } else {
        ImGui::Text("%.0f mass, %.0f energy%s", value.mass, value.energy, underwater ? " (under water: x0.6)" : "");
        ImGui::SetItemTooltip("Build cost %.0f mass, %.0f energy, times the blueprint's Wreckage MassMult and EnergyMult, the mass "
                              "times 0.9 / 0.8 / 0.7 / 0.6 for tech 1 / 2 / 3 / experimental, and both times 0.6 under water (FAF's "
                              "Unit.lua).%s",
                              facts.mass, facts.energy, wreck ? "" : " What it leaves when it dies in the game.");
      }
    }

    // A move to the army's WRECKAGE group (a wreck from the start) or INITIAL group (a unit from the start). Two buttons,
    // not a switch: turning a switch off has no group to go back to (a unit of a script's group would land in INITIAL,
    // a live unit; user report). Ctrl+Z puts it back where it was.
    const auto ask = [&](const bool toWreck) {
      EdTools::UnitWreckAsk change;
      change.army = unit.owner;
      change.names = {unit.name};
      change.wreck = toWreck;
      mTools.AskUnitWreck(std::move(change));
    };
    if (fate.kind != UnitFate::Kind::Wreck) {
      if (ImGui::Button("Make it a wreck from the start")) {
        ask(true);
      }
      ImGui::SetItemTooltip("Moves it to %s's WRECKAGE group, which the game turns into wrecks as it starts, whatever the lobby "
                            "options. It leaves its group %s. Ctrl+Z undoes it.",
                            unit.owner.c_str(), fate.group.empty() ? "(none)" : fate.group.c_str());
    }
    if (fate.kind != UnitFate::Kind::Unit) {
      if (fate.kind != UnitFate::Kind::Wreck) {
        ImGui::SameLine();
      }
      if (ImGui::Button("Make it a unit from the start")) {
        ask(false);
      }
      ImGui::SetItemTooltip("Moves it to %s's INITIAL group: a live unit of that army when the game starts. It leaves its group "
                            "%s. Ctrl+Z undoes it.",
                            unit.owner.c_str(), fate.group.empty() ? "(none)" : fate.group.c_str());
    }
    HelpNote("A map's units are only data until something creates their group: the game makes each army's INITIAL group as "
             "units and its WRECKAGE group as wrecks when the game starts; any other group appears only if the map's "
             "script creates it (FAF's ScenarioUtilities.lua).");
  }
} // namespace faf::editor
