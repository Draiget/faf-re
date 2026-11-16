// The Statistics panel (FAF Studio's panels_stats.lua): what the map holds, and per start what is nearest to it, so
// an unfair start shows.

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdMapStats.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "moho/sim/CWldMap.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "editor/ui/EdHelp.h"

#include <chrono>
#include <map>

namespace faf::editor
{
  void EdShell::DrawStatisticsPanel()
  {
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(460.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Statistics###Statistics"), &mShowStatistics)) {
      ImGui::End();
      return;
    }
    moho::CWldMap* const map = mDocument.Map();
    if (map == nullptr) {
      ImGui::TextDisabled("Open a map to see its statistics.");
      ImGui::End();
      return;
    }
    // Worked out again once a second (the props' reclaim needs the rules; until they are built it reads 0).
    static auto last = std::chrono::steady_clock::time_point{};
    static std::vector<StatStart> starts;
    static std::map<std::string, int> types;
    static std::vector<std::pair<std::string, int>> armies;
    static int props = 0;
    static int decals = 0;
    static double reclaimMass = 0.0;
    const auto now = std::chrono::steady_clock::now();
    if (now - last > std::chrono::seconds(1)) {
      last = now;
      starts.clear();
      types.clear();
      armies.clear();
      std::vector<StatThing> things;
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        const std::string type = MarkerTypeOf(marker);
        ++types[type];
        float x = 0.0f, y = 0.0f, z = 0.0f;
        if (!MarkerPosition(marker, x, y, z)) {
          continue;
        }
        if (type == "Blank Marker" && marker.name.starts_with("ARMY_")) {
          StatStart start;
          start.name = marker.name;
          start.x = x;
          start.z = z;
          starts.push_back(start);
        } else if (type == "Mass") {
          things.push_back(StatThing{StatThing::Kind::Mass, x, z, 0.0, 0.0});
        } else if (type == "Hydrocarbon") {
          things.push_back(StatThing{StatThing::Kind::Hydro, x, z, 0.0, 0.0});
        }
      }
      // The props' reclaim by blueprint (the document's table), placed where each prop stands.
      const EdDocument::ReclaimTotals reclaim = mDocument.PropReclaim();
      std::map<std::string, std::pair<float, float>> byBlueprint;
      for (const EdDocument::ReclaimRow& row : reclaim.rows) {
        byBlueprint[row.blueprint] = {std::max(0.0f, row.mass), std::max(0.0f, row.energy)};
      }
      props = 0;
      reclaimMass = reclaim.mass;
      if (map->mProps != nullptr) {
        for (const moho::CWldPropEntry& entry : map->mProps->mEntries) {
          ++props;
          const auto found = byBlueprint.find(entry.mBlueprintPath.c_str());
          things.push_back(
            StatThing{
              StatThing::Kind::Prop,
              entry.mTransform.pos_.x,
              entry.mTransform.pos_.z,
              found != byBlueprint.end() ? found->second.first : 0.0,
              found != byBlueprint.end() ? found->second.second : 0.0
            }
          );
        }
      }
      starts = PerStart(std::move(starts), things);
      decals = mDocument.Decals() != nullptr ? mDocument.Decals()->GetDecalCount() : 0;
      for (const SaveEntry& army : mDocument.SaveData().Armies()) {
        UnitGroup group;
        std::vector<const SaveUnit*> units;
        if (ParseUnitGroup(army.Get("Units"), group)) {
          CollectUnits(group, units);
        }
        armies.emplace_back(army.name, static_cast<int>(units.size()));
      }
    }
    if (Section("The map")) {
      ImGui::Text("%d props (%.0f mass to reclaim), %d decals", props, reclaimMass, decals);
      ImGui::Text(
        "%zu areas, %zu chains, %zu markers",
        mDocument.SaveData().Areas().size(),
        mDocument.SaveData().Chains().size(),
        mDocument.SaveData().Markers().size()
      );
      for (const auto& [type, count] : types) {
        ImGui::TextDisabled("  %s: %d", type.c_str(), count);
      }
    }
    if (Section("Per start")) {
      if (starts.empty()) {
        ImGui::TextDisabled("No start positions (ARMY_n markers).");
      } else if (ImGui::BeginTable("##perstart", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Start");
        ImGui::TableSetupColumn("Mass");
        ImGui::TableSetupColumn("Hydro");
        ImGui::TableSetupColumn("Props");
        ImGui::TableSetupColumn("Reclaim");
        ImGui::TableHeadersRow();
        for (const StatStart& start : starts) {
          ImGui::TableNextRow();
          ImGui::TableNextColumn();
          ImGui::TextUnformatted(start.name.c_str());
          ImGui::TableNextColumn();
          ImGui::Text("%d", start.mass);
          ImGui::TableNextColumn();
          ImGui::Text("%d", start.hydro);
          ImGui::TableNextColumn();
          ImGui::Text("%d", start.props);
          ImGui::TableNextColumn();
          ImGui::Text("%.0f", start.reclaimMass);
        }
        ImGui::EndTable();
      }
      const StatSpread spread = SpreadOf(starts);
      ImGui::Text(
        "Spread: %d mass, %d hydro, %.0f reclaim mass between the best and worst start",
        spread.mass,
        spread.hydro,
        spread.reclaimMass
      );
      HelpNote("Each mass point, hydrocarbon and prop counts for the start nearest to it.");
    }
    if (Section("Units per army")) {
      for (const auto& [name, count] : armies) {
        ImGui::Text("%s: %d", name.c_str(), count);
      }
    }
    ImGui::End();
  }
} // namespace faf::editor
