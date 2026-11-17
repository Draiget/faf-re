// The Detail pass panel (FAF Studio's panels_scatter.lua, detail part): the environment, the density, the seed, the
// classes to run, Plan, Run (one undo step) and Measure this map.

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"

#include <algorithm>
#include <ranges>

namespace faf::editor
{
  void EdShell::DrawDetailPanel()
  {
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(460.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Detail pass###DetailPass"), &mShowDetail)) {
      ImGui::End();
      return;
    }
    if (mDocument.Map() == nullptr) {
      ImGui::TextDisabled("Open a map to add its small rocks and decals.");
      ImGui::End();
      return;
    }
    HelpNote(
      "The small things on top of a painted map, in classes by size and slope as on Operation Citadel: small rocks in "
      "clusters on gentle ground, stones along the water, big rocks on steep ground, crevice, rock ground and cliff "
      "decals. Each class uses the props and decals of the environment that the game has. One undo step."
    );
    const std::vector<DetailEnvironment>& envs = DetailEnvironments();
    int current = 0;
    for (std::size_t i = 0; i < envs.size(); ++i) {
      if (mDetailRun.environment == envs[i].id) {
        current = static_cast<int>(i);
      }
    }
    auto labels = envs | std::views::transform([&](const DetailEnvironment& e) {
      return e.label;
    }) |
      std::ranges::to<std::vector<const char*>>();
    RowLabel("Environment");
    ImGui::SetNextItemWidth(-1.0f);
    if (EdCombo("##env", &current, labels.data(), static_cast<int>(labels.size()))) {
      mDetailRun.environment = envs[static_cast<std::size_t>(current)].id;
      mDetailEnvironmentSet = true;
    }
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderFloat("##density", &mDetailRun.density, 0.05f, 4.0f, "Density %.2f (1 = Citadel's)");
    ImGui::SetNextItemWidth(-1.0f);
    FillSliderInt("##seed", &mDetailRun.seed, 1, 9999, "Seed %d");
    ImGui::Checkbox("Under the water too", &mDetailRun.underWater);
    static const char* const kClasses[6][2] = {
      {"small", "Small rocks"},
      {"stones", "Stones along the water"},
      {"big", "Big rocks"},
      {"crack", "Crevice decals"},
      {"ground", "Rock ground decals"},
      {"cliff", "Cliff decals"},
    };
    for (int i = 0; i < 6; ++i) {
      const std::string id = kClasses[i][0];
      bool on = std::find(mDetailClassesOff.begin(), mDetailClassesOff.end(), id) == mDetailClassesOff.end();
      if (ImGui::Checkbox(kClasses[i][1], &on)) {
        if (on) {
          mDetailClassesOff.erase(
            std::remove(mDetailClassesOff.begin(), mDetailClassesOff.end(), id), mDetailClassesOff.end()
          );
        } else {
          mDetailClassesOff.push_back(id);
        }
      }
      if (i % 2 == 0) {
        ImGui::SameLine(Em(190.0f));
      }
    }
    if (ImGui::Button("Plan")) {
      mDetailAsk = 1;
    }
    EdSetItemTooltip("How many of each class the run would place (nothing changes)");
    ImGui::SameLine();
    if (PrimaryButton("Run")) {
      mDetailAsk = 2;
    }
    ImGui::SameLine();
    if (ImGui::Button("Measure this map")) {
      mDetailAsk = 3;
    }
    EdSetItemTooltip("The classes counted on the open map with the slope under them: a reference to tune the density");
    if (!mDetailText.empty()) {
      ImGui::Separator();
      ImGui::TextWrapped("%s", mDetailText.c_str());
    }
    ImGui::End();
  }
} // namespace faf::editor
