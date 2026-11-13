// The Units tool's unit browser (design §7 Units, like the game's build menu): EdTools' member.

#include <algorithm>
#include "editor/ui/EdControls.h"
#include <cctype>
#include <cstdio>
#include <string>

#include "editor/EdTools.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "imgui.h"

namespace faf::editor
{
  void EdTools::DrawUnitBrowser()
  {
    EdUnitFilter filter = mUnitBrowse;
    filter.text = mUnitFilter;
    // Chips as toggles filled when picked, each with what it would show.
    const auto chips = [](const char* const id, const auto& names, const std::array<int, 5>& counts, int& picked) {
      ImGui::PushID(id);
      const float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
      int total = 0;
      for (const int count : counts) {
        total += count;
      }
      const auto chip = [&](const char* const label, const int value, const int count) {
        char text[48];
        (void)std::snprintf(text, sizeof(text), "%s %d", label, count);
        const bool on = picked == value;
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(on ? ImGuiCol_Header : ImGuiCol_FrameBg));
        if (ImGui::SmallButton(text)) {
          picked = on ? -1 : value;
        }
        ImGui::PopStyleColor();
      };
      chip("All", -1, total);
      for (int i = 0; i < 5; ++i) {
        if (counts[static_cast<std::size_t>(i)] == 0 && picked != i) {
          continue; // nothing there: no chip
        }
        // As many as fit on a row, then the next.
        const float width = ImGui::CalcTextSize(names[static_cast<std::size_t>(i)]).x + Em(36.0f);
        if (ImGui::GetItemRectMax().x + width < right) {
          ImGui::SameLine(0.0f, Em(3.0f));
        }
        chip(names[static_cast<std::size_t>(i)], i, counts[static_cast<std::size_t>(i)]);
      }
      ImGui::PopID();
    };
    chips("factions", kUnitFactions, FactionCounts(mUnitInfos, filter), mUnitBrowse.faction);
    chips("kinds", kUnitKinds, KindCounts(mUnitInfos, filter), mUnitBrowse.kind);
    filter.faction = mUnitBrowse.faction;
    filter.kind = mUnitBrowse.kind;
    // Tiles or a list.
    for (int i = 0; i < 2; ++i) {
      if (i > 0) {
        ImGui::SameLine(0.0f, Em(2.0f));
      }
      const bool on = mUnitGrid == (i == 0);
      ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(on ? ImGuiCol_Header : ImGuiCol_FrameBg));
      if (ImGui::SmallButton(i == 0 ? "Tiles" : "List")) {
        mUnitGrid = i == 0;
      }
      ImGui::PopStyleColor();
    }
    const std::vector<std::size_t> shown = FilterUnits(mUnitInfos, filter);
    ImGui::SameLine();
    ImGui::TextDisabled("%zu units", shown.size());

    // The list fills what the panel has left (at least eight rows).
    const float height = FillHeight(ImGui::GetFrameHeightWithSpacing() * 6.0f, ImGui::GetFrameHeight() * 1.6f * 8.0f);
    if (!ImGui::BeginChild("##unitbrowser", ImVec2(0.0f, height), ImGuiChildFlags_Borders)) {
      ImGui::EndChild();
      return;
    }
    mLibrary.Pump(6);
    const auto iconOf = [this](const std::string& id) {
      std::string lower = id;
      for (char& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return mLibrary.Thumbnail("/textures/ui/common/icons/units/" + lower + "_icon.dds", true);
    };
    const auto pick = [this](const std::string& id) {
      mUnitType = id;
      mUnitMode = 0;
    };
    int tech = -1;
    if (mUnitGrid) {
      // Tiles by tech, as the build menu rows them: a heading per tech, the icons in a wrapping grid.
      const float tile = Em(52.0f);
      const float gap = Em(4.0f);
      const int columns = std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().x + gap) / (tile + gap)));
      int column = 0;
      for (const std::size_t index : shown) {
        const EdUnitInfo& unit = mUnitInfos[index];
        if (unit.tech != tech) {
          tech = unit.tech;
          ImGui::PushStyleColor(ImGuiCol_Text, AccentColor());
          ImGui::TextUnformatted(kUnitTechs[static_cast<std::size_t>(std::clamp(tech, 0, 4))]);
          ImGui::PopStyleColor();
          column = 0;
        }
        if (column > 0) {
          ImGui::SameLine(0.0f, gap);
        }
        ImGui::PushID(unit.id.c_str());
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton("##tile", ImVec2(tile, tile))) {
          pick(unit.id);
        }
        const bool hovered = ImGui::IsItemHovered();
        if (ImGui::IsItemVisible()) {
          ImDrawList* const dl = ImGui::GetWindowDrawList();
          const ImVec2 to(at.x + tile, at.y + tile);
          const bool selected = unit.id == mUnitType;
          // Selection by fill (design: everywhere), the icon over it.
          dl->AddRectFilled(at, to, selected ? AccentU32(0.45f) : hovered ? SurfaceHotU32() : SurfaceU32(), Em(4.0f));
          if (const std::uint64_t image = iconOf(unit.id); image != 0U) {
            dl->AddImage(
              static_cast<ImTextureID>(image),
              ImVec2(at.x + Em(3.0f), at.y + Em(3.0f)),
              ImVec2(to.x - Em(3.0f), to.y - Em(3.0f))
            );
          } else {
            dl->AddText(ImVec2(at.x + Em(4.0f), at.y + Em(4.0f)), InkDimU32(), unit.id.c_str());
          }
        }
        if (hovered) {
          EdSetTooltip(
            "%s  %s\n%s, %s, %s",
            unit.id.c_str(),
            unit.name.c_str(),
            kUnitFactions[static_cast<std::size_t>(std::clamp(unit.faction, 0, 4))],
            kUnitKinds[static_cast<std::size_t>(std::clamp(unit.kind, 0, 4))],
            kUnitTechs[static_cast<std::size_t>(std::clamp(unit.tech, 0, 4))]
          );
        }
        ImGui::PopID();
        column = (column + 1) % columns;
      }
    } else {
      // A row each: icon, id, name; the tech as a heading too.
      const float icon = ImGui::GetFrameHeight() * 1.5f;
      for (const std::size_t index : shown) {
        const EdUnitInfo& unit = mUnitInfos[index];
        if (unit.tech != tech) {
          tech = unit.tech;
          ImGui::PushStyleColor(ImGuiCol_Text, AccentColor());
          ImGui::TextUnformatted(kUnitTechs[static_cast<std::size_t>(std::clamp(tech, 0, 4))]);
          ImGui::PopStyleColor();
        }
        ImGui::PushID(unit.id.c_str());
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (ImGui::Selectable("##unit", unit.id == mUnitType, 0, ImVec2(0.0f, icon))) {
          pick(unit.id);
        }
        if (ImGui::IsItemVisible()) {
          ImDrawList* const draw = ImGui::GetWindowDrawList();
          if (const std::uint64_t image = iconOf(unit.id); image != 0U) {
            draw->AddImage(static_cast<ImTextureID>(image), at, ImVec2(at.x + icon, at.y + icon));
          } else {
            draw->AddRect(at, ImVec2(at.x + icon, at.y + icon), LineU32());
          }
          const float textY = at.y + (icon - ImGui::GetTextLineHeight()) * 0.5f;
          draw->AddText(ImVec2(at.x + icon + 6.0f, textY), InkU32(), unit.id.c_str());
          draw->AddText(
            ImVec2(at.x + icon + 6.0f + ImGui::GetFontSize() * 4.5f, textY), InkDimU32(), unit.name.c_str()
          );
        }
        ImGui::PopID();
      }
    }
    if (shown.empty()) {
      ImGui::TextDisabled("No unit matches.");
    }
    ImGui::EndChild();
  }
} // namespace faf::editor
