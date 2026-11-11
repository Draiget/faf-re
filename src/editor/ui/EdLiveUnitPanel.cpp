// The Properties panel for the game's own units, selected in the editor's view in front of a play (user ask 2026-11-11:
// select, move and change any of the game's units while it plays): what it is, its health and veterancy, its toggles
// (shield, cloak, stealth, jamming, production...), its enhancements by slot, and kill / destroy. Read through the
// game's UI Lua, changed through the sim's own Lua (view/EdLiveUnits).

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "editor/EdShell.h"
#include "editor/ui/EdHelp.h"
#include "editor/view/EdLiveUnits.h"
#include "imgui.h"

namespace faf::editor
{
  void EdShell::DrawLiveUnitPanel()
  {
    const std::vector<std::uint32_t>& ids = mTools.LiveSelection();
    if (ids.empty()) {
      return;
    }
    // The first one's state, read again a few times a second (and at once after a change).
    static std::uint32_t readFor = 0;
    static double readAt = -1.0;
    static LiveUnitInfo info;
    const double now = ImGui::GetTime();
    if (readFor != ids.front() || now - readAt > 0.3) {
      readFor = ids.front();
      readAt = now;
      info = ReadLiveUnit(readFor);
    }
    const auto changed = [&] {
      readAt = -1.0;
    };
    const auto each = [&](const std::string& lua) {
      for (const std::uint32_t id : ids) {
        LiveUnitDo(id, lua);
      }
      changed();
    };

    // What it is: the build icon, its name, the game's id, army and blueprint.
    {
      std::string icon = info.blueprint;
      std::transform(icon.begin(), icon.end(), icon.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      mTools.Library().Pump(2);
      const float side = ImGui::GetFrameHeight() * 2.6f;
      if (
        const std::uint64_t image =
          icon.empty() ? 0 : mTools.Library().Thumbnail("/textures/ui/common/icons/units/" + icon + "_icon.dds", true);
        image != 0
      ) {
        ImGui::Image(static_cast<ImTextureID>(image), ImVec2(side, side));
      } else {
        ImGui::Dummy(ImVec2(side, side));
      }
      ImGui::SameLine();
      ImGui::BeginGroup();
      ImGui::TextUnformatted(info.found ? (info.name.empty() ? info.blueprint.c_str() : info.name.c_str()) : "(gone)");
      ImGui::TextDisabled("%s  |  army %d  |  game unit %u", info.blueprint.c_str(), info.army, ids.front());
      if (ids.size() > 1) {
        ImGui::TextColored(
          ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "%zu of the game's units selected: changes go to all", ids.size()
        );
      }
      ImGui::EndGroup();
    }
    ImGui::SmallButton("Game unit##livetag");
    ImGui::SameLine();
    ImGui::TextDisabled("live in the running play");
    if (!info.found) {
      ImGui::TextDisabled("It is no longer in the game.");
      return;
    }

    const float labelWidth = ImGui::CalcTextSize("Veterancy").x + ImGui::GetStyle().ItemSpacing.x * 2.0f;
    const auto row = [&](const char* const label) {
      ImGui::AlignTextToFramePadding();
      ImGui::TextDisabled("%s", label);
      ImGui::SameLine(labelWidth + ImGui::GetStyle().WindowPadding.x);
    };

    if (ImGui::CollapsingHeader("State##live", ImGuiTreeNodeFlags_DefaultOpen)) {
      // Health: dragged, set when let go.
      static float health = 0.0f;
      static bool editingHealth = false;
      if (!editingHealth) {
        health = info.health;
      }
      row("Health");
      ImGui::SetNextItemWidth(
        -ImGui::CalcTextSize("Full").x - ImGui::GetStyle().FramePadding.x * 2.0f - ImGui::GetStyle().ItemSpacing.x
      );
      ImGui::SliderFloat("##health", &health, 1.0f, std::max(info.maxHealth, 1.0f), "%.0f");
      editingHealth = ImGui::IsItemActive();
      if (ImGui::IsItemDeactivatedAfterEdit()) {
        char lua[96];
        (void)std::snprintf(lua, sizeof(lua), "u:SetHealth(u, %g)", static_cast<double>(health));
        each(lua);
      }
      ImGui::SameLine();
      if (ImGui::Button("Full")) {
        each("u:SetHealth(u, u:GetMaxHealth())");
      }
      ImGui::SetItemTooltip("Health to its most (%.0f)", static_cast<double>(info.maxHealth));
      // Veterancy: FAF's veterancy component (SetVeterancy), levels 0 to 5.
      row("Veterancy");
      int vet = info.veteran;
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::SliderInt("##vet", &vet, 0, 5, vet == 0 ? "none" : "level %d")) {
        char lua[96];
        (void)std::snprintf(lua, sizeof(lua), "if u.SetVeterancy then u:SetVeterancy(%d) end", vet);
        each(lua);
      }
    }

    // Toggles the blueprint has: the game's own switches (as the order panel's).
    if (!info.toggles.empty() && ImGui::CollapsingHeader("Toggles##live", ImGuiTreeNodeFlags_DefaultOpen)) {
      for (const LiveUnitInfo::Toggle& toggle : info.toggles) {
        // The game's script bit: set means off for the shield, intel, jamming, production, stealth and cloak switches
        // (setting the shield's bit disables it), so those show "on" while the bit is clear; the weapon, generic and
        // special ones show the bit itself.
        const std::string name = ToggleName(toggle.cap);
        const bool inverted = name == "Shield" || name == "Intel" || name == "Jamming" || name == "Production" ||
          name == "Stealth" || name == "Cloak";
        bool on = inverted ? !toggle.on : toggle.on;
        if (ImGui::Checkbox(((inverted ? name + " on" : name) + "##" + toggle.cap).c_str(), &on)) {
          const bool bit = inverted ? !on : on;
          each("u:SetScriptBit('" + toggle.cap + "', " + (bit ? "true" : "false") + ")");
        }
        ImGui::SetItemTooltip(
          "%s: the unit's script bit %s, as the game's order button sets it",
          toggle.cap.c_str(),
          toggle.on ? "set" : "clear"
        );
      }
    }

    // Enhancements by slot: has it, add, remove (through its <name>Remove where the blueprint has one).
    if (!info.enhancements.empty() && ImGui::CollapsingHeader("Enhancements##live", ImGuiTreeNodeFlags_DefaultOpen)) {
      std::map<std::string, std::vector<const LiveUnitInfo::Enhancement*>> slots;
      for (const LiveUnitInfo::Enhancement& e : info.enhancements) {
        slots[e.slot.empty() ? std::string("(no slot)") : e.slot].push_back(&e);
      }
      for (const auto& [slot, list] : slots) {
        ImGui::SeparatorText(slot.c_str());
        for (const LiveUnitInfo::Enhancement* const e : list) {
          ImGui::PushID(e->name.c_str());
          bool has = e->has;
          ImGui::BeginDisabled(e->has && !e->removable);
          if (ImGui::Checkbox(e->name.c_str(), &has)) {
            each(has ? "u:CreateEnhancement('" + e->name + "')" : "u:CreateEnhancement('" + e->name + "Remove')");
          }
          ImGui::EndDisabled();
          if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip(
              "%s%s%s",
              e->has ? (e->removable ? "Click to take it off (its Remove enhancement)"
                                     : "The blueprint has no way to take it off")
                     : "Click to add it at once (CreateEnhancement, no build time)",
              e->prerequisite.empty() ? "" : "\nNeeds first: ",
              e->prerequisite.c_str()
            );
          }
          ImGui::PopID();
        }
      }
    }

    if (ImGui::CollapsingHeader("Actions##live", ImGuiTreeNodeFlags_DefaultOpen)) {
      if (ImGui::Button("Kill")) {
        each("u:Kill()");
      }
      ImGui::SetItemTooltip("Dies as in the game (its wreck and death effects)");
      ImGui::SameLine();
      if (ImGui::Button("Remove")) {
        each("u:Destroy()");
      }
      ImGui::SetItemTooltip("Taken out of the game at once, no wreck");
    }
    HelpNote(
      "The game's own unit, live in the running play: a drag in the view moves it (Warp), and each change here is "
      "the game's own call in its sim (SimLua; the editor's plays have cheats on). Nothing here changes the map's "
      "files."
    );
  }
} // namespace faf::editor
