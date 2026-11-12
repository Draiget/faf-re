// The Armies panel (View > Armies): the lobby's player slots and the extra armies as cards, and the chosen army's
// settings.

#include <algorithm>
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdWorkspaces.h"
#include <cstdio>
#include <string>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdArmySlots.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdHelp.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kMapWindow = "Map";
    constexpr const char* kArmiesWindow = "Armies";
    // The factions as the save numbers them, with their usual colours (the UI's accents only).
    const char* const kFactions[4] = {"UEF", "Aeon", "Cybran", "Seraphim"};
    const ImVec4 kFactionColours[4] = {
      ImVec4(0.25f, 0.45f, 0.90f, 1.0f),
      ImVec4(0.30f, 0.70f, 0.35f, 1.0f),
      ImVec4(0.85f, 0.25f, 0.25f, 1.0f),
      ImVec4(0.90f, 0.75f, 0.25f, 1.0f),
    };

    struct ArmyCard
    {
      std::string name;
      ArmySettings settings;
      int units = 0;
      std::string groups;
      bool start = false;
      float x = 0.0f;
      float z = 0.0f;
    };

    ArmyCard CardOf(
      EdDocument& document,
      const std::string& name
    )
    {
      ArmyCard card;
      card.name = name;
      for (const SaveEntry& entry : document.SaveData().Armies()) {
        if (entry.name != name) {
          continue;
        }
        card.settings = ReadArmySettings(entry);
        UnitGroup root;
        std::string error;
        if (ParseUnitGroup(entry.Get("Units"), root, error)) {
          card.units = static_cast<int>(UnitNamesIn(root).size());
          for (const UnitGroup& group : root.groups) {
            char text[96];
            (void)std::snprintf(
              text,
              sizeof(text),
              "%s%s %zu",
              card.groups.empty() ? "" : "  ",
              group.name.c_str(),
              UnitNamesIn(group).size()
            );
            card.groups += text;
          }
        }
      }
      for (const SaveEntry& marker : document.SaveData().Markers()) {
        float y = 0.0f;
        if (
          marker.name == name && MarkerTypeOf(marker) == "Blank Marker" && MarkerPosition(marker, card.x, y, card.z)
        ) {
          card.start = true;
        }
      }
      return card;
    }
  } // namespace

  void EdShell::DrawArmiesPanel()
  {
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(Panel(kMapWindow)); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    if (std::exchange(mFocusArmies, false)) {
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin(Panel(kArmiesWindow), &mShowArmies)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("No map open.");
      ImGui::End();
      return;
    }
    const std::vector<ScenarioTeam> teams = mDocument.Teams();
    const std::vector<std::string> players = mDocument.Armies();
    const std::vector<std::string> extra = mDocument.ExtraArmies();
    if (
      mArmySelected.empty() ||
      (std::find(players.begin(), players.end(), mArmySelected) == players.end() &&
       std::find(extra.begin(), extra.end(), mArmySelected) == extra.end())
    ) {
      mArmySelected = !players.empty() ? players.front() : !extra.empty() ? extra.front() : std::string();
    }

    // One card: the slot number or a tag, the name, where it starts; its units, faction and resources under it.
    const float line = ImGui::GetTextLineHeight();
    // Draws the card; its buttons go at the cursor it leaves, the caller then calls EndCard.
    const auto card = [&](
                        const ArmyCard& army,
                        const char* const badge,
                        const bool civilian,
                        const int buttonCount,
                        const std::string& mirror = std::string()
                      ) {
      ImGui::PushID(army.name.c_str());
      const float pad = ImGui::GetStyle().FramePadding.x;
      const bool chosen = army.name == mArmySelected;
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const float width = ImGui::GetContentRegionAvail().x;
      const float height = line * 2.0f + ImGui::GetStyle().FramePadding.y * 3.0f;
      const float buttons =
        buttonCount * ImGui::GetFrameHeight() + (buttonCount - 1) * ImGui::GetStyle().ItemSpacing.x + pad;
      if (ImGui::InvisibleButton("##card", ImVec2(width - buttons - pad, height))) {
        mArmySelected = army.name;
      }
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      const ImU32 background = ImGui::GetColorU32(ImGui::IsItemHovered() ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg);
      draw->AddRectFilled(at, ImVec2(at.x + width, at.y + height), background, 5.0f);
      if (chosen) {
        draw->AddRect(at, ImVec2(at.x + width, at.y + height), AccentU32(), 5.0f, 0, 1.5f);
      }
      // The badge: the slot number, or a tag for an extra army.
      const ImVec2 badgeAt(at.x + pad, at.y + ImGui::GetStyle().FramePadding.y);
      const ImVec2 badgeSize = ImGui::CalcTextSize(badge);
      const ImU32 badgeColour = civilian ? IM_COL32(110, 110, 120, 255)
                                         : ImGui::GetColorU32(kFactionColours[std::clamp(army.settings.faction, 0, 3)]);
      draw->AddRectFilled(
        badgeAt, ImVec2(badgeAt.x + badgeSize.x + pad * 2.0f, badgeAt.y + line + 2.0f), badgeColour, 3.0f
      );
      draw->AddText(ImVec2(badgeAt.x + pad, badgeAt.y + 1.0f), IM_COL32(255, 255, 255, 255), badge);
      const float textX = badgeAt.x + badgeSize.x + pad * 3.0f;
      draw->AddText(ImVec2(textX, badgeAt.y), ImGui::GetColorU32(ImGuiCol_Text), army.name.c_str());
      char where[64];
      if (army.start) {
        (void)std::snprintf(
          where, sizeof(where), "start %.0f, %.0f", static_cast<double>(army.x), static_cast<double>(army.z)
        );
      } else {
        (void)std::snprintf(where, sizeof(where), "%s", civilian ? "" : "no start position");
      }
      const float whereWidth = ImGui::CalcTextSize(where).x;
      draw->AddText(
        ImVec2(at.x + width - buttons - pad - whereWidth, badgeAt.y),
        army.start || civilian ? ImGui::GetColorU32(ImGuiCol_TextDisabled) : AccentU32(),
        where
      );
      // Its mirror's slot beside its name, in the accent colour.
      if (!mirror.empty()) {
        const std::string tag = "<> " + mirror;
        draw->AddText(
          ImVec2(textX + ImGui::CalcTextSize(army.name.c_str()).x + pad * 2.0f, badgeAt.y), AccentU32(), tag.c_str()
        );
      }
      char detail[160];
      (void)std::snprintf(
        detail,
        sizeof(detail),
        "%d units  |  %s  |  mass %.0f, energy %.0f",
        army.units,
        kFactions[std::clamp(army.settings.faction, 0, 3)],
        army.settings.mass,
        army.settings.energy
      );
      draw->AddText(
        ImVec2(textX, badgeAt.y + line + ImGui::GetStyle().FramePadding.y),
        ImGui::GetColorU32(ImGuiCol_TextDisabled),
        detail
      );
      ImGui::PopID();
      ImGui::SetCursorScreenPos(ImVec2(at.x + width - buttons, at.y + (height - ImGui::GetFrameHeight()) * 0.5f));
      return ImVec2(at.x, at.y + height + ImGui::GetStyle().ItemSpacing.y);
    };
    const auto endCard = [](const ImVec2 next) {
      ImGui::SetCursorScreenPos(next);
      ImGui::Dummy(ImVec2(0.0f, 0.0f));
    };

    // The lobby's slots: the first team's armies in order, moved up and down.
    ImGui::SeparatorText("Player slots");
    const bool oneFfa = teams.size() == 1 && teams.front().name == "FFA";
    if (!oneFfa && !teams.empty()) {
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.75f, 0.30f, 1.0f));
      ImGui::TextWrapped(
        "The lobby takes its slots from one team named FFA; this scenario has %zu team%s.",
        teams.size(),
        teams.size() == 1 ? "" : "s"
      );
      ImGui::PopStyleColor();
      if (ImGui::Button("Make one FFA team")) {
        ScenarioTeam all{"FFA", {}};
        for (const ScenarioTeam& team : teams) {
          all.armies.insert(all.armies.end(), team.armies.begin(), team.armies.end());
        }
        mTools.AskTeamsChange({all});
      }
    }
    const std::vector<std::string> slots = teams.empty() ? std::vector<std::string>() : teams.front().armies;
    // Each slot's mirror under the map's symmetry (the Tools panel's), and the order that pairs them.
    std::vector<ArmyCard> cards;
    std::vector<std::optional<std::array<float, 2>>> starts;
    for (const std::string& slot : slots) {
      cards.push_back(CardOf(mDocument, slot));
      starts.push_back(
        cards.back().start ? std::optional<std::array<float, 2>>(std::array<float, 2>{cards.back().x, cards.back().z})
                           : std::nullopt
      );
    }
    const HeightBrush brush = mTools.CurrentHeightBrush();
    const std::vector<int> partners = mTools.MapWidth() > 0
      ? MirrorPartners(starts, mTools.MapWidth() + 1, mTools.MapHeight() + 1, brush.symmetry, brush.turns)
      : std::vector<int>(slots.size(), -1);
    const std::vector<int> paired = PairMirroredSlots(partners);
    bool alreadyPaired = true;
    for (std::size_t i = 0; i < paired.size(); ++i) {
      alreadyPaired = alreadyPaired && paired[i] == static_cast<int>(i);
    }
    bool anyPair = false;
    for (const int partner : partners) {
      anyPair = anyPair || partner >= 0;
    }
    if (anyPair) {
      ImGui::BeginDisabled(alreadyPaired);
      if (ImGui::Button(alreadyPaired ? "Mirrored starts are paired" : "Pair mirrored starts", ImVec2(-1.0f, 0.0f))) {
        std::vector<ScenarioTeam> change = teams;
        change.front().armies.clear();
        for (const int index : paired) {
          change.front().armies.push_back(slots[static_cast<std::size_t>(index)]);
        }
        mTools.AskTeamsChange(change);
      }
      ImGui::EndDisabled();
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip(
          "Orders the slots so each start is followed by its mirror under the map's symmetry (the Tools\n"
          "panel's): slots 1 and 2, 3 and 4... face each other, so the lobby's \"odd vs even\" auto teams\n"
          "are fair. Players then pick slots knowing which start faces which."
        );
      }
    }
    for (std::size_t i = 0; i < slots.size(); ++i) {
      ImGui::PushID(static_cast<int>(i));
      const int partner = partners[i];
      const std::string mirror = partner >= 0 ? std::to_string(partner + 1) : std::string();
      const ImVec2 next = card(cards[i], std::to_string(i + 1).c_str(), false, 2, mirror);
      ImGui::BeginDisabled(i == 0);
      if (ImGui::ArrowButton("##up", ImGuiDir_Up)) {
        std::vector<ScenarioTeam> change = teams;
        std::swap(change.front().armies[i], change.front().armies[i - 1]);
        mTools.AskTeamsChange(change);
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(i + 1 == slots.size());
      if (ImGui::ArrowButton("##down", ImGuiDir_Down)) {
        std::vector<ScenarioTeam> change = teams;
        std::swap(change.front().armies[i], change.front().armies[i + 1]);
        mTools.AskTeamsChange(change);
      }
      ImGui::EndDisabled();
      endCard(next);
      ImGui::PopID();
    }
    if (slots.empty()) {
      ImGui::TextDisabled("No player slots: place start positions with the Markers tool.");
    }

    // The extra armies: neutral and civilian units' owners, not lobby slots.
    ImGui::SeparatorText("Extra armies");
    for (std::size_t i = 0; i < extra.size(); ++i) {
      ImGui::PushID(static_cast<int>(i) + 1000);
      const ImVec2 next = card(CardOf(mDocument, extra[i]), "extra", true, 1);
      if (ImGui::Button("x", ImVec2(ImGui::GetFrameHeight(), 0.0f))) {
        std::string list;
        for (std::size_t k = 0; k < extra.size(); ++k) {
          if (k != i) {
            list += (list.empty() ? "" : " ") + extra[k];
          }
        }
        mTools.AskExtraArmiesChange(list);
      }
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Take %s off the extra armies (its units stay in _save.lua)", extra[i].c_str());
      }
      endCard(next);
      ImGui::PopID();
    }
    {
      std::vector<std::string> names = players;
      names.insert(names.end(), extra.begin(), extra.end());
      std::vector<std::string> offers;
      for (const char* const usual : {"NEUTRAL_CIVILIAN", "ARMY_17"}) {
        if (std::find(names.begin(), names.end(), usual) == names.end()) {
          offers.emplace_back(usual);
        }
      }
      const std::string next = NextArmyName(names);
      if (std::find(offers.begin(), offers.end(), next) == offers.end()) {
        offers.push_back(next);
      }
      for (std::size_t i = 0; i < offers.size(); ++i) {
        if (i > 0) {
          ImGui::SameLine();
        }
        if (ImGui::Button(("+ " + offers[i]).c_str())) {
          std::string list;
          for (const std::string& army : extra) {
            list += army + " ";
          }
          mTools.AskExtraArmiesChange(list + offers[i]);
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip(
            "Add %s as an extra army: an owner for neutral or civilian units, not a lobby slot", offers[i].c_str()
          );
        }
      }
    }
    ImGui::SetNextItemWidth(
      ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Add").x - ImGui::GetStyle().FramePadding.x * 4.0f
    );
    ImGui::InputTextWithHint("##newextra", "Another name", mNewExtraArmy, sizeof(mNewExtraArmy));
    ImGui::SameLine();
    const std::string wantedExtra = mNewExtraArmy;
    const bool known = std::find(extra.begin(), extra.end(), wantedExtra) != extra.end() ||
      std::find(players.begin(), players.end(), wantedExtra) != players.end();
    ImGui::BeginDisabled(wantedExtra.empty() || known || wantedExtra.find(' ') != std::string::npos);
    if (ImGui::Button("Add")) {
      std::string list;
      for (const std::string& army : extra) {
        list += army + " ";
      }
      mTools.AskExtraArmiesChange(list + wantedExtra);
      mNewExtraArmy[0] = '\0';
    }
    ImGui::EndDisabled();

    // The chosen army.
    if (!mArmySelected.empty()) {
      const ArmyCard army = CardOf(mDocument, mArmySelected);
      ImGui::SeparatorText(mArmySelected.c_str());
      ImGui::BeginDisabled(!army.start);
      if (ImGui::Button("Go to start")) {
        mTools.AskMarkerFrame(mArmySelected);
      }
      ImGui::EndDisabled();
      ImGui::SameLine();
      ImGui::BeginDisabled(army.units == 0);
      if (ImGui::Button("Select its units")) {
        mTools.SetUnitTool(mTools.UnitType(), mArmySelected, true);
        mTools.AskGroup(EdTools::GroupAsk::Select, {}, "");
      }
      ImGui::EndDisabled();
      if (!army.groups.empty()) {
        ImGui::TextDisabled("Groups: %s", army.groups.c_str());
      }

      // A finished edit is one undo step; while a field is held, the panel's own copy changes.
      if (!mArmyEditing || mArmyEditName != mArmySelected) {
        mArmyEdit = army.settings;
        mArmyEditName = mArmySelected;
      }
      ArmySettings& edit = mArmyEdit;
      bool active = false;
      bool finished = false;
      const auto watch = [&] {
        active = active || ImGui::IsItemActive();
        finished = finished || ImGui::IsItemDeactivatedAfterEdit();
      };

      ImGui::TextDisabled("Starting resources");
      const float half = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) * 0.5f;
      float mass = static_cast<float>(edit.mass);
      float energy = static_cast<float>(edit.energy);
      ImGui::SetNextItemWidth(half);
      ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.20f, 0.30f, 0.16f, 1.0f));
      ImGui::DragFloat("##mass", &mass, 10.0f, 0.0f, 1000000.0f, "Mass %.0f");
      ImGui::PopStyleColor();
      watch();
      ImGui::SameLine();
      ImGui::SetNextItemWidth(half);
      ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.32f, 0.28f, 0.10f, 1.0f));
      ImGui::DragFloat("##energy", &energy, 10.0f, 0.0f, 1000000.0f, "Energy %.0f");
      ImGui::PopStyleColor();
      watch();
      edit.mass = mass;
      edit.energy = energy;

      ImGui::TextDisabled("Faction");
      const float quarter = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * 3.0f) * 0.25f;
      for (int f = 0; f < 4; ++f) {
        if (f > 0) {
          ImGui::SameLine();
        }
        const bool on = edit.faction == f;
        ImVec4 colour = kFactionColours[f];
        if (!on) {
          colour = ImVec4(colour.x * 0.35f, colour.y * 0.35f, colour.z * 0.35f, 1.0f);
        }
        ImGui::PushStyleColor(ImGuiCol_Button, colour);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kFactionColours[f]);
        if (ImGui::Button(kFactions[f], ImVec2(quarter, 0.0f)) && !on) {
          edit.faction = f;
          finished = true;
        }
        ImGui::PopStyleColor(2);
      }

      ImGui::SetNextItemWidth(half);
      ImGui::DragInt("##colour", &edit.color, 0.1f, 0, 32, "Colour %d");
      watch();
      ImGui::SameLine();
      ImGui::TextDisabled("a palette number");

      // Alliances: this army's stance toward each other one.
      if (ImGui::CollapsingHeader("Alliances")) {
        static const char* const kStances[4] = {"-", "Enemy", "Ally", "Neutral"};
        static const ImVec4 kStanceColours[4] = {
          ImVec4(0.30f, 0.32f, 0.36f, 1.0f),
          ImVec4(0.70f, 0.22f, 0.22f, 1.0f),
          ImVec4(0.25f, 0.60f, 0.30f, 1.0f),
          ImVec4(0.45f, 0.45f, 0.50f, 1.0f)
        };
        std::vector<std::string> others = players;
        others.insert(others.end(), extra.begin(), extra.end());
        const float stanceWidth = ImGui::GetFontSize() * 3.6f;
        for (const std::string& other : others) {
          if (other == mArmySelected) {
            continue;
          }
          ImGui::PushID(other.c_str());
          const auto found = std::find_if(edit.alliances.begin(), edit.alliances.end(), [&](const auto& pair) {
            return pair.first == other;
          });
          int stance = 0;
          for (int s = 1; s < 4 && found != edit.alliances.end(); ++s) {
            stance = found->second == kStances[s] ? s : stance;
          }
          ImGui::AlignTextToFramePadding();
          ImGui::TextUnformatted(other.c_str());
          ImGui::SameLine(
            ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - stanceWidth * 4.0f -
            ImGui::GetStyle().ItemSpacing.x * 3.0f
          );
          for (int s = 0; s < 4; ++s) {
            if (s > 0) {
              ImGui::SameLine();
            }
            ImVec4 colour = kStanceColours[s];
            if (stance != s) {
              colour = ImVec4(colour.x * 0.45f, colour.y * 0.45f, colour.z * 0.45f, 1.0f);
            }
            ImGui::PushStyleColor(ImGuiCol_Button, colour);
            if (ImGui::Button(kStances[s], ImVec2(stanceWidth, 0.0f)) && stance != s) {
              if (s == 0 && found != edit.alliances.end()) {
                edit.alliances.erase(found);
              } else if (s > 0 && found != edit.alliances.end()) {
                found->second = kStances[s];
              } else if (s > 0) {
                edit.alliances.emplace_back(other, kStances[s]);
              }
              finished = true;
              ImGui::PopStyleColor();
              break;
            }
            ImGui::PopStyleColor();
          }
          ImGui::PopID();
        }
      }
      if (ImGui::CollapsingHeader("Scripting")) {
        char plans[256];
        (void)std::snprintf(plans, sizeof(plans), "%s", edit.plans.c_str());
        ImGui::SetNextItemWidth(-1.0f);
        if (
          ImGui::InputTextWithHint(
            "##plans", "plans: an AI plan file", plans, sizeof(plans), ImGuiInputTextFlags_EnterReturnsTrue
          )
        ) {
          edit.plans = plans;
          finished = true;
        }
        active = active || ImGui::IsItemActive();
        char personality[128];
        (void)std::snprintf(personality, sizeof(personality), "%s", edit.personality.c_str());
        ImGui::SetNextItemWidth(-1.0f);
        if (
          ImGui::InputTextWithHint(
            "##personality", "personality", personality, sizeof(personality), ImGuiInputTextFlags_EnterReturnsTrue
          )
        ) {
          edit.personality = personality;
          finished = true;
        }
        active = active || ImGui::IsItemActive();
      }
      mArmyEditing = active;
      if (finished && !(edit == army.settings)) {
        EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
        for (SaveEntry& entry : mDocument.SaveData().Armies()) {
          if (entry.name == mArmySelected) {
            WriteArmySettings(entry, edit);
          }
        }
        if (!(before.armies == mDocument.SaveData().Armies())) {
          mDocument.SaveDataEdited(std::move(before));
          gpg::Logf(
            "editor: army %s: mass %.0f, energy %.0f, faction %s, colour %d, %zu alliances",
            mArmySelected.c_str(),
            edit.mass,
            edit.energy,
            kFactions[std::clamp(edit.faction, 0, 3)],
            edit.color,
            edit.alliances.size()
          );
        }
      }
      HelpNote(
        "FAF's skirmish start gives each army its starting mass and energy here (InitializeArmies); the lobby picks "
        "the "
        "faction and colour and the teams set the alliances, so those matter to scripted maps. The retail maps leave "
        "mass "
        "and energy at 0. Each change is one undo step."
      );
    }
    ImGui::End();
  }
} // namespace faf::editor
