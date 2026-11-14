#include "editor/ui/EdUnitLabPanel.h"

#include "editor/doc/EdModProject.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdModPanel.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace faf::editor
{
  EdUnitLabPanel::EdUnitLabPanel(
    EdModPanel& project
  )
    : mProject(project)
  {}

  UnitLabSource EdUnitLabPanel::ReadUnit(
    const std::string& id
  )
  {
    UnitLabSource s;
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (rules == nullptr) {
      return s;
    }
    moho::RResId resId{};
    resId.name.assign(id.c_str());
    const moho::RUnitBlueprint* const bp = rules->GetUnitBlueprint(resId);
    if (bp == nullptr) {
      return s;
    }
    s.values = {
      {"Economy.BuildCostMass", bp->Economy.BuildCostMass},
      {"Economy.BuildCostEnergy", bp->Economy.BuildCostEnergy},
      {"Economy.BuildTime", bp->Economy.BuildTime},
      {"Economy.BuildRate", bp->Economy.BuildRate},
      {"Economy.StorageMass", bp->Economy.StorageMass},
      {"Economy.StorageEnergy", bp->Economy.StorageEnergy},
      {"Defense.MaxHealth", bp->Defense.MaxHealth},
      {"Defense.RegenRate", bp->Defense.RegenRate},
      {"Defense.Shield.ShieldSize", bp->Defense.Shield.ShieldSize},
      {"Physics.MaxSpeed", bp->Physics.MaxSpeed},
      {"Physics.MaxAcceleration", bp->Physics.MaxAcceleration},
      {"Physics.MaxBrake", bp->Physics.MaxBrake},
      {"Physics.TurnRate", bp->Physics.TurnRate},
      {"Intel.VisionRadius", static_cast<double>(bp->Intel.VisionRadius)},
      {"Intel.WaterVisionRadius", static_cast<double>(bp->Intel.WaterVisionRadius)},
      {"Intel.RadarRadius", static_cast<double>(bp->Intel.RadarRadius)},
      {"Intel.SonarRadius", static_cast<double>(bp->Intel.SonarRadius)},
      {"Intel.OmniRadius", static_cast<double>(bp->Intel.OmniRadius)},
    };
    for (const moho::RUnitBlueprintWeapon& w : bp->Weapons.WeaponBlueprints) {
      UnitLabSource::Weapon weapon;
      weapon.label = w.Label.c_str();
      weapon.values = {
        {"Damage", w.Damage},
        {"DamageRadius", w.DamageRadius},
        {"MaxRadius", w.MaxRadius},
        {"MinRadius", w.MinRadius},
        {"RateOfFire", w.RateOfFire},
        {"MuzzleVelocity", w.MuzzleVelocity},
      };
      s.weapons.push_back(std::move(weapon));
    }
    return s;
  }

  bool EdUnitLabPanel::GameHasUnit(
    const std::string& id
  )
  {
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (rules == nullptr) {
      return false;
    }
    moho::RResId resId{};
    resId.name.assign(id.c_str());
    return rules->GetUnitBlueprint(resId) != nullptr;
  }

  bool EdUnitLabPanel::Derive(
    const std::string& id,
    const std::string& name,
    const std::string& description,
    std::string& error
  )
  {
    ModProject* const p = mProject.Project();
    if (p == nullptr || mUnit.empty()) {
      error = "no project or unit";
      return false;
    }
    const std::string base = ModSourceUnit(*p, mUnit);
    const ModChanges before = ModChangesOf(*p);
    if (!AddModDerived(*p, id, base, name, description, &EdUnitLabPanel::GameHasUnit, error)) {
      return false;
    }
    (void)mProject.History().Record("derive " + id + " from " + base, before, ModChangesOf(*p), "", ImGui::GetTime());
    mProject.Touch();
    mUnit = id;
    return true;
  }

  bool EdUnitLabPanel::SetField(
    const UnitLabField& field,
    const double value,
    const bool merge
  )
  {
    ModProject* const p = mProject.Project();
    if (p == nullptr || mUnit.empty()) {
      return false;
    }
    const ModChanges before = ModChangesOf(*p);
    if (!SetModEdit(*p, mUnit, field.key, value, field.base)) {
      return false;
    }
    (void)mProject.History().Record(
      "change " + mUnit + " " + field.label,
      before,
      ModChangesOf(*p),
      merge ? "lab " + mUnit + " " + field.key : "",
      ImGui::GetTime()
    );
    mProject.Touch();
    return true;
  }

  void EdUnitLabPanel::Draw(
    bool& open,
    const std::vector<EdUnitInfo>& units,
    const bool canPlay
  )
  {
    if (!ImGui::Begin(Panel("Unit lab###UnitLab"), &open)) {
      ImGui::End();
      return;
    }
    ModProject* const p = mProject.Project();
    if (p == nullptr) {
      ImGui::TextWrapped("Open or make a mod project first (Mod project): the changes go into it.");
      ImGui::End();
      return;
    }
    // The unit: typed words narrow the list; changed units marked.
    const auto nameOf = [&](const std::string& id) {
      if (const auto d = p->derived.find(id); d != p->derived.end()) {
        return (d->second.name.empty() ? std::string("derived") : d->second.name) + "  (from " + d->second.base + ")";
      }
      const auto it = std::find_if(units.begin(), units.end(), [&](const EdUnitInfo& u) {
        return u.id == id;
      });
      return it != units.end() ? it->name : std::string();
    };
    const std::string current = mUnit.empty() ? std::string("(choose a unit)") : mUnit + "  " + nameOf(mUnit);
    ImGui::SetNextItemWidth(-1.0f);
    if (EdBeginCombo("##unit", current.c_str())) {
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::IsWindowAppearing()) {
        ImGui::SetKeyboardFocusHere();
      }
      ImGui::InputTextWithHint("##filter", "Id or name", mFilter, sizeof(mFilter));
      std::string filter = mFilter;
      std::transform(filter.begin(), filter.end(), filter.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      int shown = 0;
      // The project's derived units first.
      for (const auto& [id, d] : p->derived) {
        const std::string text = id + "  " + nameOf(id);
        if (ImGui::Selectable(text.c_str(), id == mUnit)) {
          mUnit = id;
        }
      }
      if (!p->derived.empty()) {
        ImGui::Separator();
      }
      for (const EdUnitInfo& u : units) {
        std::string text = u.id + "  " + u.name;
        std::string lower = text;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
        if (!filter.empty() && lower.find(filter) == std::string::npos) {
          continue;
        }
        if (++shown > 300) {
          ImGui::TextDisabled("... more: type to narrow");
          break;
        }
        if (p->edits.count(u.id) != 0) {
          text += "  (changed)";
        }
        if (ImGui::Selectable(text.c_str(), u.id == mUnit)) {
          mUnit = u.id;
        }
      }
      ImGui::EndCombo();
    }
    // Undo, redo, revert, test.
    ModEditHistory& history = mProject.History();
    ImGui::BeginDisabled(history.UndoName() == nullptr);
    if (ImGui::Button(ICON_UNDO " Undo")) {
      (void)history.Undo(*p);
      mProject.Touch();
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled) && history.UndoName() != nullptr) {
      EdSetTooltip("Undo %s (the project's own steps)", history.UndoName()->c_str());
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(history.RedoName() == nullptr);
    if (ImGui::Button(ICON_REDO " Redo")) {
      (void)history.Redo(*p);
      mProject.Touch();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(mUnit.empty());
    if (ImGui::Button("Derive...")) {
      std::snprintf(mDeriveId, sizeof(mDeriveId), "x%s", ModSourceUnit(*p, mUnit).substr(1).c_str());
      mDeriveName[0] = mDeriveDescription[0] = '\0';
      mDeriveError.clear();
      ImGui::OpenPopup("##derive");
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      EdSetTooltip("A new unit id copied from this unit (no files copied: the project's blueprint hook makes it)");
    }
    if (ImGui::BeginPopup("##derive")) {
      ImGui::Text("A new unit from %s", ModSourceUnit(*p, mUnit).c_str());
      ImGui::SetNextItemWidth(260.0f);
      ImGui::InputText("Id", mDeriveId, sizeof(mDeriveId));
      ImGui::SetNextItemWidth(260.0f);
      ImGui::InputText("Name", mDeriveName, sizeof(mDeriveName));
      ImGui::SetNextItemWidth(260.0f);
      ImGui::InputText("Description", mDeriveDescription, sizeof(mDeriveDescription));
      if (ImGui::Button("Derive")) {
        if (Derive(mDeriveId, mDeriveName, mDeriveDescription, mDeriveError)) {
          ImGui::CloseCurrentPopup();
        }
      }
      if (!mDeriveError.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "%s", mDeriveError.c_str());
      }
      ImGui::EndPopup();
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(mUnit.empty() || (p->edits.count(mUnit) == 0 && p->derived.count(mUnit) == 0));
    if (ImGui::Button(p->derived.count(mUnit) != 0 ? "Remove unit" : "Revert unit")) {
      const ModChanges before = ModChangesOf(*p);
      p->edits.erase(mUnit);
      const bool removed = p->derived.erase(mUnit) != 0;
      (void)history.Record((removed ? "remove " : "revert ") + mUnit, before, ModChangesOf(*p), "", ImGui::GetTime());
      if (removed) {
        mUnit.clear();
      }
      mProject.Touch();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!canPlay || p->Empty());
    if (ImGui::Button(ICON_PLAY " Test")) {
      mTestAsked = true;
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      EdSetTooltip(
        canPlay ? "Writes the project and plays the open map with its mod on"
                : "Open a map to play it with the project's mod on"
      );
    }
    if (mUnit.empty()) {
      ImGui::End();
      return;
    }
    if (mUnit.empty()) {
      ImGui::End();
      return;
    }
    // A derived unit's fields are its base unit's (its changes over them).
    const std::vector<UnitLabField> fields = UnitLabFields(ReadUnit(ModSourceUnit(*p, mUnit)));
    if (fields.empty()) {
      ImGui::TextDisabled("The game's rules have no fields for %s yet.", mUnit.c_str());
      ImGui::End();
      return;
    }
    const auto unit = p->edits.find(mUnit);
    std::string group;
    ImGui::BeginChild("##fields", ImVec2(0.0f, 0.0f), false);
    for (const UnitLabField& f : fields) {
      if (f.group != group) {
        group = f.group;
        ImGui::SeparatorText(group.c_str());
      }
      ImGui::PushID(f.key.c_str());
      double value = f.base;
      bool changed = false;
      if (unit != p->edits.end()) {
        const auto it = unit->second.find(f.key);
        if (it != unit->second.end()) {
          value = it->second;
          changed = true;
        }
      }
      RowLabel(f.label.c_str());
      ImGui::SetNextItemWidth(-ImGui::GetFrameHeight() * 1.4f);
      float x = static_cast<float>(value);
      char format[32];
      std::snprintf(format, sizeof(format), "%%.%df%s", f.decimals, changed ? "  ~" : "");
      if (
        FillDragFloat(
          "##v",
          &x,
          static_cast<float>(f.step),
          static_cast<float>(f.min),
          static_cast<float>(std::max(f.max, value)),
          format
        )
      ) {
        (void)SetField(f, x, true);
      }
      if (ImGui::IsItemHovered()) {
        char base[64];
        std::snprintf(base, sizeof(base), "%.*f", f.decimals, f.base);
        EdSetTooltip("%s: the game has %s%s", f.key.c_str(), base, changed ? " (~ changed in the project)" : "");
      }
      ImGui::SameLine();
      ImGui::BeginDisabled(!changed);
      if (ImGui::SmallButton(ICON_UNDO)) {
        (void)SetField(f, f.base, false);
      }
      ImGui::EndDisabled();
      if (ImGui::IsItemHovered() && changed) {
        EdSetTooltip("Back to the game's value");
      }
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();
  }
} // namespace faf::editor
