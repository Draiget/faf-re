#include "editor/ui/EdUnitLabPanel.h"

#include "editor/doc/EdModProject.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdModPanel.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"
#include "lua/LuaObject.h"
#include "editor/ui/EdUiScale.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

#include <set>

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
    // What only the blueprint's Lua table holds (FAF's production, upkeep and shield numbers), from the rules' state.
    if (LuaPlus::LuaState* const state = static_cast<moho::RRuleGameRulesImpl*>(rules)->mLuaState; state != nullptr) {
      const LuaPlus::LuaObject table = bp->GetLuaBlueprint(state);
      for (const char* const key :
           {"Economy.ProductionPerSecondMass",
            "Economy.ProductionPerSecondEnergy",
            "Economy.MaintenanceConsumptionPerSecondEnergy",
            "Defense.Shield.ShieldMaxHealth",
            "Defense.Shield.ShieldRegenRate"}) {
        LuaPlus::LuaObject at = table;
        std::string rest = key;
        while (at.IsTable() && !rest.empty()) {
          const std::size_t dot = rest.find('.');
          at = at.GetByName(rest.substr(0, dot).c_str());
          rest = dot == std::string::npos ? std::string() : rest.substr(dot + 1);
        }
        if (rest.empty() && at.IsNumber()) {
          s.values[key] = at.GetNumber();
        }
      }
    }
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

  std::expected<void, std::string> EdUnitLabPanel::Derive(
    const std::string& id,
    const std::string& name,
    const std::string& description
  )
  {
    ModProject* const p = mProject.Project();
    if (p == nullptr || mUnit.empty()) {
      return std::unexpected("no project or unit");
    }
    const std::string base = ModSourceUnit(*p, mUnit);
    const ModChanges before = ModChangesOf(*p);
    if (const auto added = AddModDerived(*p, id, base, name, description, &EdUnitLabPanel::GameHasUnit); !added) {
      return std::unexpected(added.error());
    }
    (void)mProject.History().Record("derive " + id + " from " + base, before, ModChangesOf(*p), "", ImGui::GetTime());
    mProject.Touch();
    mUnit = id;
    return {};
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
        if (!filter.empty() && !lower.contains(filter)) {
          continue;
        }
        if (++shown > 300) {
          ImGui::TextDisabled("... more: type to narrow");
          break;
        }
        if (p->edits.contains(u.id)) {
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
      ImGui::Checkbox("With a script of its own", &mDeriveScript);
      EdSetItemTooltip("units/<id>/<id>_script.lua: a class built on the base unit's, written once for you to change");
      if (ImGui::Button("Derive")) {
        if (const auto derived = Derive(mDeriveId, mDeriveName, mDeriveDescription); derived) {
          if (mDeriveScript) {
            if (const auto made = p->derived.find(mDeriveId); made != p->derived.end()) {
              made->second.script = true;
            }
          }
          ImGui::CloseCurrentPopup();
        } else {
          mDeriveError = derived.error();
        }
      }
      if (!mDeriveError.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "%s", mDeriveError.c_str());
      }
      ImGui::EndPopup();
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(mUnit.empty() || (!p->edits.contains(mUnit) && !p->derived.contains(mUnit)));
    if (ImGui::Button(p->derived.contains(mUnit) ? "Remove unit" : "Revert unit")) {
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
    if (p->derived.contains(mUnit)) {
      if (ImGui::Button("Model from an OBJ...")) {
        mModelAsk = mUnit;
      }
      EdSetItemTooltip(
        "The derived unit's model made from a Wavefront OBJ (its units game units, y up): written as "
        "units/<id>/<id>_lod0.scm, every LOD of the unit drawn with it; the base unit's textures stay"
      );
      ImGui::SameLine();
    }
    if (ImGui::Button(ICON_PLAY " Test")) {
      mTestAsked = true;
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(mUnit.empty());
    if (ImGui::Button("Test in game")) {
      mTestInGameAsked = true;
    }
    ImGui::EndDisabled();
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      EdSetTooltip(
        canPlay ? "Plays the open map with the project's mod on; Test in game also puts the selected unit and dummy "
                  "targets near the first start, with quick orders here"
                : "Open a map to play it with the project's mod on"
      );
    }
    // The test running: the sim's state and the quick orders.
    if (!testUnit.empty()) {
      ImGui::SeparatorText(("Testing " + testUnit).c_str());
      ImGui::TextWrapped("%s", testStatus.empty() ? "Waiting for the play..." : testStatus.c_str());
      if (!testNote.empty()) {
        ImGui::TextDisabled("%s", testNote.c_str());
      }
      for (const char* order :
           {"Attack", "Move", "Patrol", "Stop", "Heal", "Kill", "Build", "Respawn", "Restart", "End test"}) {
        // One row that wraps (SameLineIfFits) instead of running off the panel.
        if (std::string(order) != "Attack") {
          SameLineIfFits(ImGui::CalcTextSize(order).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        }
        if (ImGui::SmallButton(order)) {
          std::string key = order;
          key = key == "End test" ? "end" : key;
          for (char& c : key) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          mTestOrder = key;
        }
      }
      // Fire any projectile of the game from the unit (the sim's own, with its effects), and play an effect template at
      // it (Studio's Effects panel).
      if (!testProjectiles.empty()) {
        testProjectile = std::clamp(testProjectile, 0, static_cast<int>(testProjectiles.size()) - 1);
        ImGui::SetNextItemWidth(Em(260.0f));
        if (EdBeginCombo("##testprojectile", testProjectiles[static_cast<std::size_t>(testProjectile)].c_str())) {
          for (int i = 0; i < static_cast<int>(testProjectiles.size()); ++i) {
            if (ImGui::Selectable(testProjectiles[static_cast<std::size_t>(i)].c_str(), i == testProjectile)) {
              testProjectile = i;
            }
          }
          ImGui::EndCombo();
        }
        SameLineIfFits(Em(120.0f));
        ImGui::SetNextItemWidth(Em(120.0f));
        (void)FillSliderFloat("##testspeed", &testProjectileSpeed, 1.0f, 100.0f, "Speed %.0f");
        SameLineIfFits(ImGui::CalcTextSize("Fire").x + ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::SmallButton("Fire")) {
          char order[320];
          (void)std::snprintf(
            order,
            sizeof(order),
            "fire:%s:%.1f",
            testProjectiles[static_cast<std::size_t>(testProjectile)].c_str(),
            static_cast<double>(testProjectileSpeed)
          );
          mTestOrder = order;
        }
        EdSetItemTooltip("The sim fires this projectile from the unit, with its trail and impact effects");
      }
      ImGui::SetNextItemWidth(Em(200.0f));
      ImGui::InputTextWithHint("##testeffect", "EffectTemplates name", testEffect, sizeof(testEffect));
      SameLineIfFits(Em(120.0f));
      ImGui::SetNextItemWidth(Em(120.0f));
      (void)FillSliderFloat("##testeffecth", &testEffectHeight, 0.0f, 20.0f, "Height %.1f");
      SameLineIfFits(ImGui::CalcTextSize("Play effect").x + ImGui::GetStyle().FramePadding.x * 2.0f);
      if (ImGui::SmallButton("Play effect")) {
        char order[200];
        (void)std::snprintf(order, sizeof(order), "effect:%s:%.1f", testEffect, static_cast<double>(testEffectHeight));
        mTestOrder = order;
      }
      EdSetItemTooltip("Plays an effect template of EffectTemplates.lua at the unit, this high above it");
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
    DrawProjectiles();
    ImGui::EndChild();
    ImGui::End();
  }

  void EdUnitLabPanel::DrawProjectiles()
  {
    // Studio's fxedit.lua: the numbers of the projectiles the unit's weapons fire, as merge blueprints of the project
    // (projectiles/<name>/<name>_proj.bp; each change an undo step of the project).
    ModProject* const p = mProject.Project();
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (p == nullptr || rules == nullptr || mUnit.empty()) {
      return;
    }
    moho::RResId unitId{};
    unitId.name.assign(mUnit.c_str());
    const moho::RUnitBlueprint* const unit = rules->GetUnitBlueprint(unitId);
    if (unit == nullptr || unit->Weapons.WeaponBlueprints.empty() || !Section("Projectiles", false)) {
      return;
    }
    std::set<std::string> shown;
    for (const moho::RUnitBlueprintWeapon& weapon : unit->Weapons.WeaponBlueprints) {
      std::string id = weapon.ProjectileId.name.c_str();
      for (char& c : id) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (id.empty() || !ModProjectileId(id) || !shown.insert(id).second) {
        continue;
      }
      const moho::RProjectileBlueprint* const bp = rules->GetProjectileBlueprint(weapon.ProjectileId);
      if (bp == nullptr) {
        continue;
      }
      ImGui::SeparatorText((std::string(weapon.Label.c_str()) + ": " + id).c_str());
      struct Row
      {
        const char* key;
        const char* label;
        double base;
        float step;
      };
      const Row rows[] = {
        {"Physics.InitialSpeed", "Initial speed", bp->Physics.InitialSpeed, 0.5f},
        {"Physics.MaxSpeed", "Max speed", bp->Physics.MaxSpeed, 0.5f},
        {"Physics.Acceleration", "Acceleration", bp->Physics.Acceleration, 0.5f},
        {"Physics.TurnRate", "Turn rate", bp->Physics.TurnRate, 1.0f},
        {"Physics.Lifetime", "Lifetime", bp->Physics.Lifetime, 0.1f},
        {"Physics.MaxZigZag", "Zig-zag", bp->Physics.MaxZigZag, 0.1f},
        {"Display.UniformScale", "Model scale", bp->Display.UniformScale, 0.01f},
        {"Economy.BuildCostMass", "Mass cost", bp->Economy.BuildCostMass, 10.0f},
        {"Economy.BuildCostEnergy", "Energy cost", bp->Economy.BuildCostEnergy, 100.0f},
        {"Economy.BuildTime", "Build time", bp->Economy.BuildTime, 10.0f},
      };
      ImGui::PushID(id.c_str());
      for (const Row& row : rows) {
        double current = row.base;
        bool changed = false;
        if (const auto edits = p->edits.find(id); edits != p->edits.end()) {
          if (const auto edit = edits->second.find(row.key); edit != edits->second.end()) {
            current = edit->second;
            changed = true;
          }
        }
        float value = static_cast<float>(current);
        ImGui::SetNextItemWidth(-Em(40.0f));
        const std::string label = std::string(row.label) + (changed ? " ~" : "");
        if (FillDragFloat((label + "##" + row.key).c_str(), &value, row.step, 0.0f, 0.0f, "%.2f")) {
          const ModChanges before = ModChangesOf(*p);
          if (SetModEdit(*p, id, row.key, value, row.base)) {
            (void)mProject.History().Record(
              "change " + id + " " + row.label, before, ModChangesOf(*p), "lab " + id + " " + row.key, ImGui::GetTime()
            );
            mProject.Touch();
          }
        }
        EdSetItemTooltip("%s: the game has %.2f", row.key, row.base);
        ImGui::SameLine();
        ImGui::BeginDisabled(!changed);
        if (ImGui::SmallButton((std::string(ICON_UNDO) + "##back" + row.key).c_str())) {
          const ModChanges before = ModChangesOf(*p);
          if (SetModEdit(*p, id, row.key, row.base, row.base)) {
            (void)mProject.History().Record(
              "change " + id + " " + row.label, before, ModChangesOf(*p), "", ImGui::GetTime()
            );
            mProject.Touch();
          }
        }
        ImGui::EndDisabled();
      }
      ImGui::PopID();
    }
  }
} // namespace faf::editor
