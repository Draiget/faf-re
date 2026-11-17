#include "editor/ui/EdUnitWizardPanel.h"

#include "editor/doc/EdModProject.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdModPanel.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ranges>

namespace faf::editor
{
  const std::string& EmbeddedEditorData(const std::string& name);

  EdUnitWizardPanel::EdUnitWizardPanel(
    EdModPanel& project
  )
    : mProject(project)
  {}

  bool EdUnitWizardPanel::Data()
  {
    if (!mDataTried) {
      mDataTried = true;
      const std::string& text = EmbeddedEditorData("unitwizdata.lua");
      if (text.empty()) {
        mDataError = "the wizard's template data isn't in this build";
      } else if (const auto loaded = LoadUnitWizardData(text, mData); !loaded) {
        mDataError = "the wizard's template data can't be read: " + loaded.error();
      }
      if (!mDataError.empty()) {
        gpg::Warnf("editor: unit wizard: %s", mDataError.c_str());
      }
    }
    return mDataError.empty();
  }

  void EdUnitWizardPanel::LoadSpecs()
  {
    mSpecs.clear();
    mCurrent = -1;
    mReport.clear();
    mChecks.clear();
    mFolder = mProject.Folder().string();
    std::ifstream in(mProject.Folder() / "editor_newunits.json", std::ios::binary);
    if (!in) {
      return;
    }
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (auto read = ReadUnitSpecs(text)) {
      mSpecs = std::move(*read);
    } else {
      gpg::Warnf("editor: unit wizard: editor_newunits.json: %s", read.error().c_str());
    }
    mCurrent = mSpecs.empty() ? -1 : 0;
  }

  void EdUnitWizardPanel::SaveSpecs()
  {
    if (mFolder.empty()) {
      return;
    }
    const std::string text = UnitSpecsText(mSpecs);
    std::ofstream out(std::filesystem::path(mFolder) / "editor_newunits.json", std::ios::binary | std::ios::trunc);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    mDirty = false;
  }

  bool EdUnitWizardPanel::Taken(
    const std::string& id
  ) const
  {
    if (gameHasUnit && gameHasUnit(id)) {
      return true;
    }
    if (const ModProject* p = const_cast<EdModPanel&>(mProject).Project(); p != nullptr && p->derived.contains(id)) {
      return true;
    }
    return std::any_of(mSpecs.begin(), mSpecs.end(), [&id](const UnitWizardSpec& s) {
      return s.id == id;
    });
  }

  std::string EdUnitWizardPanel::Test(
    const std::string& templateId,
    const std::string& faction
  )
  {
    if (mProject.Project() == nullptr) {
      return "no mod project open";
    }
    if (!Data()) {
      return mDataError;
    }
    if (mFolder != mProject.Folder().string()) {
      LoadSpecs();
    }
    const std::string id = SuggestUnitId(templateId, faction, [this](const std::string& i) {
      return Taken(i);
    });
    const auto made = NewUnitSpec(mData, templateId, faction, id);
    if (!made) {
      return made.error();
    }
    const UnitWizardSpec& spec = *made;
    mSpecs.push_back(spec);
    SaveSpecs();
    std::vector<std::string> report;
    const ModProject* p = mProject.Project();
    const auto edits = p->edits.find(id);
    (void)WriteWizardUnit(
      mData, spec, edits != p->edits.end() ? edits->second : std::map<std::string, double>{}, mFolder, report
    );
    UnitCheckGame game;
    game.unitExists = gameHasUnit;
    game.projectileExists = gameFileExists;
    game.fileExists = gameFileExists;
    std::string text = "made " + id + ":";
    for (const std::string& line : report) {
      text += " " + line + ";";
    }
    for (const UnitCheck& c : CheckWizardUnit(mData, spec, mFolder, game)) {
      text += std::string(" [") + c.severity + "] " + c.text + ";";
    }
    return text;
  }

  void EdUnitWizardPanel::Draw(
    bool& open
  )
  {
    ImGui::SetNextWindowSize(ImVec2(Em(420.0f), Em(640.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("New unit###UnitWizard"), &open)) {
      ImGui::End();
      return;
    }
    if (mProject.Project() == nullptr) {
      ImGui::TextWrapped("Open or make a mod project first (Mod project panel): the new units go into it.");
      ImGui::End();
      return;
    }
    if (!Data()) {
      ImGui::TextWrapped("%s", mDataError.c_str());
      ImGui::End();
      return;
    }
    if (mFolder != mProject.Folder().string()) {
      LoadSpecs();
    }
    HelpNote(
      "A unit with its own id, made from a template (bot, tank, ship, aircraft, structure ...) and never from a copy "
      "of "
      "a blueprint: its blueprint, script, strings, mesh (your OBJ, or a placeholder in the template's skeleton), "
      "textures and a quick icon are written into the project. The unit lab's changes go into its blueprint."
    );
    if (Section("New")) {
      std::vector<const char*> templates;
      for (const UnitTemplate& t : UnitTemplates()) {
        templates.push_back(t.label);
      }
      RowLabel("Template");
      ImGui::SetNextItemWidth(-1.0f);
      (void)EdCombo("##template", &mNewTemplate, templates.data(), static_cast<int>(templates.size()));
      RowLabel("Faction");
      ImGui::SetNextItemWidth(-1.0f);
      (void)EdCombo("##faction", &mNewFaction, UnitFactions().data(), static_cast<int>(UnitFactions().size()));
      if (PrimaryButton("Make the unit")) {
        const UnitTemplate& t = UnitTemplates()[static_cast<std::size_t>(mNewTemplate)];
        const std::string faction = UnitFactions()[static_cast<std::size_t>(mNewFaction)];
        const std::string id = SuggestUnitId(t.id, faction, [this](const std::string& i) {
          return Taken(i);
        });
        if (auto spec = NewUnitSpec(mData, t.id, faction, id)) {
          mSpecs.push_back(std::move(*spec));
          mCurrent = static_cast<int>(mSpecs.size()) - 1;
          SaveSpecs();
          mReport = {"made " + id + " (" + t.label + ", " + faction + "): set it up, then Write"};
        } else {
          mReport = {spec.error()};
        }
      }
    }
    if (!mSpecs.empty() && Section("Units")) {
      for (std::size_t i = 0; i < mSpecs.size(); ++i) {
        char label[200];
        (void)std::snprintf(
          label,
          sizeof(label),
          "%s  %s (%s %s)###unit%zu",
          mSpecs[i].id.c_str(),
          mSpecs[i].name.c_str(),
          mSpecs[i].faction.c_str(),
          mSpecs[i].templateId.c_str(),
          i
        );
        if (ImGui::Selectable(label, mCurrent == static_cast<int>(i))) {
          mCurrent = static_cast<int>(i);
          mChecks.clear();
        }
      }
    }
    if (mCurrent >= 0 && mCurrent < static_cast<int>(mSpecs.size())) {
      UnitWizardSpec& spec = mSpecs[static_cast<std::size_t>(mCurrent)];
      ImGui::PushID(mCurrent);
      DrawSpec(spec);
      ImGui::Separator();
      if (PrimaryButton("Write the unit")) {
        SaveSpecs();
        mReport.clear();
        const ModProject* p = mProject.Project();
        const auto edits = p->edits.find(spec.id);
        (void)WriteWizardUnit(
          mData, spec, edits != p->edits.end() ? edits->second : std::map<std::string, double>{}, mFolder, mReport
        );
        gpg::Logf("editor: unit wizard: %s written (%zu lines)", spec.id.c_str(), mReport.size());
      }
      ImGui::SameLine();
      if (ImGui::Button("Check")) {
        UnitCheckGame game;
        game.unitExists = gameHasUnit;
        game.projectileExists = gameFileExists;
        game.fileExists = gameFileExists;
        mChecks = CheckWizardUnit(mData, spec, mFolder, game);
      }
      ImGui::SameLine();
      if (ImGui::Button("Check mesh")) {
        // The mesh as Write would build it: its size and anything wrong with it (FAF Studio's Check mesh).
        std::string objText;
        if (!spec.mesh.source.empty()) {
          std::ifstream in(spec.mesh.source, std::ios::binary);
          objText.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        UnitMeshInfo info;
        if (const auto mesh = UnitMesh(mData, spec, objText, info); !mesh) {
          mReport = {"mesh: " + mesh.error()};
        } else {
          const std::array<float, 3> dims = UnitDims(mData, spec, info.bounds);
          char line[256];
          (void)std::snprintf(
            line,
            sizeof(line),
            "%s%d vertices, %d triangles, %d bones; %.2f x %.2f x %.2f world units",
            info.placeholder ? "placeholder: " : "",
            info.vertices,
            info.triangles,
            info.bones,
            static_cast<double>(dims[0]),
            static_cast<double>(dims[1]),
            static_cast<double>(dims[2])
          );
          mReport = {line};
          mReport.insert(mReport.end(), info.warnings.begin(), info.warnings.end());
        }
        gpg::Logf("editor: unit wizard: check mesh of %s: %s", spec.id.c_str(), mReport.front().c_str());
      }
      // Fix (FAF Studio's): what Write mends (missing files, the script's weapons, the icon), and no builder: the
      // template's builders.
      const bool fixable = std::any_of(mChecks.begin(), mChecks.end(), [](const UnitCheck& c) {
        return c.text.contains("Write") || c.text.contains("nothing can build");
      });
      if (fixable) {
        ImGui::SameLine();
        if (ImGui::Button("Fix")) {
          if (std::any_of(mChecks.begin(), mChecks.end(), [](const UnitCheck& c) {
            return c.text.contains("nothing can build");
          })) {
            if (const UnitTemplate* t = UnitTemplateOf(spec.templateId); t != nullptr) {
              spec.buildBy = DefaultBuildBy(*t, spec.tech);
            }
          }
          SaveSpecs();
          mReport.clear();
          const ModProject* p = mProject.Project();
          const auto edits = p->edits.find(spec.id);
          (void)WriteWizardUnit(
            mData, spec, edits != p->edits.end() ? edits->second : std::map<std::string, double>{}, mFolder, mReport
          );
          UnitCheckGame game;
          game.unitExists = gameHasUnit;
          game.projectileExists = gameFileExists;
          game.fileExists = gameFileExists;
          mChecks = CheckWizardUnit(mData, spec, mFolder, game);
          gpg::Logf("editor: unit wizard: %s fixed: %zu findings left", spec.id.c_str(), mChecks.size());
        }
        EdSetItemTooltip(
          "Writes the unit again (files, the script's weapons, the icon) and gives it the template's "
          "builders when nothing builds it"
        );
      }
      // The files the unit has in the project.
      if (ImGui::TreeNode("Files")) {
        const std::string id = spec.id;
        for (const std::string& rel :
             {"units/" + id + "/" + id + "_unit.bp",
              "units/" + id + "/" + id + "_script.lua",
              "units/" + id + "/" + id + "_strings.lua",
              "units/" + id + "/" + id + "_lod0.scm",
              "units/" + id + "/" + id + "_albedo.dds",
              "units/" + id + "/" + id + "_normalsts.dds",
              "units/" + id + "/" + id + "_specteam.dds",
              "textures/ui/common/icons/units/" + id + "_icon.dds"}) {
          std::error_code ec;
          const std::filesystem::path file = std::filesystem::path(mFolder) / rel;
          if (std::filesystem::exists(file, ec)) {
            ImGui::Text(
              "ok       %s (%llu bytes)",
              rel.c_str(),
              static_cast<unsigned long long>(std::filesystem::file_size(file, ec))
            );
          } else {
            ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "missing  %s", rel.c_str());
          }
        }
        ImGui::TreePop();
      }
      ImGui::SameLine();
      if (ImGui::Button("Remove from the list")) {
        mSpecs.erase(mSpecs.begin() + mCurrent);
        mCurrent = mSpecs.empty() ? -1 : 0;
        SaveSpecs();
        mReport = {"removed from the wizard's list; its files stay in the project"};
        ImGui::PopID();
        ImGui::End();
        return;
      }
      ImGui::PopID();
    }
    for (const UnitCheck& c : mChecks) {
      const ImU32 colour = c.severity == 'E' ? IM_COL32(255, 110, 100, 255)
        : c.severity == 'W'                  ? IM_COL32(255, 200, 100, 255)
                                             : IM_COL32(170, 170, 170, 255);
      ImGui::PushStyleColor(ImGuiCol_Text, colour);
      ImGui::TextWrapped("%c  %s", c.severity, c.text.c_str());
      ImGui::PopStyleColor();
    }
    for (const std::string& line : mReport) {
      ImGui::TextWrapped("%s", line.c_str());
    }
    if (mDirty) {
      SaveSpecs();
    }
    ImGui::End();
  }

  void EdUnitWizardPanel::DrawSpec(
    UnitWizardSpec& spec
  )
  {
    const auto text = [this](const char* label, const char* hint, std::string& value) {
      char buffer[512];
      (void)std::snprintf(buffer, sizeof(buffer), "%s", value.c_str());
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::InputTextWithHint(label, hint, buffer, sizeof(buffer))) {
        value = buffer;
        mDirty = true;
      }
    };
    const auto number = [this](
                          const char* id,
                          std::map<std::string, double>& map,
                          const char* key,
                          const float lo,
                          const float hi,
                          const char* format
                        ) {
      float v = static_cast<float>(map.contains(key) ? map[key] : 0.0);
      ImGui::SetNextItemWidth(-1.0f);
      if (FillDragFloat(id, &v, (hi - lo) / 400.0f, lo, hi, format)) {
        map[key] = v;
        mDirty = true;
      }
    };
    if (Section("Unit")) {
      std::string id = spec.id;
      text("##id", "unit id (zel0001)", id);
      if (id != spec.id) {
        if (const auto checked = CheckUnitId(id, [this, &spec](const std::string& i) {
          return i != spec.id && Taken(i);
        })) {
          spec.id = id;
        } else {
          ImGui::TextDisabled("%s", checked.error().c_str());
        }
      }
      text("##name", "name", spec.name);
      text("##desc", "description", spec.description);
      RowLabel("Tech");
      ImGui::SetNextItemWidth(-1.0f);
      static const char* const kTech[4] = {"Tech 1", "Tech 2", "Tech 3", "Experimental"};
      int tech = std::clamp(spec.tech, 1, 4) - 1;
      if (EdCombo("##tech", &tech, kTech, 4)) {
        spec.tech = tech + 1;
        if (const UnitTemplate* t = UnitTemplateOf(spec.templateId); t != nullptr) {
          spec.buildBy = DefaultBuildBy(*t, spec.tech);
        }
        mDirty = true;
      }
      ImGui::TextDisabled("Template %s, faction %s", spec.templateId.c_str(), spec.faction.c_str());
    }
    if (Section("Who builds it", false)) {
      for (const UnitBuildKey& key : UnitBuildKeys()) {
        bool on = std::find(spec.buildBy.begin(), spec.buildBy.end(), key.key) != spec.buildBy.end();
        if (ImGui::Checkbox(key.label, &on)) {
          if (on) {
            spec.buildBy.push_back(key.key);
          } else {
            spec.buildBy.erase(std::remove(spec.buildBy.begin(), spec.buildBy.end(), key.key), spec.buildBy.end());
          }
          mDirty = true;
        }
      }
      std::string add;
      for (const std::string& c : spec.catAdd) {
        add += (add.empty() ? "" : " ") + c;
      }
      std::string del;
      for (const std::string& c : spec.catDel) {
        del += (del.empty() ? "" : " ") + c;
      }
      const std::string addWas = add;
      const std::string delWas = del;
      text("##catadd", "categories to add (space between)", add);
      text("##catdel", "categories to take away", del);
      const auto split = [](const std::string& s) {
        std::vector<std::string> out;
        std::string word;
        for (const char c : s + " ") {
          if (c == ' ' || c == ',') {
            if (!word.empty()) {
              out.push_back(word);
            }
            word.clear();
          } else {
            word += c;
          }
        }
        return out;
      };
      if (add != addWas) {
        spec.catAdd = split(add);
      }
      if (del != delWas) {
        spec.catDel = split(del);
      }
      std::string cats;
      for (const std::string& c : UnitCategories(mData, spec)) {
        cats += (cats.empty() ? "" : " ") + c;
      }
      ImGui::TextWrapped("Categories: %s", cats.c_str());
    }
    if (Section("Numbers", false)) {
      number("##mass", spec.economy, "BuildCostMass", 0.0f, 100000.0f, "Mass %.0f");
      number("##energy", spec.economy, "BuildCostEnergy", 0.0f, 1000000.0f, "Energy %.0f");
      number("##time", spec.economy, "BuildTime", 1.0f, 100000.0f, "Build time %.0f");
      number("##health", spec.defense, "MaxHealth", 1.0f, 200000.0f, "Health %.0f");
      number("##regen", spec.defense, "RegenRate", 0.0f, 500.0f, "Regeneration %.1f");
      if (const UnitTemplate* t = UnitTemplateOf(spec.templateId); t != nullptr && t->mobile) {
        number("##speed", spec.physics, "MaxSpeed", 0.0f, 60.0f, "Speed %.2f");
        number("##accel", spec.physics, "MaxAcceleration", 0.0f, 60.0f, "Acceleration %.1f");
        number("##brake", spec.physics, "MaxBrake", 0.0f, 60.0f, "Braking %.1f");
        number("##turn", spec.physics, "TurnRate", 0.0f, 360.0f, "Turn rate %.0f");
        // The motion type (FAF Studio's Motion), and an air unit's cruise altitude.
        static constexpr const char* kMotions[] = {
          "(the template's)",
          "RULEUMT_Land",
          "RULEUMT_Air",
          "RULEUMT_Water",
          "RULEUMT_Hover",
          "RULEUMT_Amphibious",
          "RULEUMT_AmphibiousFloating",
          "RULEUMT_SurfacingSub"
        };
        int motion = 0;
        for (int i = 1; i < IM_ARRAYSIZE(kMotions); ++i) {
          motion = spec.motionType == kMotions[i] ? i : motion;
        }
        ImGui::SetNextItemWidth(-1.0f);
        if (EdCombo("##motion", &motion, kMotions, IM_ARRAYSIZE(kMotions))) {
          spec.motionType = motion == 0 ? std::string() : kMotions[motion];
          mDirty = true;
        }
        if (std::string(t->layer) == "air") {
          number("##elevation", spec.physics, "Elevation", 1.0f, 120.0f, "Cruise altitude %.0f");
        }
      } else {
        ImGui::SetNextItemWidth(Em(140.0f));
        if (FillSliderInt("##fx", &spec.footprintX, 1, 20, "Footprint %d")) {
          mDirty = true;
        }
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1.0f);
        if (FillSliderInt("##fz", &spec.footprintZ, 1, 20, "by %d")) {
          mDirty = true;
        }
      }
      number("##vision", spec.intel, "VisionRadius", 0.0f, 300.0f, "Vision %.0f");
      if (const UnitTemplate* t = UnitTemplateOf(spec.templateId); t != nullptr && t->builder) {
        number("##buildrate", spec.economy, "BuildRate", 0.0f, 500.0f, "Build rate %.1f");
        // What it builds: BuildableCategory expressions, | between them (empty: the template's).
        std::string list;
        for (const std::string& c : spec.buildable) {
          list += (list.empty() ? "" : " | ") + c;
        }
        const std::string was = list;
        text("##buildable", "this unit builds (BUILTBYTIER1ENGINEER UEF | ...; empty: the template's)", list);
        if (list != was) {
          spec.buildable.clear();
          std::string part;
          for (const char c : list + "|") {
            if (c == '|') {
              const std::size_t a = part.find_first_not_of(' ');
              const std::size_t b = part.find_last_not_of(' ');
              if (a != std::string::npos) {
                spec.buildable.push_back(part.substr(a, b - a + 1));
              }
              part.clear();
            } else {
              part += c;
            }
          }
        }
      }
      if (spec.templateId == "economy") {
        number("##energyprod", spec.economy, "ProductionPerSecondEnergy", 0.0f, 20000.0f, "Energy produced %.0f / s");
      }
      text("##sounds", "sound set: a unit id whose sounds it takes (empty: the template's)", spec.sounds);
      static constexpr const char* kAnims[] = {"Animations: the template's", "Animations: none"};
      int anim = spec.anim == "none" ? 1 : 0;
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##anim", &anim, kAnims, 2)) {
        spec.anim = anim == 1 ? "none" : "template";
        mDirty = true;
      }
    }
    if (Section("Weapons", false)) {
      int remove = -1;
      for (std::size_t i = 0; i < spec.weapons.size(); ++i) {
        UnitWizardWeapon& w = spec.weapons[i];
        ImGui::PushID(static_cast<int>(i));
        // Its kind (the template's kinds): a change takes the donor's numbers for that kind, the label kept.
        if (const UnitTemplate* tk = UnitTemplateOf(spec.templateId); tk != nullptr && !tk->kinds.empty()) {
          std::vector<const char*> kinds;
          int index = 0;
          for (std::size_t k = 0; k < tk->kinds.size(); ++k) {
            kinds.push_back(UnitWeaponKindName(tk->kinds[k]));
            index = w.kind == tk->kinds[k] ? static_cast<int>(k) : index;
          }
          ImGui::SetNextItemWidth(-1.0f);
          if (EdCombo("##kind", &index, kinds.data(), static_cast<int>(kinds.size()))) {
            const std::string label = w.label;
            w = NewUnitWeapon(mData, spec, tk->kinds[static_cast<std::size_t>(index)], label);
            mDirty = true;
          }
        } else {
          ImGui::TextDisabled("%s", UnitWeaponKindName(w.kind));
        }
        text("##label", "label (the script's weapon name)", w.label);
        const auto weaponNumber =
          [this](const char* id, double& value, const float lo, const float hi, const char* format) {
          float v = static_cast<float>(value);
          ImGui::SetNextItemWidth(-1.0f);
          if (FillDragFloat(id, &v, (hi - lo) / 400.0f, lo, hi, format)) {
            value = v;
            mDirty = true;
          }
        };
        weaponNumber("##damage", w.damage, 0.0f, 100000.0f, "Damage %.1f");
        weaponNumber("##range", w.range, 0.0f, 1000.0f, "Range %.1f");
        weaponNumber("##minrange", w.minRange, 0.0f, 500.0f, "Minimum range %.1f");
        weaponNumber("##rof", w.rof, 0.01f, 20.0f, "Rate of fire %.2f");
        weaponNumber("##radius", w.damageRadius, 0.0f, 50.0f, "Damage radius %.1f");
        text("##proj", "projectile blueprint", w.projectile);
        if (ImGui::SmallButton("Remove weapon")) {
          remove = static_cast<int>(i);
        }
        ImGui::Separator();
        ImGui::PopID();
      }
      if (remove >= 0) {
        spec.weapons.erase(spec.weapons.begin() + remove);
        mDirty = true;
      }
      if (const UnitTemplate* t = UnitTemplateOf(spec.templateId); t != nullptr && !t->kinds.empty()) {
        auto names = t->kinds | std::views::transform([&](const char* k) {
          return UnitWeaponKindName(k);
        }) |
          std::ranges::to<std::vector<const char*>>();
        mNewWeaponKind = std::clamp(mNewWeaponKind, 0, static_cast<int>(names.size()) - 1);
        ImGui::SetNextItemWidth(Em(160.0f));
        (void)EdCombo("##newweapon", &mNewWeaponKind, names.data(), static_cast<int>(names.size()));
        ImGui::SameLine();
        if (ImGui::Button("Add weapon")) {
          const std::string label =
            spec.weapons.empty() ? "MainGun" : "Weapon" + std::to_string(spec.weapons.size() + 1);
          spec.weapons.push_back(NewUnitWeapon(mData, spec, t->kinds[static_cast<std::size_t>(mNewWeaponKind)], label));
          mDirty = true;
        }
      }
    }
    if (Section("Mesh and textures", false)) {
      text("##obj", "OBJ file (empty: a placeholder)", spec.mesh.source);
      ImGui::SetNextItemWidth(Em(120.0f));
      if (FillSliderInt("##lods", &spec.mesh.lods, 1, 2, "LODs %d")) {
        mDirty = true;
      }
      EdSetItemTooltip("2: a second level of detail (the same mesh) for zoomed out views");
      static const char* const kAxis[2] = {"Y up", "Z up"};
      int axis = spec.mesh.axis == "z_up" ? 1 : 0;
      RowLabel("Up axis");
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##axis", &axis, kAxis, 2)) {
        spec.mesh.axis = axis == 1 ? "z_up" : "y_up";
        mDirty = true;
      }
      static const char* const kSkeleton[2] = {"The template's skeleton", "One bone per OBJ group"};
      int skeleton = spec.mesh.skeleton == "groups" ? 1 : 0;
      RowLabel("Bones");
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##skeleton", &skeleton, kSkeleton, 2)) {
        spec.mesh.skeleton = skeleton == 1 ? "groups" : "template";
        mDirty = true;
      }
      EdSetItemTooltip("Template: OBJ groups named like the template's bones move with them, the rest with the root");
      ImGui::SetNextItemWidth(-1.0f);
      if (FillDragFloat("##length", &spec.mesh.length, 0.01f, 0.1f, 100.0f, "Length %.2f units")) {
        mDirty = true;
      }
      ImGui::SetNextItemWidth(-1.0f);
      if (FillSliderFloat("##yaw", &spec.mesh.yaw, -180.0f, 180.0f, "Turn %.0f deg")) {
        mDirty = true;
      }
      mDirty |= ImGui::Checkbox("Mirror X", &spec.mesh.mirrorX);
      ImGui::SameLine();
      mDirty |= ImGui::Checkbox("Flip faces", &spec.mesh.flipWinding);
      ImGui::SameLine();
      mDirty |= ImGui::Checkbox("Flip V", &spec.mesh.flipV);
      text("##albedo", "albedo DDS (empty: placeholder)", spec.albedo);
      text("##normal", "normal map DDS", spec.normal);
      text("##spec", "specular + team colour DDS", spec.specular);
      mDirty |= ImGui::Checkbox("Quick icon", &spec.icon);
      static const char* const kAnim[2] = {"The template's animations", "None"};
      int anim = spec.anim == "none" ? 1 : 0;
      RowLabel("Animations");
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##anim", &anim, kAnim, 2)) {
        spec.anim = anim == 1 ? "none" : "template";
        mDirty = true;
      }
    }
  }
} // namespace faf::editor
