#include "editor/ui/EdModPanel.h"

#include "editor/doc/EdDocument.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

#include <algorithm>
#include <cstdio>
#include <system_error>

namespace faf::editor
{
  namespace
  {
    bool TextField(
      const char* id,
      std::string& value
    )
    {
      char buffer[512];
      std::snprintf(buffer, sizeof(buffer), "%s", value.c_str());
      if (ImGui::InputText(id, buffer, sizeof(buffer))) {
        value = buffer;
        return true;
      }
      return false;
    }
  } // namespace

  EdModPanel::EdModPanel(
    EdDocument& document
  )
    : mDocument(document)
  {}

  std::filesystem::path EdModPanel::Root() const
  {
    return mDocument.VaultFolder().empty() ? std::filesystem::path() : mDocument.VaultFolder() / "mods";
  }

  int EdModPanel::WeaponIndex(
    const std::string& id,
    const std::string& label
  )
  {
    moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
    if (rules == nullptr) {
      return 0;
    }
    moho::RResId resId{};
    resId.name.assign(id.c_str());
    const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(resId);
    if (blueprint == nullptr) {
      return 0;
    }
    const auto& weapons = blueprint->Weapons.WeaponBlueprints;
    for (std::size_t i = 0; i < weapons.size(); ++i) {
      if (label == weapons[i].Label.c_str()) {
        return static_cast<int>(i) + 1;
      }
    }
    return 0;
  }

  bool EdModPanel::Create(
    const std::string& name,
    std::string& error
  )
  {
    if (Root().empty()) {
      error = "no vault folder to keep mods in";
      return false;
    }
    if (!ModProjectNameOk(name)) {
      error = "a project name takes letters, digits, spaces, _ and -";
      return false;
    }
    std::error_code ec;
    const std::filesystem::path folder = Root() / name;
    if (std::filesystem::exists(folder, ec)) {
      error = "there is a mod folder " + name + " already";
      return false;
    }
    ModProject p;
    p.name = name;
    p.uid = NewModUid();
    p.description = "Made with the FAF map editor";
    mProject = std::move(p);
    mFolder = folder;
    mHistory.Clear();
    const ModWriteReport report = Write();
    if (!report.problems.empty()) {
      error = report.problems.front();
      return false;
    }
    return true;
  }

  bool EdModPanel::Open(
    const std::string& name,
    std::string& error
  )
  {
    ModProject p;
    bool fromBackup = false;
    if (!OpenModProject(Root() / name, p, error, &fromBackup)) {
      return false;
    }
    mProject = std::move(p);
    mFolder = Root() / name;
    mHistory.Clear();
    mDirty = fromBackup;
    mReport.clear();
    mMessage =
      fromBackup ? "its project file couldn't be read: opened the copy before it (write to keep it)" : "opened " + name;
    gpg::Logf("editor: mod project %s opened (%zu units changed)", name.c_str(), mProject->edits.size());
    return true;
  }

  ModWriteReport EdModPanel::Write()
  {
    ModWriteReport report;
    if (!mProject) {
      return report;
    }
    report = WriteModProject(
      mFolder, *mProject, &EdModPanel::WeaponIndex, [this](const std::string& text, const std::string& name) {
      const CheckIssue issue = mDocument.CheckLuaText(text, name);
      return issue.text;
    }
    );
    mDirty = !report.problems.empty();
    mReport = report.problems;
    mMessage = "wrote " + std::to_string(report.written.size()) + " files" +
      (report.problems.empty() ? std::string() : ", " + std::to_string(report.problems.size()) + " problems");
    gpg::Logf(
      "editor: mod project %s written to %s: %zu files, %zu problems",
      mProject->name.c_str(),
      mFolder.string().c_str(),
      report.written.size(),
      report.problems.size()
    );
    for (const std::string& problem : report.problems) {
      gpg::Warnf("editor: mod project: %s", problem.c_str());
    }
    return report;
  }

  void EdModPanel::Draw(
    bool& open
  )
  {
    if (!ImGui::Begin(Panel("Mod project###ModProject"), &open)) {
      ImGui::End();
      return;
    }
    const std::filesystem::path root = Root();
    if (root.empty()) {
      ImGui::TextDisabled("No vault folder: the mods folder is in it.");
      ImGui::End();
      return;
    }
    ImGui::TextDisabled("In %s", root.string().c_str());
    // Open one of the projects, or make one.
    const std::vector<std::string> projects = ModProjectsIn(root);
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.6f);
    const std::string current = mProject ? mFolder.filename().string() : std::string();
    if (
      EdBeginCombo(
        "##projects", current.empty() ? (projects.empty() ? "(no projects yet)" : "(open a project)") : current.c_str()
      )
    ) {
      for (const std::string& name : projects) {
        if (ImGui::Selectable(name.c_str(), name == current)) {
          std::string error;
          if (!Open(name, error)) {
            mMessage = "couldn't open " + name + ": " + error;
          }
        }
      }
      ImGui::EndCombo();
    }
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.6f);
    ImGui::InputTextWithHint("##newname", "New project's name", mNewName, sizeof(mNewName));
    ImGui::SameLine();
    if (ImGui::Button(ICON_PLUS " New project")) {
      std::string error;
      if (Create(mNewName, error)) {
        mNewName[0] = '\0';
      } else {
        mMessage = error;
      }
    }
    if (ImGui::IsItemHovered()) {
      EdSetTooltip(
        "A mod folder the game lists: mod_info.lua, the project file, and a merge blueprint per unit you change"
      );
    }
    if (!mMessage.empty()) {
      ImGui::TextWrapped("%s", mMessage.c_str());
    }
    if (!mProject) {
      ImGui::End();
      return;
    }
    ModProject& p = *mProject;
    ImGui::SeparatorText(("Project" + std::string(mDirty ? "  (not written)" : "")).c_str());
    RowLabel("Name");
    ImGui::SetNextItemWidth(-1.0f);
    if (TextField("##name", p.name)) {
      mDirty = true;
    }
    RowLabel("Author");
    ImGui::SetNextItemWidth(-1.0f);
    if (TextField("##author", p.author)) {
      mDirty = true;
    }
    RowLabel("Description");
    ImGui::SetNextItemWidth(-1.0f);
    if (TextField("##description", p.description)) {
      mDirty = true;
    }
    RowLabel("Version");
    ImGui::SetNextItemWidth(-1.0f);
    if (ImGui::InputInt("##version", &p.version)) {
      p.version = std::max(1, p.version);
      mDirty = true;
    }
    ImGui::TextDisabled("uid %s", p.uid.c_str());
    ImGui::SeparatorText("Changes");
    if (p.edits.empty()) {
      ImGui::TextDisabled("No unit changed yet (the unit lab changes them).");
    }
    std::string removeId;
    std::string removeKey;
    if (
      !p.edits.empty() && ImGui::BeginTable("##edits", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)
    ) {
      ImGui::TableSetupColumn("Unit", ImGuiTableColumnFlags_WidthStretch, 0.7f);
      ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthStretch, 1.6f);
      ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch, 0.7f);
      ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFrameHeight());
      ImGui::TableHeadersRow();
      int row = 0;
      for (const auto& [id, keys] : p.edits) {
        for (const auto& [key, value] : keys) {
          ImGui::PushID(row++);
          ImGui::TableNextRow();
          ImGui::TableNextColumn();
          ImGui::TextUnformatted(id.c_str());
          ImGui::TableNextColumn();
          ImGui::TextUnformatted(key.c_str());
          ImGui::TableNextColumn();
          ImGui::Text("%g", value);
          ImGui::TableNextColumn();
          if (ImGui::SmallButton(ICON_TRASH)) {
            removeId = id;
            removeKey = key;
          }
          if (ImGui::IsItemHovered()) {
            EdSetTooltip("Back to the game's value");
          }
          ImGui::PopID();
        }
      }
      ImGui::EndTable();
    }
    if (!removeId.empty()) {
      const ModEditHistory::Edits before = p.edits;
      p.edits[removeId].erase(removeKey);
      if (p.edits[removeId].empty()) {
        p.edits.erase(removeId);
      }
      (void)mHistory.Record("revert " + removeId + " " + removeKey, before, p.edits, "", ImGui::GetTime());
      mDirty = true;
    }
    ImGui::BeginDisabled(mHistory.UndoName() == nullptr);
    if (ImGui::Button(ICON_UNDO " Undo")) {
      (void)mHistory.Undo(p.edits);
      mDirty = true;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(mHistory.RedoName() == nullptr);
    if (ImGui::Button(ICON_REDO " Redo")) {
      (void)mHistory.Redo(p.edits);
      mDirty = true;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button(ICON_SAVE " Write project")) {
      (void)Write();
    }
    if (ImGui::IsItemHovered()) {
      EdSetTooltip(
        "Writes mod_info.lua, the project file and the merge blueprints; a file that doesn't compile, or "
        "one the project didn't make, is left as it is"
      );
    }
    for (const std::string& problem : mReport) {
      ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "%s", problem.c_str());
    }
    ImGui::End();
  }
} // namespace faf::editor
