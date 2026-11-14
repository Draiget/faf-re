#include "editor/ui/EdMissionPanel.h"

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    void CollectGroups(
      const UnitGroup& group,
      std::vector<std::string>& out
    )
    {
      for (const UnitGroup& g : group.groups) {
        out.push_back(g.name);
        CollectGroups(g, out);
      }
    }

    /** An InputText over a std::string. */
    bool TextField(
      const char* id,
      std::string& value,
      const bool multiline = false
    )
    {
      char buffer[2048];
      std::snprintf(buffer, sizeof(buffer), "%s", value.c_str());
      const bool changed = multiline
        ? ImGui::InputTextMultiline(id, buffer, sizeof(buffer), ImVec2(-1.0f, ImGui::GetTextLineHeight() * 6.0f))
        : ImGui::InputText(id, buffer, sizeof(buffer));
      if (changed) {
        value = buffer;
      }
      return changed;
    }

    const char* const kSections[] = {"When it starts", "Then"};
  } // namespace

  MissionFacts MissionFactsOf(
    const EdDocument& document
  )
  {
    MissionFacts facts;
    facts.armies = document.Armies();
    for (const std::string& extra : document.ExtraArmies()) {
      facts.armies.push_back(extra);
    }
    const SaveFile& save = document.SaveData();
    for (const MarkerChain& chain : save.Chains()) {
      facts.chains.push_back(chain.name);
    }
    for (const SaveEntry& area : save.Areas()) {
      facts.areas.push_back(area.name);
    }
    for (const SaveEntry& marker : save.Markers()) {
      facts.markers.push_back(marker.name);
    }
    for (const SaveEntry& army : save.Armies()) {
      UnitGroup root;
      std::string error;
      if (ParseUnitGroup(army.Get("Units"), root, error)) {
        CollectGroups(root, facts.groups[army.name]);
      }
    }
    return facts;
  }

  EdMissionPanel::EdMissionPanel(
    EdDocument& document
  )
    : mDocument(document)
  {}

  void EdMissionPanel::Edited(
    Mission before
  )
  {
    mDocument.MissionEdited(std::move(before));
  }

  void EdMissionPanel::BeginField()
  {
    if (ImGui::IsItemActivated()) {
      mFieldBefore = mDocument.MissionNow();
    }
  }

  void EdMissionPanel::EndField(
    const bool
  )
  {
    if (ImGui::IsItemDeactivated() && mFieldBefore.has_value()) {
      if (ImGui::IsItemDeactivatedAfterEdit()) {
        mDocument.MissionEdited(std::move(*mFieldBefore));
      }
      mFieldBefore.reset();
    }
  }

  std::vector<MissionNode>* EdMissionPanel::ListOf(
    Mission& m,
    const int section,
    const std::vector<int>& path
  )
  {
    if (mStage < 0 || mStage >= static_cast<int>(m.stages.size()) || path.empty()) {
      return nullptr;
    }
    MissionStage& stage = m.stages[static_cast<std::size_t>(mStage)];
    std::vector<MissionNode>* list = section == 0 ? &stage.enter : &stage.ready;
    for (std::size_t k = 0; k + 1 < path.size(); ++k) {
      if (path[k] < 0 || path[k] >= static_cast<int>(list->size())) {
        return nullptr;
      }
      list = &(*list)[static_cast<std::size_t>(path[k])].children;
    }
    return path.back() >= 0 && path.back() < static_cast<int>(list->size()) ? list : nullptr;
  }

  MissionNode* EdMissionPanel::NodeAt(
    Mission& m,
    const int section,
    const std::vector<int>& path
  )
  {
    std::vector<MissionNode>* list = ListOf(m, section, path);
    return list != nullptr ? &(*list)[static_cast<std::size_t>(path.back())] : nullptr;
  }

  void EdMissionPanel::DrawNodes(
    std::vector<MissionNode>& list,
    const int section,
    std::vector<int> path,
    const int depth
  )
  {
    for (std::size_t i = 0; i < list.size(); ++i) {
      std::vector<int> here = path;
      here.push_back(static_cast<int>(i));
      const MissionNode& node = list[i];
      const MissionNodeType* t = FindMissionNodeType(node.type);
      std::string label =
        std::string(static_cast<std::size_t>(depth) * 2, ' ') + (t != nullptr ? t->title : "Unknown: " + node.type);
      // A short summary: the first text-like value.
      if (t != nullptr) {
        for (const MissionParam& p : t->params) {
          const auto it = node.p.find(p.key);
          if (
            it != node.p.end() && !it->second.empty() && p.kind != "bool" && p.kind != "number" && p.kind != "choice"
          ) {
            label += "  (" + it->second.substr(0, 32) + ")";
            break;
          }
        }
      }
      ImGui::PushID(static_cast<int>(i));
      if (ImGui::Selectable(label.c_str(), mSection == section && mPath == here)) {
        mSection = section;
        mPath = here;
      }
      if (t != nullptr && t->container) {
        ImGui::PushID("children");
        DrawNodes(list[i].children, section, here, depth + 1);
        ImGui::PopID();
      }
      ImGui::PopID();
    }
  }

  void EdMissionPanel::DrawParams(
    MissionNode& node,
    const MissionFacts& facts
  )
  {
    const MissionNodeType* t = FindMissionNodeType(node.type);
    if (t == nullptr) {
      ImGui::TextDisabled("Unknown node type %s: it is left out of the script.", node.type.c_str());
      return;
    }
    if (t->params.empty()) {
      ImGui::TextDisabled("No settings.");
    }
    const Mission& m = mDocument.MissionNow();
    for (const MissionParam& p : t->params) {
      ImGui::PushID(p.key.c_str());
      std::string& value = node.p[p.key];
      RowLabel(p.label.c_str());
      ImGui::SetNextItemWidth(-1.0f);
      // A list to choose from (the map's names), or typed text.
      std::vector<std::string> names;
      if (p.kind == "army") {
        names = facts.armies;
      } else if (p.kind == "chain") {
        names = facts.chains;
      } else if (p.kind == "area") {
        names = facts.areas;
      } else if (p.kind == "marker") {
        names = facts.markers;
      } else if (p.kind == "dialogue") {
        for (const MissionDialogue& d : m.dialogues) {
          names.push_back(d.name);
        }
      } else if (p.kind == "group") {
        const auto found = facts.groups.find(node.p["army"]);
        if (found != facts.groups.end()) {
          names = found->second;
        }
      } else if (p.kind == "choice") {
        names = p.choices;
      }
      if (p.kind == "bool") {
        bool on = value == "true";
        if (ImGui::Checkbox("##v", &on)) {
          Mission before = mDocument.MissionNow();
          value = on ? "true" : "false";
          Edited(std::move(before));
        }
      } else if (p.kind == "number") {
        float x = static_cast<float>(std::atof(value.c_str()));
        const bool edited =
          FillDragFloat("##v", &x, 0.25f, static_cast<float>(p.min), static_cast<float>(p.max), "%.1f");
        BeginField();
        if (edited) {
          char buffer[32];
          std::snprintf(buffer, sizeof(buffer), "%g", static_cast<double>(x));
          value = buffer;
        }
        EndField(edited);
      } else if (!names.empty() || p.kind == "choice") {
        if (EdBeginCombo("##v", value.empty() ? "(choose)" : value.c_str())) {
          if (p.optional && ImGui::Selectable("(none)", value.empty())) {
            Mission before = mDocument.MissionNow();
            value.clear();
            Edited(std::move(before));
          }
          for (const std::string& name : names) {
            if (ImGui::Selectable(name.c_str(), name == value)) {
              Mission before = mDocument.MissionNow();
              value = name;
              Edited(std::move(before));
            }
          }
          ImGui::EndCombo();
        }
      } else {
        const bool edited = TextField("##v", value, node.type == "raw");
        BeginField();
        EndField(edited);
      }
      ImGui::PopID();
    }
  }

  void EdMissionPanel::DrawStagesPanel(
    bool& open,
    const bool mapOpen
  )
  {
    if (!ImGui::Begin(Panel("Stages###MissionStages"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to give it a mission.");
      ImGui::End();
      return;
    }
    Mission& m = mDocument.EditMission();
    const MissionFacts facts = MissionFactsOf(mDocument);
    // The mode.
    {
      static const char* const kModes[] = {"campaign", "coop", "both"};
      int mode = m.mode == "coop" ? 1 : m.mode == "both" ? 2 : 0;
      RowLabel("Mode");
      ImGui::SetNextItemWidth(-1.0f);
      if (EdCombo("##missionmode", &mode, kModes, 3)) {
        Mission before = m;
        m.mode = kModes[mode];
        Edited(std::move(before));
      }
    }
    // The stages.
    if (Section("Stages")) {
      for (std::size_t s = 0; s < m.stages.size(); ++s) {
        const MissionStage& stage = m.stages[s];
        char label[160];
        std::snprintf(
          label,
          sizeof(label),
          "%zu  %s  (%zu nodes)##stage%zu",
          s + 1,
          stage.name.empty() ? "(no name)" : stage.name.c_str(),
          stage.enter.size() + stage.ready.size(),
          s
        );
        if (ImGui::Selectable(label, mStage == static_cast<int>(s))) {
          mStage = static_cast<int>(s);
          mPath.clear();
        }
      }
      if (ImGui::SmallButton(ICON_PLUS " Stage")) {
        Mission before = m;
        MissionStage stage;
        stage.name = "Stage " + std::to_string(m.stages.size() + 1);
        m.stages.push_back(stage);
        mStage = static_cast<int>(m.stages.size()) - 1;
        mPath.clear();
        Edited(std::move(before));
      }
      const bool has = mStage >= 0 && mStage < static_cast<int>(m.stages.size());
      ImGui::BeginDisabled(!has);
      ImGui::SameLine();
      if (ImGui::SmallButton("Up") && mStage > 0) {
        Mission before = m;
        std::swap(m.stages[static_cast<std::size_t>(mStage)], m.stages[static_cast<std::size_t>(mStage - 1)]);
        --mStage;
        Edited(std::move(before));
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Down") && mStage + 1 < static_cast<int>(m.stages.size())) {
        Mission before = m;
        std::swap(m.stages[static_cast<std::size_t>(mStage)], m.stages[static_cast<std::size_t>(mStage + 1)]);
        ++mStage;
        Edited(std::move(before));
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(ICON_TRASH " Stage") && has) {
        Mission before = m;
        m.stages.erase(m.stages.begin() + mStage);
        mStage = std::max(0, mStage - 1);
        mPath.clear();
        Edited(std::move(before));
      }
      ImGui::EndDisabled();
    }
    if (mStage < 0 || mStage >= static_cast<int>(m.stages.size())) {
      ImGui::TextDisabled(m.stages.empty() ? "No stages: add one to start the mission." : "Pick a stage.");
      ImGui::End();
      return;
    }
    MissionStage& stage = m.stages[static_cast<std::size_t>(mStage)];
    RowLabel("Name");
    ImGui::SetNextItemWidth(-1.0f);
    bool edited = TextField("##stagename", stage.name);
    BeginField();
    EndField(edited);
    float failsafe = static_cast<float>(stage.failsafe);
    ImGui::SetNextItemWidth(-1.0f);
    edited = FillDragFloat("##failsafe", &failsafe, 1.0f, 0.0f, 7200.0f, "Failsafe (seconds, 0 = none) %.0f");
    BeginField();
    if (edited) {
      stage.failsafe = failsafe;
    }
    EndField(edited);
    // The nodes.
    for (int section = 0; section < 2; ++section) {
      ImGui::SeparatorText(kSections[section]);
      ImGui::PushID(section);
      DrawNodes(section == 0 ? stage.enter : stage.ready, section, {}, 0);
      ImGui::PopID();
    }
    // Add: inside the selected container, after the selected node, or at the end of "Then".
    if (EdBeginCombo("##addnode", ICON_PLUS " Add a node")) {
      std::string family;
      for (const MissionNodeType& t : MissionNodeTypes()) {
        if (t.family != family) {
          family = t.family;
          ImGui::SeparatorText(family.c_str());
        }
        if (ImGui::Selectable(t.title.c_str())) {
          Mission before = m;
          MissionNode* selected = NodeAt(m, mSection, mPath);
          const MissionNodeType* selectedType = selected != nullptr ? FindMissionNodeType(selected->type) : nullptr;
          if (selected != nullptr && selectedType != nullptr && selectedType->container) {
            selected->children.push_back(NewMissionNode(t.id));
            mPath.push_back(static_cast<int>(selected->children.size()) - 1);
          } else if (std::vector<MissionNode>* list = ListOf(m, mSection, mPath)) {
            list->insert(list->begin() + mPath.back() + 1, NewMissionNode(t.id));
            ++mPath.back();
          } else {
            m.stages[static_cast<std::size_t>(mStage)].ready.push_back(NewMissionNode(t.id));
            mSection = 1;
            mPath = {static_cast<int>(m.stages[static_cast<std::size_t>(mStage)].ready.size()) - 1};
          }
          Edited(std::move(before));
        }
      }
      ImGui::EndCombo();
    }
    MissionNode* node = NodeAt(m, mSection, mPath);
    if (node != nullptr) {
      ImGui::SameLine();
      if (ImGui::SmallButton("Up") && mPath.back() > 0) {
        Mission before = m;
        std::vector<MissionNode>* list = ListOf(m, mSection, mPath);
        std::swap((*list)[static_cast<std::size_t>(mPath.back())], (*list)[static_cast<std::size_t>(mPath.back() - 1)]);
        --mPath.back();
        Edited(std::move(before));
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Down")) {
        std::vector<MissionNode>* list = ListOf(m, mSection, mPath);
        if (mPath.back() + 1 < static_cast<int>(list->size())) {
          Mission before = m;
          list = ListOf(m, mSection, mPath);
          std::swap(
            (*list)[static_cast<std::size_t>(mPath.back())], (*list)[static_cast<std::size_t>(mPath.back() + 1)]
          );
          ++mPath.back();
          Edited(std::move(before));
        }
      }
      ImGui::SameLine();
      if (ImGui::SmallButton(ICON_TRASH)) {
        Mission before = m;
        std::vector<MissionNode>* list = ListOf(m, mSection, mPath);
        list->erase(list->begin() + mPath.back());
        mPath.clear();
        Edited(std::move(before));
      }
      node = NodeAt(m, mSection, mPath);
    }
    if (node != nullptr) {
      ImGui::SeparatorText("Settings");
      DrawParams(*node, facts);
    }
    // The mission's findings (the Check lists them too).
    const std::vector<MissionProblem> problems = CheckMission(m, facts);
    if (!problems.empty()) {
      ImGui::SeparatorText("Findings");
      for (const MissionProblem& p : problems) {
        ImGui::TextColored(
          p.level == 'E' ? ImVec4(1.0f, 0.45f, 0.4f, 1.0f) : ImVec4(1.0f, 0.8f, 0.35f, 1.0f),
          "%s%s",
          p.stage > 0 ? ("stage " + std::to_string(p.stage) + ": ").c_str() : "",
          p.text.c_str()
        );
      }
    }
    ImGui::End();
  }

  void EdMissionPanel::DrawStringsPanel(
    bool& open,
    const bool mapOpen
  )
  {
    if (!ImGui::Begin(Panel("Strings###MissionStrings"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to write its dialogues.");
      ImGui::End();
      return;
    }
    Mission& m = mDocument.EditMission();
    for (std::size_t d = 0; d < m.dialogues.size(); ++d) {
      const std::string label =
        m.dialogues[d].name + "  (" + std::to_string(m.dialogues[d].lines.size()) + " lines)##d" + std::to_string(d);
      if (ImGui::Selectable(label.c_str(), mDialogue == static_cast<int>(d))) {
        mDialogue = static_cast<int>(d);
      }
    }
    if (ImGui::SmallButton(ICON_PLUS " Dialogue")) {
      Mission before = m;
      MissionDialogue dialogue;
      dialogue.name = "Dialogue" + std::to_string(m.dialogues.size() + 1);
      dialogue.lines.push_back({"", "", 5.0});
      m.dialogues.push_back(dialogue);
      mDialogue = static_cast<int>(m.dialogues.size()) - 1;
      Edited(std::move(before));
    }
    if (mDialogue < 0 || mDialogue >= static_cast<int>(m.dialogues.size())) {
      ImGui::End();
      return;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_TRASH " Dialogue")) {
      Mission before = m;
      m.dialogues.erase(m.dialogues.begin() + mDialogue);
      mDialogue = std::max(0, mDialogue - 1);
      Edited(std::move(before));
      ImGui::End();
      return;
    }
    MissionDialogue& dialogue = m.dialogues[static_cast<std::size_t>(mDialogue)];
    RowLabel("Name");
    ImGui::SetNextItemWidth(-1.0f);
    bool edited = TextField("##dialoguename", dialogue.name);
    BeginField();
    EndField(edited);
    int removeLine = -1;
    for (std::size_t l = 0; l < dialogue.lines.size(); ++l) {
      ImGui::PushID(static_cast<int>(l));
      MissionDialogueLine& line = dialogue.lines[l];
      ImGui::SeparatorText(("Line " + std::to_string(l + 1)).c_str());
      RowLabel("Speaker");
      ImGui::SetNextItemWidth(-1.0f);
      edited = TextField("##speaker", line.speaker);
      BeginField();
      EndField(edited);
      RowLabel("Text");
      ImGui::SetNextItemWidth(-1.0f);
      edited = TextField("##text", line.text);
      BeginField();
      EndField(edited);
      float seconds = static_cast<float>(line.seconds);
      ImGui::SetNextItemWidth(-ImGui::GetFrameHeight() * 1.5f);
      edited = FillDragFloat("##seconds", &seconds, 0.1f, 0.0f, 60.0f, "Shown for %.1f s");
      BeginField();
      if (edited) {
        line.seconds = seconds;
      }
      EndField(edited);
      ImGui::SameLine();
      if (ImGui::SmallButton(ICON_TRASH)) {
        removeLine = static_cast<int>(l);
      }
      ImGui::PopID();
    }
    if (removeLine >= 0) {
      Mission before = m;
      dialogue.lines.erase(dialogue.lines.begin() + removeLine);
      Edited(std::move(before));
    }
    if (ImGui::SmallButton(ICON_PLUS " Line")) {
      Mission before = m;
      dialogue.lines.push_back({"", "", 5.0});
      Edited(std::move(before));
    }
    ImGui::End();
  }
} // namespace faf::editor
