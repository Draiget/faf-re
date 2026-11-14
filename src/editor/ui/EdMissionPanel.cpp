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

    /** A combo over names; true when one was picked. */
    bool NameCombo(
      const char* id,
      std::string& value,
      const std::vector<std::string>& names
    )
    {
      bool picked = false;
      if (EdBeginCombo(id, value.empty() ? "(choose)" : value.c_str())) {
        for (const std::string& name : names) {
          if (ImGui::Selectable(name.c_str(), name == value)) {
            value = name;
            picked = true;
          }
        }
        ImGui::EndCombo();
      }
      return picked;
    }

    /** Checkboxes for a set of names (in rows of three); true when one changed. */
    bool NameSet(
      const char* id,
      std::vector<std::string>& set,
      const std::vector<std::string>& names
    )
    {
      bool changed = false;
      ImGui::PushID(id);
      const float column = ImGui::GetContentRegionAvail().x / 3.0f;
      for (std::size_t i = 0; i < names.size(); ++i) {
        if (i % 3 != 0) {
          ImGui::SameLine(column * static_cast<float>(i % 3));
        }
        const auto at = std::find(set.begin(), set.end(), names[i]);
        bool on = at != set.end();
        if (ImGui::Checkbox(names[i].c_str(), &on)) {
          if (on) {
            set.push_back(names[i]);
          } else {
            set.erase(at);
          }
          changed = true;
        }
      }
      ImGui::PopID();
      return changed;
    }
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
      } else if (p.kind == "base") {
        for (const MissionBase& b : m.bases) {
          names.push_back(b.name);
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
    if (mFocusStages) {
      mFocusStages = false;
      ImGui::SetNextWindowFocus();
    }
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
  void EdMissionPanel::DrawRunPanel(
    bool& open,
    const bool mapOpen,
    const bool playing,
    const std::vector<std::string>& newTrace
  )
  {
    // A new play starts a new trace.
    if (playing && !mWasPlaying) {
      mTrace.clear();
    }
    mWasPlaying = playing;
    mTrace.insert(mTrace.end(), newTrace.begin(), newTrace.end());
    if (mTrace.size() > 2000) {
      mTrace.erase(mTrace.begin(), mTrace.begin() + static_cast<std::ptrdiff_t>(mTrace.size() - 2000));
    }
    if (!ImGui::Begin(Panel("Run###MissionRun"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to run its mission.");
      ImGui::End();
      return;
    }
    Mission& m = mDocument.EditMission();
    // Where the play is: the last stage entered.
    int current = 0;
    for (auto it = mTrace.rbegin(); it != mTrace.rend(); ++it) {
      MissionTraceId id;
      if (ParseMissionTrace(*it, id) && id.section.empty()) {
        current = id.stage;
        break;
      }
    }
    if (playing) {
      ImGui::Text(
        "Playing: %s", current > 0 ? ("stage " + std::to_string(current)).c_str() : "the mission hasn't started"
      );
    } else {
      ImGui::TextDisabled(mTrace.empty() ? "No play yet." : "The last play's trace:");
    }
    // Play from a stage.
    const int stages = static_cast<int>(m.stages.size());
    int start = std::clamp(mDocument.PlayStartStage(), 1, std::max(1, stages));
    ImGui::BeginDisabled(playing || stages == 0);
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.45f);
    if (EdBeginCombo("##startstage", ("Stage " + std::to_string(start)).c_str())) {
      for (int i = 1; i <= stages; ++i) {
        const std::string label = std::to_string(i) + "  " + m.stages[static_cast<std::size_t>(i - 1)].name;
        if (ImGui::Selectable(label.c_str(), i == start)) {
          start = i;
          mDocument.SetPlayStartStage(i);
        }
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button(ICON_PLAY " Play from this stage")) {
      mDocument.SetPlayStartStage(start);
      mPlayAsked = true;
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip(
        "Plays the open map with its mission from a copy (test run: every node traced here), starting at "
        "the chosen stage"
      );
    }
    ImGui::Separator();
    // The trace, newest last; a click selects the node in Stages.
    ImGui::BeginChild("##trace", ImVec2(0.0f, 0.0f), false);
    for (std::size_t k = 0; k < mTrace.size(); ++k) {
      MissionTraceId id;
      if (!ParseMissionTrace(mTrace[k], id)) {
        continue;
      }
      std::string text;
      if (id.section.empty()) {
        text = "stage " + std::to_string(id.stage) + " entered";
      } else {
        std::string title = "a node";
        if (id.stage >= 1 && id.stage <= stages) {
          const MissionStage& stage = m.stages[static_cast<std::size_t>(id.stage - 1)];
          const std::vector<MissionNode>* list = id.section == "enter" ? &stage.enter : &stage.ready;
          const MissionNode* node = nullptr;
          for (const int i : id.path) {
            if (list == nullptr || i < 1 || i > static_cast<int>(list->size())) {
              node = nullptr;
              break;
            }
            node = &(*list)[static_cast<std::size_t>(i - 1)];
            list = &node->children;
          }
          if (node != nullptr) {
            const MissionNodeType* t = FindMissionNodeType(node->type);
            title = t != nullptr ? t->title : node->type;
          }
        }
        text = "  " + std::to_string(id.stage) + " " + (id.section == "enter" ? "start" : "then") + ": " + title +
          (id.mark == '!'     ? "  (its trigger fired)"
             : id.mark == '~' ? "  (dropped: the stage had moved on)"
                              : "");
      }
      ImGui::PushID(static_cast<int>(k));
      if (id.mark == '~') {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.35f, 1.0f));
      }
      if (ImGui::Selectable(text.c_str(), false) && id.stage >= 1 && id.stage <= stages) {
        mStage = id.stage - 1;
        mSection = id.section == "enter" ? 0 : 1;
        mPath.clear();
        for (const int i : id.path) {
          mPath.push_back(i - 1);
        }
        mFocusStages = true;
      }
      if (id.mark == '~') {
        ImGui::PopStyleColor();
      }
      ImGui::PopID();
    }
    if (playing && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f) {
      ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
    ImGui::End();
  }
  void EdMissionPanel::DrawBasesPanel(
    bool& open,
    const bool mapOpen
  )
  {
    if (!ImGui::Begin(Panel("Bases###MissionBases"), &open)) {
      ImGui::End();
      return;
    }
    if (!mapOpen) {
      ImGui::TextDisabled("Open a map to give its mission AI bases.");
      ImGui::End();
      return;
    }
    Mission& m = mDocument.EditMission();
    const MissionFacts facts = MissionFactsOf(mDocument);
    // A drag over a number with its undo.
    const auto number =
      [&](const char* id, double& v, const float speed, const float lo, const float hi, const char* format) {
      float x = static_cast<float>(v);
      const bool edited = FillDragFloat(id, &x, speed, lo, hi, format);
      BeginField();
      if (edited) {
        v = x;
      }
      EndField(edited);
    };
    // Three numbers, one per difficulty.
    const auto three = [&](const char* id, std::array<double, 3>& v, const float hi) {
      ImGui::PushID(id);
      const float w = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * 2.0f) / 3.0f;
      static const char* const kDiff[] = {"Easy %.0f", "Normal %.0f", "Hard %.0f"};
      for (int d = 0; d < 3; ++d) {
        if (d > 0) {
          ImGui::SameLine();
        }
        ImGui::SetNextItemWidth(w);
        ImGui::PushID(d);
        number("##d", v[static_cast<std::size_t>(d)], 0.1f, 0.0f, hi, kDiff[d]);
        ImGui::PopID();
      }
      ImGui::PopID();
    };
    // The list of bases.
    for (std::size_t b = 0; b < m.bases.size(); ++b) {
      const std::string label = m.bases[b].name + "  (" + m.bases[b].army + ", " +
        std::to_string(m.bases[b].opai.size()) + " attacks)##b" + std::to_string(b);
      if (ImGui::Selectable(label.c_str(), mBase == static_cast<int>(b))) {
        mBase = static_cast<int>(b);
        mAttack = -1;
      }
    }
    if (ImGui::SmallButton(ICON_PLUS " Base")) {
      Mission before = m;
      std::string army = facts.armies.size() > 1 ? facts.armies[1] : facts.armies.empty() ? "ARMY_2" : facts.armies[0];
      m.bases.push_back(NewMissionBase("Base" + std::to_string(m.bases.size() + 1), army));
      mBase = static_cast<int>(m.bases.size()) - 1;
      mAttack = -1;
      Edited(std::move(before));
    }
    if (ImGui::IsItemHovered()) {
      EdSetTooltip(
        "A BaseManager on an AI army: started by a Start a base node, it spawns (or builds) the army's unit "
        "groups around a marker and sends its attacks"
      );
    }
    if (mBase < 0 || mBase >= static_cast<int>(m.bases.size())) {
      ImGui::End();
      return;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_TRASH " Base")) {
      Mission before = m;
      m.bases.erase(m.bases.begin() + mBase);
      mBase = std::min(mBase, static_cast<int>(m.bases.size()) - 1);
      mAttack = -1;
      Edited(std::move(before));
      ImGui::End();
      return;
    }
    MissionBase& base = m.bases[static_cast<std::size_t>(mBase)];
    ImGui::SeparatorText("Base");
    RowLabel("Name");
    ImGui::SetNextItemWidth(-1.0f);
    bool edited = TextField("##basename", base.name);
    BeginField();
    EndField(edited);
    RowLabel("Army");
    ImGui::SetNextItemWidth(-1.0f);
    {
      std::string army = base.army;
      if (NameCombo("##basearmy", army, facts.armies)) {
        Mission before = mDocument.MissionNow();
        base.army = army;
        Edited(std::move(before));
      }
    }
    RowLabel("Marker");
    ImGui::SetNextItemWidth(-1.0f);
    {
      std::string marker = base.marker;
      if (NameCombo("##basemarker", marker, facts.markers)) {
        Mission before = mDocument.MissionNow();
        base.marker = marker;
        Edited(std::move(before));
      }
    }
    RowLabel("Radius");
    ImGui::SetNextItemWidth(-1.0f);
    number("##radius", base.radius, 0.5f, 5.0f, 500.0f, "%.0f");
    const auto toggle = [&](const char* label, bool& v, const char* tip) {
      bool on = v;
      if (ImGui::Checkbox(label, &on)) {
        Mission before = mDocument.MissionNow();
        v = on;
        Edited(std::move(before));
      }
      if (ImGui::IsItemHovered()) {
        EdSetTooltip("%s", tip);
      }
    };
    toggle(
      "Starts empty", base.startEmpty, "Its engineers build the groups (else every group is spawned when it starts)"
    );
    ImGui::SameLine();
    toggle("Groups per difficulty", base.diff, "Each group has _D1, _D2 and _D3 versions (InitializeDifficultyTables)");
    ImGui::SameLine();
    toggle("Always assist", base.alwaysAssist, "Engineers assist construction whenever they're idle");
    ImGui::SeparatorText("Build groups");
    int removeGroup = -1;
    const auto groups = facts.groups.find(base.army);
    std::vector<std::string> groupNames;
    if (groups != facts.groups.end()) {
      for (const std::string& g : groups->second) {
        // A per-difficulty group is offered by its base name.
        if (base.diff && g.size() > 3 && g.compare(g.size() - 3, 2, "_D") == 0) {
          const std::string stem = g.substr(0, g.size() - 3);
          if (std::find(groupNames.begin(), groupNames.end(), stem) == groupNames.end()) {
            groupNames.push_back(stem);
          }
        } else if (!base.diff) {
          groupNames.push_back(g);
        }
      }
    }
    for (std::size_t g = 0; g < base.groups.size(); ++g) {
      ImGui::PushID(static_cast<int>(g));
      const float w = ImGui::GetContentRegionAvail().x;
      ImGui::SetNextItemWidth(w * 0.55f);
      std::string name = base.groups[g].name;
      if (NameCombo("##group", name, groupNames)) {
        Mission before = mDocument.MissionNow();
        base.groups[g].name = name;
        Edited(std::move(before));
      }
      ImGui::SameLine();
      ImGui::SetNextItemWidth(w * 0.45f - ImGui::GetFrameHeight() * 1.5f);
      number("##priority", base.groups[g].priority, 1.0f, 0.0f, 1000.0f, "Priority %.0f");
      ImGui::SameLine();
      if (ImGui::SmallButton(ICON_TRASH)) {
        removeGroup = static_cast<int>(g);
      }
      ImGui::PopID();
    }
    if (removeGroup >= 0) {
      Mission before = m;
      base.groups.erase(base.groups.begin() + removeGroup);
      Edited(std::move(before));
    }
    if (ImGui::SmallButton(ICON_PLUS " Group")) {
      Mission before = m;
      base.groups.push_back(
        {groupNames.empty() ? std::string() : groupNames.front(),
         100.0 - 10.0 * static_cast<double>(base.groups.size())}
      );
      Edited(std::move(before));
    }
    if (groupNames.empty()) {
      ImGui::SameLine();
      ImGui::TextDisabled(base.diff ? "(the army has no _D1.._D3 groups)" : "(the army has no unit groups)");
    }
    ImGui::SeparatorText("Engineers");
    RowLabel("Engineers");
    three("##engineers", base.engineers, 50.0f);
    RowLabel("Assisting");
    three("##assist", base.assist, 50.0f);
    RowLabel("Building at once");
    ImGui::SetNextItemWidth(-1.0f);
    number("##maxbuild", base.maxBuild, 0.1f, 0.0f, 50.0f, base.maxBuild > 0.0 ? "%.0f" : "no limit");
    RowLabel("Support ACUs");
    ImGui::SetNextItemWidth(-1.0f);
    number("##sacus", base.supportAcus, 0.1f, 0.0f, 20.0f, "%.0f");
    if (ImGui::TreeNode("Switches")) {
      ImGui::TextDisabled("Turned on");
      const auto set = [&](const char* id, std::vector<std::string>& v, const std::vector<std::string>& names) {
        std::vector<std::string> copy = v;
        if (NameSet(id, copy, names)) {
          Mission before = mDocument.MissionNow();
          v = std::move(copy);
          Edited(std::move(before));
        }
      };
      set("on", base.switchOn, MissionBaseActive());
      ImGui::TextDisabled("Turned off");
      set("off", base.switchOff, MissionBaseActive());
      ImGui::TextDisabled("Never builds");
      set("nobuild", base.noBuild, MissionBaseBuild());
      ImGui::TreePop();
    }
    // The attacks.
    ImGui::SeparatorText("Attacks");
    for (std::size_t k = 0; k < base.opai.size(); ++k) {
      const std::string label = base.opai[k].name + "  (" + base.opai[k].ptype + ")##a" + std::to_string(k);
      if (ImGui::Selectable(label.c_str(), mAttack == static_cast<int>(k))) {
        mAttack = static_cast<int>(k);
      }
    }
    if (ImGui::SmallButton(ICON_PLUS " Attack")) {
      Mission before = m;
      MissionOpAI o;
      o.name = base.name + "_Attack" + std::to_string(base.opai.size() + 1);
      o.children = {MissionOpAIChildren(o.ptype).front()};
      if (!facts.chains.empty()) {
        o.chains.push_back(facts.chains.front());
      }
      base.opai.push_back(o);
      mAttack = static_cast<int>(base.opai.size()) - 1;
      Edited(std::move(before));
    }
    if (mAttack < 0 || mAttack >= static_cast<int>(base.opai.size())) {
      ImGui::End();
      return;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_TRASH " Attack")) {
      Mission before = m;
      base.opai.erase(base.opai.begin() + mAttack);
      mAttack = std::min(mAttack, static_cast<int>(base.opai.size()) - 1);
      Edited(std::move(before));
      ImGui::End();
      return;
    }
    MissionOpAI& o = base.opai[static_cast<std::size_t>(mAttack)];
    ImGui::PushID("attack");
    RowLabel("Name");
    ImGui::SetNextItemWidth(-1.0f);
    edited = TextField("##name", o.name);
    BeginField();
    EndField(edited);
    RowLabel("Kind");
    ImGui::SetNextItemWidth(-1.0f);
    {
      std::string ptype = o.ptype;
      if (NameCombo("##ptype", ptype, MissionOpAITypes()) && ptype != o.ptype) {
        Mission before = mDocument.MissionNow();
        o.ptype = ptype;
        o.children = {MissionOpAIChildren(ptype).front()};
        Edited(std::move(before));
      }
    }
    if (ImGui::TreeNodeEx("Platoon kinds", ImGuiTreeNodeFlags_DefaultOpen)) {
      if (std::vector<std::string> copy = o.children; NameSet("children", copy, MissionOpAIChildren(o.ptype))) {
        Mission before = mDocument.MissionNow();
        o.children = std::move(copy);
        Edited(std::move(before));
      }
      ImGui::TreePop();
    }
    RowLabel("Units");
    three("##qty", o.qty, 100.0f);
    RowLabel("Orders");
    ImGui::SetNextItemWidth(-1.0f);
    {
      std::string master = o.master;
      if (NameCombo("##master", master, MissionOpAIMasters())) {
        Mission before = mDocument.MissionNow();
        o.master = master;
        Edited(std::move(before));
      }
    }
    if (o.master != "default") {
      ImGui::TextDisabled(o.master == "patrol chain picker" ? "Chains (one picked per platoon)" : "Chain");
      if (o.master == "patrol chain picker") {
        if (std::vector<std::string> copy = o.chains; NameSet("chains", copy, facts.chains)) {
          Mission before = mDocument.MissionNow();
          o.chains = std::move(copy);
          Edited(std::move(before));
        }
      } else {
        std::string chain = o.chains.empty() ? std::string() : o.chains.front();
        ImGui::SetNextItemWidth(-1.0f);
        if (NameCombo("##chain", chain, facts.chains)) {
          Mission before = mDocument.MissionNow();
          o.chains = {chain};
          Edited(std::move(before));
        }
      }
      if (facts.chains.empty()) {
        ImGui::TextDisabled("(the map has no marker chains)");
      }
    }
    RowLabel("Priority");
    ImGui::SetNextItemWidth(-1.0f);
    number("##priority", o.priority, 1.0f, 0.0f, 1000.0f, "%.0f");
    RowLabel("Lock");
    ImGui::SetNextItemWidth(o.lock == "None" ? -1.0f : ImGui::GetContentRegionAvail().x * 0.5f);
    {
      std::string lock = o.lock;
      if (NameCombo("##lock", lock, MissionOpAILocks())) {
        Mission before = mDocument.MissionNow();
        o.lock = lock;
        Edited(std::move(before));
      }
    }
    if (o.lock != "None") {
      ImGui::SameLine();
      ImGui::SetNextItemWidth(-1.0f);
      number(
        "##locksecs",
        o.lockSecs,
        0.5f,
        0.0f,
        o.lock == "DeathRatio" ? 100.0f : 3600.0f,
        o.lock == "DeathRatio" ? "%.0f%% lost" : "%.0f s"
      );
    }
    for (int slot = 0; slot < 2; ++slot) {
      ImGui::PushID(slot);
      const std::size_t i = static_cast<std::size_t>(slot);
      RowLabel(slot == 0 ? "Builds when" : "and when");
      ImGui::SetNextItemWidth(-1.0f);
      std::string cond = o.cond[i];
      if (NameCombo("##cond", cond, MissionOpAIConditions())) {
        Mission before = mDocument.MissionNow();
        o.cond[i] = cond;
        Edited(std::move(before));
      }
      if (o.cond[i] == "humans have units") {
        RowLabel("At least");
        three("##condn", o.condCount[i], 1000.0f);
      } else if (o.cond[i] == "stage reached") {
        RowLabel("Stage");
        ImGui::SetNextItemWidth(-1.0f);
        number("##stage", o.condStage[i], 0.1f, 1.0f, 50.0f, "%.0f");
      } else if (o.cond[i] == "flag is set") {
        RowLabel("Flag");
        ImGui::SetNextItemWidth(-1.0f);
        edited = TextField("##flag", o.condFlag[i]);
        BeginField();
        EndField(edited);
      }
      ImGui::PopID();
    }
    ImGui::PopID();
    ImGui::End();
  }
} // namespace faf::editor
