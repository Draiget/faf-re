// The Adaptive Map window (View > Adaptive Map): an adaptive map's setup by what the player picks in the lobby (user ask
// 2026-11-11: the old panel showed files and mechanics; make it easy to understand and edit). Left, the lobby's options;
// right, the picked one: its name and description, its choices with what each puts on the map, and every change made
// in place (_options.lua, _tables.lua and the unit groups written together, each an undo step). doc/EdAdaptiveModel.

#include <algorithm>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdAdaptiveModel.h"
#include "editor/doc/EdAdaptiveTables.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnitWrecks.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdFonts.h"
#include "editor/ui/EdHelp.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    const ImVec4 kGood(0.45f, 0.80f, 0.45f, 1.0f);
    const ImVec4 kWarn(0.95f, 0.75f, 0.30f, 1.0f);
    const ImVec4 kDim(0.62f, 0.66f, 0.72f, 1.0f);

    int GrowText(ImGuiInputTextCallbackData* const data)
    {
      if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* const text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<std::size_t>(data->BufTextLen));
        data->Buf = text->data();
      }
      return 0;
    }

    /** A text field on a std::string; true when an edit ended (Enter or leaving it) with a change. */
    bool EditText(const char* const id, std::string& text, const float width, const bool multiline = false)
    {
      if (multiline) {
        ImGui::InputTextMultiline(id, text.data(), text.capacity() + 1, ImVec2(width, ImGui::GetTextLineHeight() * 3.2f),
                                  ImGuiInputTextFlags_CallbackResize, &GrowText, &text);
      } else {
        ImGui::SetNextItemWidth(width);
        ImGui::InputText(id, text.data(), text.capacity() + 1, ImGuiInputTextFlags_CallbackResize, &GrowText, &text);
      }
      return ImGui::IsItemDeactivatedAfterEdit();
    }

    /** A kind's tag as the list shows it. */
    const char* KindTag(const AdaptiveOption& option)
    {
      switch (option.kind) {
        case AdaptiveOption::Kind::Mexes:
          return "mexes";
        case AdaptiveOption::Kind::Hydros:
          return "hydros";
        case AdaptiveOption::Kind::UnitLevels:
          return option.loop.wreck ? "wrecks" : "units";
        default:
          return "script";
      }
    }

    ImU32 KindColour(const AdaptiveOption& option)
    {
      switch (option.kind) {
        case AdaptiveOption::Kind::Mexes:
          return IM_COL32(110, 190, 90, 255);
        case AdaptiveOption::Kind::Hydros:
          return IM_COL32(90, 170, 230, 255);
        case AdaptiveOption::Kind::UnitLevels:
          return IM_COL32(220, 150, 80, 255);
        default:
          return IM_COL32(150, 150, 160, 255);
      }
    }

    /** A small coloured tag. */
    void Tag(const char* const text, const ImU32 colour)
    {
      const ImVec2 size = ImGui::CalcTextSize(text);
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const float pad = 4.0f;
      ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + size.x + pad * 2.0f, at.y + size.y + 2.0f), (colour & 0x00FFFFFF) | 0x50000000, 3.0f);
      ImGui::GetWindowDrawList()->AddText(ImVec2(at.x + pad, at.y + 1.0f), colour, text);
      ImGui::Dummy(ImVec2(size.x + pad * 2.0f, size.y + 2.0f));
    }

    void TakeOut(std::vector<std::vector<std::string>>& lists, const std::vector<std::string>& names)
    {
      for (std::vector<std::string>& list : lists) {
        list.erase(std::remove_if(list.begin(), list.end(),
                                  [&](const std::string& name) { return std::find(names.begin(), names.end(), name) != names.end(); }),
                   list.end());
      }
    }

    /** The group named `name` anywhere in the tree, and its path. */
    const UnitGroup* FindGroup(const UnitGroup& root, const std::string& name, std::vector<std::string>& path)
    {
      for (const UnitGroup& child : root.groups) {
        path.push_back(child.name);
        if (child.name == name) {
          return &child;
        }
        if (const UnitGroup* const found = FindGroup(child, name, path); found != nullptr) {
          return found;
        }
        path.pop_back();
      }
      return nullptr;
    }
  } // namespace

  void EdShell::DrawAdaptiveWindow()
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.66f, viewport->WorkSize.y * 0.76f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(viewport->GetCenter(), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    if (std::exchange(mFocusAdaptiveWindow, false)) {
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin("Adaptive Map###AdaptiveMap", &mShowAdaptiveWindow, ImGuiWindowFlags_NoCollapse)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("No map open.");
      ImGui::End();
      return;
    }
    if (!mDocument.Adaptive()) {
      ImGui::TextWrapped("This map isn't adaptive yet. Adaptive maps (FAF's \"Ultimate maps\" script) spawn each player's resources "
                         "only with that player, and let the lobby add groups of mexes, hydrocarbons, wrecks and units.");
      DrawAdaptivePanel(); // its "Make this map adaptive"
      ImGui::End();
      return;
    }
    AdaptiveTables tables;
    std::string error;
    if (!ParseAdaptiveTables(mDocument.TablesText(), tables, error)) {
      ImGui::TextColored(kWarn, "_tables.lua doesn't read: %s", error.c_str());
      if (ImGui::Button("Open it in the Script Editor")) {
        ShowLuaFile(2);
      }
      ImGui::End();
      return;
    }
    const std::string& script = mDocument.Script();
    const std::string optionsText = mDocument.OptionsText();
    const std::vector<LobbyOptionInfo> lobby = ParseLobbyOptions(optionsText);
    const bool adaptiveScript = !AdaptiveTablesPath(script).empty();
    const std::vector<AdaptiveOption> options = AdaptiveOptionsOf(script, lobby, tables, adaptiveScript);

    // What the buttons take: the selected mass and hydrocarbon markers, and the selected units by army.
    std::vector<std::string> selectedMass;
    std::vector<std::string> selectedHydro;
    for (const SaveEntry& marker : mTools.MarkerSelection()) {
      const std::string type = MarkerTypeOf(marker);
      if (type == "Mass" && !AdaptiveEntry(marker.name, false).empty()) {
        selectedMass.push_back(marker.name);
      } else if (type == "Hydrocarbon" && !AdaptiveEntry(marker.name, true).empty()) {
        selectedHydro.push_back(marker.name);
      }
    }
    const auto selectedUnitsOf = [&](const std::string& army) {
      std::vector<std::string> names;
      for (const auto& [owner, name] : mTools.UnitSelection()) {
        if (army.empty() || owner == army) {
          names.push_back(name);
        }
      }
      return names;
    };
    const auto armyTree = [&](const std::string& army) {
      UnitGroup root;
      for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
        std::string parseError;
        if (entry.name == army) {
          (void)ParseUnitGroup(entry.Get("Units"), root, parseError);
        }
      }
      return root;
    };

    // The status line: the three files, each a click from its text.
    {
      const auto file = [&](const char* const name, const bool good, const char* const goodText, const char* const badText, const int which) {
        ImGui::PushID(name);
        ImGui::TextColored(good ? kGood : kWarn, "%s %s", good ? "\xE2\x97\x8F" : "\xE2\x97\x8B", name);
        ImGui::SetItemTooltip("%s\nClick to see its text in the Script Editor", good ? goodText : badText);
        if (ImGui::IsItemClicked()) {
          ShowLuaFile(which);
        }
        ImGui::SameLine(0.0f, 18.0f);
        ImGui::PopID();
      };
      file("_tables.lua", true, "The adaptive tables: which resources spawn with which player and option.", "", 2);
      file("_script.lua", adaptiveScript, "The adaptive script, which reads the tables.",
           "The script doesn't read the tables: copy an adaptive map's _script.lua into this map's folder.", 0);
      file("_options.lua", !optionsText.empty(), "The lobby's options.", "No lobby options yet: the first option written makes the file.", 1);
      ImGui::NewLine();
    }
    ImGui::Separator();

    // Two columns: the options, and the picked one.
    if (!ImGui::BeginTable("##adaptive", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail())) {
      ImGui::End();
      return;
    }
    ImGui::TableSetupColumn("options", ImGuiTableColumnFlags_WidthFixed, std::max(ImGui::GetContentRegionAvail().x * 0.28f, 240.0f));
    ImGui::TableSetupColumn("edit", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    if (mAdaptivePick.empty() && !options.empty()) {
      mAdaptivePick = options.front().key;
    }
    if (ImGui::BeginChild("##list", ImVec2(0.0f, 0.0f))) {
      ImGui::TextDisabled("LOBBY OPTIONS");
      for (const AdaptiveOption& option : options) {
        ImGui::PushID(option.key.c_str());
        const bool picked = mAdaptivePick == option.key;
        const float rowHeight = ImGui::GetTextLineHeightWithSpacing() * 2.0f + 4.0f;
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (ImGui::Selectable("##pick", picked, 0, ImVec2(0.0f, rowHeight))) {
          mAdaptivePick = option.key;
        }
        ImGui::SetCursorScreenPos(ImVec2(at.x + 4.0f, at.y + 2.0f));
        if (gBoldFont != nullptr) {
          ImGui::PushFont(gBoldFont, 0.0f);
        }
        ImGui::TextUnformatted(option.title.c_str());
        if (gBoldFont != nullptr) {
          ImGui::PopFont();
        }
        ImGui::SameLine();
        Tag(KindTag(option), KindColour(option));
        ImGui::SetCursorScreenPos(ImVec2(at.x + 4.0f, at.y + 2.0f + ImGui::GetTextLineHeightWithSpacing()));
        if (option.lobby < 0) {
          ImGui::TextColored(kWarn, "not in the lobby");
        } else {
          const LobbyOptionInfo& info = lobby[static_cast<std::size_t>(option.lobby)];
          const int d = info.defaultIndex;
          ImGui::TextColored(kDim, "%zu choices, default \"%s\"%s", info.values.size(),
                             d >= 1 && d <= static_cast<int>(info.values.size()) ? info.values[static_cast<std::size_t>(d - 1)].text.c_str() : "?",
                             option.scriptReads ? "" : ", not in the map's script");
        }
        ImGui::SetCursorScreenPos(ImVec2(at.x, at.y + rowHeight + ImGui::GetStyle().ItemSpacing.y));
        ImGui::PopID();
      }
      if (options.empty()) {
        ImGui::TextDisabled("None yet.");
      }
      ImGui::Spacing();
      if (ImGui::Button("+ New lobby option", ImVec2(-1.0f, 0.0f))) {
        ImGui::OpenPopup("##new");
      }
      if (ImGui::BeginPopup("##new")) {
        ImGui::TextDisabled("Extra resources the player can turn on");
        for (const OptionTable& table : KnownOptionTables()) {
          const std::string key = AdaptiveOptionKey(table.name);
          if (std::any_of(options.begin(), options.end(), [&](const AdaptiveOption& o) { return o.key == key; })) {
            continue;
          }
          const std::vector<std::string>& wanted = table.hydro ? selectedHydro : selectedMass;
          if (ImGui::MenuItem(table.label, wanted.empty() ? nullptr : "the selected")) {
            AdaptiveTables changed = tables;
            for (auto& [name, groups] : changed.options) {
              TakeOut(groups, wanted);
            }
            changed.options.emplace_back(table.name, std::vector<std::vector<std::string>>{wanted});
            mDocument.SetTablesText(WithAdaptiveTables(mDocument.TablesText(), changed));
            LobbyOptionInfo info;
            info.key = key;
            info.label = table.label;
            info.help = std::string("Adds ") + (table.hydro ? "hydrocarbons" : "mexes") + " to the map.";
            info.defaultIndex = 1;
            info.values = {NextLevelValue(info, "none")};
            info.values.push_back(NextLevelValue(info, "group 1"));
            mDocument.SetOptionsText(WithOption(mDocument.OptionsText(), info));
            mAdaptivePick = key;
          }
          ImGui::SetItemTooltip("%s: a lobby option whose choices add groups of %s (its table %s)%s", table.label, table.hydro ? "hydrocarbons" : "mexes",
                                table.name, wanted.empty() ? "" : "; the selected ones are its first group");
        }
        ImGui::EndPopup();
      }
      ImGui::Spacing();
      ImGui::Separator();
      ImGui::TextDisabled("ALSO");
      if (ImGui::Selectable("Players' resources and crazyrush", mAdaptivePick == "#players")) {
        mAdaptivePick = "#players";
      }
      ImGui::SetItemTooltip("Which resources spawn only with which player, the most players, and the crazyrush lists");
    }
    ImGui::EndChild();

    ImGui::TableSetColumnIndex(1);
    if (ImGui::BeginChild("##edit", ImVec2(0.0f, 0.0f))) {
      const AdaptiveOption* option = nullptr;
      for (const AdaptiveOption& o : options) {
        if (o.key == mAdaptivePick) {
          option = &o;
        }
      }
      if (mAdaptivePick == "#players") {
        DrawAdaptivePanel();
      } else if (option == nullptr) {
        ImGui::TextDisabled("Pick an option on the left, or make a new one.");
      } else {
        DrawAdaptiveOption(*option, lobby, tables, selectedMass, selectedHydro, selectedUnitsOf(option->loop.army), armyTree(option->loop.army));
      }
    }
    ImGui::EndChild();
    ImGui::EndTable();
    ImGui::End();
  }

  void EdShell::DrawAdaptiveOption(const AdaptiveOption& option, const std::vector<LobbyOptionInfo>& lobby, const AdaptiveTables& tables,
                                   const std::vector<std::string>& selectedMass, const std::vector<std::string>& selectedHydro,
                                   const std::vector<std::string>& selectedUnits, const UnitGroup& army)
  {
    const bool table = option.kind == AdaptiveOption::Kind::Mexes || option.kind == AdaptiveOption::Kind::Hydros;
    const bool levels = option.kind == AdaptiveOption::Kind::UnitLevels;
    const bool hydro = option.kind == AdaptiveOption::Kind::Hydros;
    const std::vector<std::string>& selectedResources = hydro ? selectedHydro : selectedMass;
    // The table's groups as they are.
    std::vector<std::vector<std::string>> groups;
    for (const auto& [name, its] : tables.options) {
      if (name == option.table) {
        groups = its;
      }
    }
    // The option as the lobby has it, or as it would be written (none, then one choice per group or level).
    LobbyOptionInfo info;
    if (option.lobby >= 0) {
      info = lobby[static_cast<std::size_t>(option.lobby)];
    } else {
      info.key = option.key;
      info.label = option.title;
      info.defaultIndex = 1;
      info.values = {NextLevelValue(info, "disabled")};
    }
    // The level groups that exist (for a loop): <prefix>from, from+1, ...
    int highestLevel = 0;
    if (levels) {
      for (int k = option.loop.from; k < option.loop.from + 32; ++k) {
        std::vector<std::string> path;
        if (FindGroup(army, option.loop.prefix + std::to_string(k), path) != nullptr) {
          highestLevel = k;
        }
      }
    }
    // Writes the option back, as one undo step.
    const auto writeOption = [&](const LobbyOptionInfo& changed) { mDocument.SetOptionsText(WithOption(mDocument.OptionsText(), changed)); };
    const auto writeTable = [&](const std::vector<std::vector<std::string>>& changedGroups) {
      AdaptiveTables changed = tables;
      bool found = false;
      for (auto& [name, its] : changed.options) {
        if (name == option.table) {
          its = changedGroups;
          found = true;
        }
      }
      if (!found) {
        changed.options.emplace_back(option.table, changedGroups);
      }
      mDocument.SetTablesText(WithAdaptiveTables(mDocument.TablesText(), changed));
    };

    // The title, its kind, the delete.
    if (gBoldFont != nullptr) {
      ImGui::PushFont(gBoldFont, 0.0f);
    }
    ImGui::TextUnformatted(option.title.c_str());
    if (gBoldFont != nullptr) {
      ImGui::PopFont();
    }
    ImGui::SameLine();
    Tag(KindTag(option), KindColour(option));
    ImGui::SameLine();
    ImGui::TextDisabled("key %s", option.key.c_str());
    {
      const char* const label = option.lobby >= 0 ? "Delete the option" : "";
      if (option.lobby >= 0) {
        ImGui::SameLine(ImGui::GetContentRegionAvail().x + ImGui::GetCursorPosX() - ImGui::CalcTextSize(label).x - ImGui::GetStyle().FramePadding.x * 2.0f);
        if (ImGui::SmallButton(label)) {
          ImGui::OpenPopup("##delete");
        }
      }
    }
    if (ImGui::BeginPopup("##delete")) {
      ImGui::TextUnformatted(("Delete \"" + option.title + "\" from the lobby?").c_str());
      if (table) {
        ImGui::TextDisabled("Its %zu groups' %s then spawn in every game (they leave the table).", groups.size(), hydro ? "hydrocarbons" : "mexes");
        if (ImGui::Button("Delete the option")) {
          mDocument.SetOptionsText(WithoutLobbyOption(mDocument.OptionsText(), option.key));
          writeTable({});
          ImGui::CloseCurrentPopup();
        }
      } else if (levels) {
        ImGui::TextDisabled("Without it, the script never makes its levels: their units are kept, unused, unless deleted too.");
        if (ImGui::Button("Delete the option")) {
          mDocument.SetOptionsText(WithoutLobbyOption(mDocument.OptionsText(), option.key));
          ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Delete it and its levels' units")) {
          mDocument.SetOptionsText(WithoutLobbyOption(mDocument.OptionsText(), option.key));
          EdTools::UnitGroupAsk ask;
          ask.army = option.loop.army;
          ask.removeGroup = true;
          for (int k = option.loop.from; k <= highestLevel; ++k) {
            std::vector<std::string> path;
            if (FindGroup(army, option.loop.prefix + std::to_string(k), path) != nullptr) {
              (ask.path.empty() ? ask.path : ask.morePaths.emplace_back()) = path;
            }
          }
          if (!ask.path.empty()) {
            mTools.AskUnitGroup(std::move(ask));
          }
          ImGui::CloseCurrentPopup();
        }
      } else {
        ImGui::TextDisabled("The script then reads its default (as if the lobby had no such option).");
        if (ImGui::Button("Delete the option")) {
          mDocument.SetOptionsText(WithoutLobbyOption(mDocument.OptionsText(), option.key));
          ImGui::CloseCurrentPopup();
        }
      }
      ImGui::SameLine();
      if (ImGui::Button("Cancel")) {
        ImGui::CloseCurrentPopup();
      }
      ImGui::EndPopup();
    }

    // What it does, in a sentence.
    ImGui::PushTextWrapPos(0.0f);
    if (table) {
      ImGui::TextColored(kDim, "Each choice adds one more group of %s to the ones before it. Select %s markers in the view to put them in a "
                               "choice's group.", hydro ? "hydrocarbons" : "mexes", hydro ? "hydrocarbon" : "mass");
    } else if (levels) {
      ImGui::TextColored(kDim, "Each choice adds one more level of %s (the group %s<n> of %s) to the ones before it. Select units of %s in the "
                               "view to put them in a level.", option.loop.wreck ? "wrecks" : "units", option.loop.prefix.c_str(),
                         option.loop.army.c_str(), option.loop.army.c_str());
    } else {
      ImGui::TextColored(kDim, "%s", option.scriptReads ? "The map's script reads this option; what each choice makes is read from the script."
                                                        : "The map's script doesn't read this option (the game's own code may: FAF reads some "
                                                          "lobby options itself, such as natural reclaim values).");
    }
    ImGui::PopTextWrapPos();

    // Mismatches between the files, each with its fix.
    if (option.lobby < 0) {
      ImGui::TextColored(kWarn, "The lobby doesn't offer it yet, so none of its choices can be picked in a game.");
      ImGui::SameLine();
      if (ImGui::SmallButton("Add it to the lobby")) {
        LobbyOptionInfo added = info;
        const int count = table ? static_cast<int>(groups.size()) : levels ? std::max(highestLevel - option.loop.from + 1, 1) : 1;
        for (int c = 0; c < count; ++c) {
          added.values.push_back(NextLevelValue(added, (table ? "group " : "level ") + std::to_string(c + 1)));
        }
        if (levels) {
          // The loop starts at `from`: values below it make nothing, so the first level is key `from`.
          for (std::size_t v = 1; v < added.values.size(); ++v) {
            added.values[v].numberKey = static_cast<double>(option.loop.from) + static_cast<double>(v - 1);
            added.values[v].key = std::to_string(option.loop.from + static_cast<int>(v) - 1);
          }
        }
        writeOption(added);
      }
    } else if (table && info.values.size() != groups.size() + 1) {
      ImGui::TextColored(kWarn, "The lobby has %zu choices for %zu groups: %s.", info.values.size(), groups.size(),
                         info.values.size() > groups.size() + 1 ? "the last choices add nothing" : "the last groups can't be picked");
      ImGui::SameLine();
      if (ImGui::SmallButton("Fix")) {
        LobbyOptionInfo fixed = info;
        fixed.values.resize(std::min(fixed.values.size(), groups.size() + 1));
        while (fixed.values.size() < groups.size() + 1) {
          fixed.values.push_back(NextLevelValue(fixed, "group " + std::to_string(fixed.values.size())));
        }
        writeOption(fixed);
      }
      ImGui::SetItemTooltip("One choice per group, and none: the choices there keep their names");
    } else if (levels && highestLevel > 0) {
      int reach = 0;
      for (const LobbyOptionInfo::Value& value : info.values) {
        reach = std::max(reach, value.number ? static_cast<int>(value.numberKey) : 0);
      }
      if (reach < highestLevel) {
        ImGui::TextColored(kWarn, "Levels above %d never appear: the lobby's choices end there.", reach);
        ImGui::SameLine();
        if (ImGui::SmallButton("Fix")) {
          LobbyOptionInfo fixed = info;
          while (reach < highestLevel) {
            ++reach;
            LobbyOptionInfo::Value value = NextLevelValue(fixed, "level " + std::to_string(reach - option.loop.from + 1));
            value.numberKey = reach;
            value.key = std::to_string(reach);
            fixed.values.push_back(value);
          }
          writeOption(fixed);
        }
      }
    }
    if (option.lobby < 0) {
      // What it would offer: the groups or levels already on the map.
      if (table) {
        std::size_t count = 0;
        for (const std::vector<std::string>& group : groups) {
          count += group.size();
        }
        ImGui::Text("On the map: %zu groups, %zu %s in all.", groups.size(), count, hydro ? "hydrocarbons" : "mexes");
      } else if (levels) {
        int count = 0;
        std::size_t units = 0;
        for (int k = option.loop.from; k <= highestLevel; ++k) {
          std::vector<std::string> path;
          if (const UnitGroup* const found = FindGroup(army, option.loop.prefix + std::to_string(k), path); found != nullptr) {
            std::vector<const SaveUnit*> list;
            CollectUnits(*found, list);
            units += list.size();
            ++count;
          }
        }
        ImGui::Text("On the map: %d levels, %zu %s in all%s.", count, units, option.loop.wreck ? "wrecks" : "units",
                    count == 0 ? " (add it to the lobby, then units to its levels)" : "");
      }
      return;
    }

    // Its name and description in the lobby.
    ImGui::Spacing();
    {
      LobbyOptionInfo edited = info;
      ImGui::AlignTextToFramePadding();
      ImGui::TextDisabled("In the lobby");
      ImGui::SameLine(ImGui::GetFontSize() * 7.0f);
      if (EditText("##label", edited.label, std::min(ImGui::GetContentRegionAvail().x, 420.0f))) {
        writeOption(edited);
      }
      ImGui::SetItemTooltip("The option's name in the lobby");
      ImGui::AlignTextToFramePadding();
      ImGui::TextDisabled("Description");
      ImGui::SameLine(ImGui::GetFontSize() * 7.0f);
      if (EditText("##help", edited.help, ImGui::GetContentRegionAvail().x, true)) {
        writeOption(edited);
      }
      ImGui::SetItemTooltip("What the lobby shows when the option is hovered");
    }

    // The choices.
    ImGui::Spacing();
    ImGui::TextDisabled("CHOICES");
    int removeChoice = -1;
    if (ImGui::BeginTable("##choices", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_SizingStretchProp)) {
      ImGui::TableSetupColumn("Default", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 3.6f);
      ImGui::TableSetupColumn("Choice", ImGuiTableColumnFlags_WidthStretch, 1.0f);
      ImGui::TableSetupColumn("Puts on the map", ImGuiTableColumnFlags_WidthStretch, 1.4f);
      ImGui::TableSetupColumn("##actions", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 15.0f);
      ImGui::TableHeadersRow();
      double total = 0.0;
      std::size_t totalCount = 0;
      for (std::size_t v = 0; v < info.values.size(); ++v) {
        const LobbyOptionInfo::Value& value = info.values[v];
        ImGui::PushID(static_cast<int>(v));
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        if (ImGui::RadioButton("##default", info.defaultIndex == static_cast<int>(v) + 1)) {
          LobbyOptionInfo changed = info;
          changed.defaultIndex = static_cast<int>(v) + 1;
          writeOption(changed);
        }
        ImGui::SetItemTooltip("The lobby's choice until a player changes it");
        ImGui::TableSetColumnIndex(1);
        {
          LobbyOptionInfo changed = info;
          if (EditText("##text", changed.values[v].text, -1.0f)) {
            writeOption(changed);
          }
          ImGui::SetItemTooltip("%s\nkey %s", value.help.empty() ? "(no description)" : value.help.c_str(), value.key.c_str());
        }
        ImGui::TableSetColumnIndex(2);
        ImGui::AlignTextToFramePadding();
        // What it adds, and the buttons for it.
        std::vector<std::string> names;     // resources: the group's markers
        std::string levelGroup;             // levels: the group
        std::vector<std::string> levelPath; // levels: its path
        std::vector<const SaveUnit*> levelUnits;
        int group = -1;
        if (table) {
          group = TableGroupOfChoice(value);
          if (group < 0) {
            ImGui::TextDisabled("nothing more");
          } else if (static_cast<std::size_t>(group) < groups.size()) {
            names = groups[static_cast<std::size_t>(group)];
            totalCount += names.size();
            ImGui::Text("+ %zu %s", names.size(), hydro ? "hydrocarbons" : "mexes");
            ImGui::SameLine();
            ImGui::TextDisabled("(%zu in all)", totalCount);
          } else {
            ImGui::TextColored(kWarn, "no group %d", group + 1);
          }
        } else if (levels) {
          levelGroup = LoopGroupOfChoice(option.loop, value);
          if (levelGroup.empty()) {
            ImGui::TextDisabled("nothing more");
          } else if (const UnitGroup* const found = FindGroup(army, levelGroup, levelPath); found != nullptr) {
            CollectUnits(*found, levelUnits);
            double mass = 0.0;
            if (option.loop.wreck) {
              for (const SaveUnit* const unit : levelUnits) {
                mass += UnitBlueprintWreck(unit->type, UnderWater(mDocument, unit->position[0], unit->position[2])).wreck.mass;
              }
            }
            total += mass;
            ImGui::Text("+ %zu %s", levelUnits.size(), option.loop.wreck ? "wrecks" : "units");
            if (option.loop.wreck) {
              ImGui::SameLine();
              ImGui::TextDisabled("%.0f mass (%.0f in all)", mass, total);
            }
            ImGui::SetItemTooltip("The group %s of %s", levelGroup.c_str(), option.loop.army.c_str());
          } else {
            ImGui::TextDisabled("+ nothing yet (%s)", levelGroup.c_str());
          }
        } else {
          // Read from the script once per script, options and option (the script is read whole for it).
          static std::size_t madeFor = 0;
          static std::vector<std::vector<MadeGroup>> made;
          const std::size_t key = std::hash<std::string>{}(mDocument.Script()) ^ (std::hash<std::string>{}(mDocument.OptionsText()) * 31u) ^
                                  (std::hash<std::string>{}(option.key) * 131u);
          if (madeFor != key) {
            madeFor = key;
            made.clear();
            for (std::size_t c = 0; c < info.values.size(); ++c) {
              made.push_back(GroupsMadeByChoice(mDocument.Script(), lobby, option.key, static_cast<int>(c)));
            }
          }
          std::string what;
          if (v < made.size()) {
            for (const MadeGroup& m : made[v]) {
              what += (what.empty() ? "" : ", ") + m.group + (m.wreck && m.unit ? " (wrecks or units)" : m.wreck ? " (wrecks)" : " (units)") +
                      (m.maybe ? "?" : "");
            }
          }
          if (what.empty()) {
            ImGui::TextDisabled("no groups");
          } else {
            ImGui::TextWrapped("%s", what.c_str());
          }
        }
        ImGui::TableSetColumnIndex(3);
        if (table && group >= 0 && static_cast<std::size_t>(group) < groups.size()) {
          ImGui::BeginDisabled(names.empty());
          if (ImGui::SmallButton("Select")) {
            mTools.AskMarkerSelect(names, ImGui::GetIO().KeyCtrl);
          }
          ImGui::EndDisabled();
          ImGui::SameLine();
          ImGui::BeginDisabled(selectedResources.empty());
          if (ImGui::SmallButton("Add selected")) {
            std::vector<std::vector<std::string>> changed = groups;
            TakeOut(changed, selectedResources);
            changed[static_cast<std::size_t>(group)].insert(changed[static_cast<std::size_t>(group)].end(), selectedResources.begin(),
                                                            selectedResources.end());
            writeTable(changed);
          }
          ImGui::SetItemTooltip("Puts the %zu selected %s in this choice's group (out of any other)", selectedResources.size(),
                                hydro ? "hydrocarbons" : "mexes");
          ImGui::SameLine();
          if (ImGui::SmallButton("Take out")) {
            std::vector<std::vector<std::string>> changed = groups;
            std::vector<std::vector<std::string>> one{changed[static_cast<std::size_t>(group)]};
            TakeOut(one, selectedResources);
            changed[static_cast<std::size_t>(group)] = one.front();
            writeTable(changed);
          }
          ImGui::SetItemTooltip("Takes the selected ones out of this group (they then spawn in every game)");
          ImGui::EndDisabled();
        } else if (levels && !levelGroup.empty()) {
          ImGui::BeginDisabled(levelUnits.empty());
          if (ImGui::SmallButton("Select")) {
            EdTools::UnitGroupAsk ask;
            ask.select = true;
            for (const SaveUnit* const unit : levelUnits) {
              ask.units.emplace_back(option.loop.army, unit->name);
            }
            mTools.AskUnitGroup(std::move(ask));
          }
          ImGui::EndDisabled();
          ImGui::SameLine();
          ImGui::BeginDisabled(selectedUnits.empty());
          if (ImGui::SmallButton("Add selected")) {
            EdTools::UnitGroupAsk ask;
            ask.army = option.loop.army;
            ask.names = selectedUnits;
            ask.path = levelPath.empty() ? std::vector<std::string>{levelGroup} : levelPath;
            mTools.AskUnitGroup(std::move(ask));
          }
          ImGui::SetItemTooltip("Moves the %zu selected units of %s into this level", selectedUnits.size(), option.loop.army.c_str());
          ImGui::EndDisabled();
        }
        // Delete: the "none" choice stays; a level only from the top (the script counts levels up to the value).
        const bool deletable = v > 0 && (!levels || v + 1 == info.values.size());
        ImGui::SameLine();
        ImGui::BeginDisabled(!deletable);
        if (ImGui::SmallButton("x")) {
          removeChoice = static_cast<int>(v);
        }
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
          ImGui::SetTooltip("%s", !deletable ? (v == 0 ? "The first choice is the one that adds nothing" : "Levels are deleted from the top")
                                  : table    ? "Deletes the choice and its group (the groups after it move down)"
                                  : levels   ? "Deletes the choice and its level's units"
                                             : "Deletes the choice");
        }
        ImGui::PopID();
      }
      ImGui::EndTable();
    }
    if (removeChoice > 0) {
      LobbyOptionInfo changed = info;
      const LobbyOptionInfo::Value removed = changed.values[static_cast<std::size_t>(removeChoice)];
      changed.values.erase(changed.values.begin() + removeChoice);
      if (table) {
        // The choices after it come down a key, as their groups do.
        const int group = TableGroupOfChoice(removed);
        for (std::size_t v = static_cast<std::size_t>(removeChoice); v < changed.values.size(); ++v) {
          if (changed.values[v].number) {
            changed.values[v].numberKey -= 1.0;
            changed.values[v].key = std::to_string(static_cast<int>(changed.values[v].numberKey));
          }
        }
        if (group >= 0 && static_cast<std::size_t>(group) < groups.size()) {
          std::vector<std::vector<std::string>> fewer = groups;
          fewer.erase(fewer.begin() + group);
          writeTable(fewer);
        }
      } else if (levels) {
        std::vector<std::string> path;
        if (FindGroup(army, LoopGroupOfChoice(option.loop, removed), path) != nullptr) {
          EdTools::UnitGroupAsk ask;
          ask.army = option.loop.army;
          ask.path = path;
          ask.removeGroup = true;
          mTools.AskUnitGroup(std::move(ask));
        }
      }
      if (changed.defaultIndex > static_cast<int>(changed.values.size())) {
        changed.defaultIndex = 1;
      }
      writeOption(changed);
    }
    // A new choice: a group (the selected resources), a level (the selected units), or a value.
    ImGui::Spacing();
    const char* const addLabel = table ? (selectedResources.empty() ? "+ Add a choice (an empty group)" : "+ Add a choice with the selected")
                                 : levels ? (selectedUnits.empty() ? "+ Add a level" : "+ Add a level with the selected units")
                                          : "+ Add a choice";
    if (ImGui::Button(addLabel)) {
      LobbyOptionInfo changed = info;
      if (table) {
        std::vector<std::vector<std::string>> more = groups;
        TakeOut(more, selectedResources);
        more.push_back(selectedResources);
        writeTable(more);
        changed.values.resize(std::min(changed.values.size(), groups.size() + 1));
        changed.values.push_back(NextLevelValue(changed, "group " + std::to_string(more.size())));
      } else if (levels) {
        LobbyOptionInfo::Value value = NextLevelValue(changed, "level " + std::to_string(changed.values.size()));
        value.numberKey = std::max(value.numberKey, static_cast<double>(option.loop.from));
        value.key = std::to_string(static_cast<int>(value.numberKey));
        changed.values.push_back(value);
        if (!selectedUnits.empty()) {
          EdTools::UnitGroupAsk ask;
          ask.army = option.loop.army;
          ask.names = selectedUnits;
          ask.path = {LoopGroupOfChoice(option.loop, value)};
          mTools.AskUnitGroup(std::move(ask));
        }
      } else {
        changed.values.push_back(NextLevelValue(changed, "choice " + std::to_string(changed.values.size() + 1)));
      }
      writeOption(changed);
    }
    ImGui::Spacing();
    HelpNote("Every change is written into the map's files at once (_options.lua, _tables.lua, the units), each one undo step "
             "(Ctrl+Z); Save writes them into the map's folder.");
  }
} // namespace faf::editor
