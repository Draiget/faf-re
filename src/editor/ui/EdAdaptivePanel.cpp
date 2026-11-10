// The Adaptive tool's panel: an adaptive map's whole setup in one place (EdShell::DrawAdaptivePanel). Which resources
// spawn with which army, the lobby options' groups, the crazyrush lists, and the lobby options in `_options.lua` that
// the script reads them by; the Properties panel keeps the one-marker view of the same tables.

#include <algorithm>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <string>
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdAdaptiveTables.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdUnitFate.h"
#include "editor/doc/EdUnitWrecks.h"
#include "editor/doc/EdUnits.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdHelp.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    const ImVec4 kGood(0.45f, 0.80f, 0.45f, 1.0f);
    const ImVec4 kWarn(0.95f, 0.75f, 0.30f, 1.0f);
    const ImVec4 kBad(0.95f, 0.45f, 0.35f, 1.0f);

    void Header(const char* const text)
    {
      ImGui::Spacing();
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::TextUnformatted(text);
      ImGui::PopStyleColor();
    }

    /** A status line: a coloured dot and the text, wrapped. */
    void Status(const ImVec4& colour, const std::string& text)
    {
      const float size = ImGui::GetTextLineHeight();
      const ImVec2 at = ImGui::GetCursorScreenPos();
      ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(at.x + size * 0.4f, at.y + size * 0.5f), size * 0.22f, ImGui::GetColorU32(colour));
      ImGui::Dummy(ImVec2(size * 0.8f, size));
      ImGui::SameLine();
      ImGui::TextWrapped("%s", text.c_str());
    }

    /** Small buttons at the right of a row, right to left; true when clicked. */
    class RowButtons
    {
    public:
      /** `rowRight`: the row's right edge, in the window's local x (as SameLine takes it). */
      /**
       * `rowRight`: the row's right edge, in the window's local x (as SameLine takes it); `labels`: every button the
       * row will have, so a narrow panel puts them all under the row's text rather than over it.
       */
      RowButtons(const float rowRight, std::initializer_list<const char*> labels) : mRight(rowRight)
      {
        float total = 0.0f;
        for (const char* const label : labels) {
          total += Width(label) + ImGui::GetStyle().ItemInnerSpacing.x;
        }
        const float textEnd = ImGui::GetItemRectMax().x - ImGui::GetWindowPos().x + ImGui::GetScrollX();
        mWrap = mRight - total < textEnd + ImGui::GetStyle().ItemSpacing.x;
      }
      bool Button(const char* const label, const bool enabled = true)
      {
        mRight -= Width(label);
        if (mWrap) {
          mWrap = false; // the first one starts the line under the text; the rest follow it
          ImGui::SetCursorPosX(mRight);
        } else {
          ImGui::SameLine(mRight);
        }
        mRight -= ImGui::GetStyle().ItemInnerSpacing.x;
        ImGui::BeginDisabled(!enabled);
        const bool clicked = ImGui::SmallButton(label);
        ImGui::EndDisabled();
        return clicked;
      }

    private:
      static float Width(const char* const label)
      {
        return ImGui::CalcTextSize(label, nullptr, true).x + ImGui::GetStyle().FramePadding.x * 2.0f;
      }
      float mRight;
      bool mWrap = false;
    };

    /** Takes `names` out of every list in `lists`. */
    void TakeOut(std::vector<std::vector<std::string>>& lists, const std::vector<std::string>& names)
    {
      for (std::vector<std::string>& list : lists) {
        list.erase(std::remove_if(list.begin(), list.end(),
                                  [&](const std::string& name) { return std::find(names.begin(), names.end(), name) != names.end(); }),
                   list.end());
      }
    }
  } // namespace

  void EdShell::DrawAdaptivePanel()
  {
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("Open a map to set up its adaptive resources.");
      return;
    }
    const std::vector<ScenarioTeam> teams = mDocument.Teams();
    const int slots = teams.empty() ? 0 : static_cast<int>(teams.front().armies.size());

    // The files the script needs, and what each one does.
    Header("FILES");
    if (!mDocument.Adaptive()) {
      HelpNote("Adaptive maps (FAF's \"Ultimate maps\" script by CookieNoob and KeyBlue) spawn each player's resources only "
               "when that player is in the game, and let the lobby's options add groups of resources. The editor writes the "
               "_tables.lua and the lobby options; the _script.lua comes from an adaptive map (copy it into this map's folder).");
      if (ImGui::Button("Make this map adaptive", ImVec2(-1.0f, 0.0f))) {
        AdaptiveTables fresh;
        fresh.maxPlayers = std::max(slots, 1);
        fresh.mexArmy.assign(static_cast<std::size_t>(fresh.maxPlayers), {});
        fresh.hydroArmy.assign(static_cast<std::size_t>(fresh.maxPlayers), {});
        mDocument.SetTablesText(WithAdaptiveTables("", fresh));
      }
      return;
    }
    AdaptiveTables tables;
    std::string error;
    if (!ParseAdaptiveTables(mDocument.TablesText(), tables, error)) {
      Status(kBad, "_tables.lua doesn't read: " + error);
      return;
    }
    HelpNote("Three files make an adaptive map. _tables.lua says which resources spawn with which army and which belong to "
             "the lobby options' groups: this panel writes it (the tables it doesn't know are kept). _script.lua is the "
             "\"Ultimate maps\" script that reads the tables when the game starts: it isn't made here, it comes from an "
             "adaptive map. _options.lua holds the lobby's options: this panel writes the ones its tables need, the rest "
             "(wreckage, reclaim...) are kept. They are written into the map's folder on Save; Edit shows a file's text.");
    const auto editLink = [&](const char* const id, const int file) {
      ImGui::SameLine();
      ImGui::PushID(id);
      if (ImGui::SmallButton("Edit")) {
        ShowLuaFile(file);
      }
      ImGui::PopID();
      ImGui::SetItemTooltip("This file's text in the Script panel");
    };
    Status(kGood, "Tables: " + mDocument.Facts().tablesPath);
    editLink("tables", 2);
    if (AdaptiveTablesPath(mDocument.Script()).empty()) {
      Status(kWarn, "The map's _script.lua doesn't read the tables yet: put an adaptive map's _script.lua in its folder, importing " +
                      mDocument.Facts().tablesPath + ". Until then nothing here changes the game.");
    } else {
      Status(kGood, "The script reads them.");
    }
    editLink("script", 0);
    if (mDocument.OptionsText().empty()) {
      Status(kWarn, "No _options.lua: the lobby shows no options, so no option group below spawns (the script reads 1, none).");
    } else {
      Status(kGood, "Lobby options: " + mDocument.Facts().optionsPath);
    }
    editLink("options", 1);

    // The edit: a copy of the tables changed, written into the file's text as one undo step.
    AdaptiveTables changed = tables;
    bool edited = false;
    std::string options = mDocument.OptionsText();
    bool optionsEdited = false;

    // The selection's resources, by kind: what the "Add selected" buttons take.
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
    std::vector<std::string> selected = selectedMass;
    selected.insert(selected.end(), selectedHydro.begin(), selectedHydro.end());
    ImGui::Spacing();
    if (selected.empty()) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("Select mass or hydrocarbon markers in the view (click, Ctrl+click, box) to add them below.");
      ImGui::PopTextWrapPos();
    } else {
      ImGui::Text("Selected: %zu mass, %zu hydrocarbon", selectedMass.size(), selectedHydro.size());
    }

    // The rows' right edge, a frame padding short of the scrollbar so the buttons don't touch it.
    const float right = ImGui::GetContentRegionAvail().x + ImGui::GetCursorPosX() - ImGui::GetStyle().FramePadding.x;
    const auto selectNames = [&](const std::vector<std::string>& names) { mTools.AskMarkerSelect(names, ImGui::GetIO().KeyCtrl); };

    // Players.
    Header("PLAYERS");
    {
      int players = changed.maxPlayers;
      ImGui::SetNextItemWidth(ImGui::GetFontSize() * 7.0f);
      if (ImGui::InputInt("Max players on the map", &players) && players >= std::max(slots, 1) && players <= 16) {
        changed.maxPlayers = players;
        edited = true;
      }
      ImGui::SetItemTooltip("maxPlayerOnMap: the script reads the armies' lists up to it (never fewer than the %d slots)", slots);
    }

    // By army: the resources that spawn only with that army's player.
    Header("SPAWN WITH AN ARMY");
    HelpNote("A resource in an army's list is there only when that army's player is in the game (with the lobby's "
             "Dynamic Spawn option, also for the mirror slot). Resources in no list always spawn, unless an option group has them.");
    {
      std::vector<std::string> armyAll;
      for (const auto* const lists : {&changed.mexArmy, &changed.hydroArmy}) {
        for (const std::vector<std::string>& list : *lists) {
          armyAll.insert(armyAll.end(), list.begin(), list.end());
        }
      }
      const int armies = std::max({changed.maxPlayers, slots, static_cast<int>(changed.mexArmy.size()), static_cast<int>(changed.hydroArmy.size())});
      for (int a = 1; a <= armies; ++a) {
        ImGui::PushID(a);
        const std::size_t index = static_cast<std::size_t>(a - 1);
        const std::size_t mass = index < changed.mexArmy.size() ? changed.mexArmy[index].size() : 0;
        const std::size_t hydro = index < changed.hydroArmy.size() ? changed.hydroArmy[index].size() : 0;
        ImGui::AlignTextToFramePadding();
        ImGui::Text("ARMY_%d", a);
        ImGui::SameLine(ImGui::GetFontSize() * 5.5f);
        ImGui::TextDisabled("%zu mass, %zu hydro", mass, hydro);
        RowButtons buttons(right, {"Add selected", "Select"});
        if (buttons.Button("Add selected", !selected.empty())) {
          TakeOut(changed.mexArmy, selected);
          TakeOut(changed.hydroArmy, selected);
          if (changed.mexArmy.size() < static_cast<std::size_t>(a)) {
            changed.mexArmy.resize(static_cast<std::size_t>(a));
          }
          if (changed.hydroArmy.size() < static_cast<std::size_t>(a)) {
            changed.hydroArmy.resize(static_cast<std::size_t>(a));
          }
          changed.mexArmy[index].insert(changed.mexArmy[index].end(), selectedMass.begin(), selectedMass.end());
          changed.hydroArmy[index].insert(changed.hydroArmy[index].end(), selectedHydro.begin(), selectedHydro.end());
          edited = true;
        }
        if (buttons.Button("Select", mass + hydro > 0)) {
          std::vector<std::string> names;
          if (index < changed.mexArmy.size()) {
            names = changed.mexArmy[index];
          }
          if (index < changed.hydroArmy.size()) {
            names.insert(names.end(), changed.hydroArmy[index].begin(), changed.hydroArmy[index].end());
          }
          selectNames(names);
        }
        ImGui::PopID();
      }
      if (ImGui::Button("Selected: spawn always", ImVec2(-1.0f, 0.0f)) && !selected.empty()) {
        TakeOut(changed.mexArmy, selected);
        TakeOut(changed.hydroArmy, selected);
        edited = true;
      }
      ImGui::SetItemTooltip("Takes the selected resources out of every army's list");
    }

    // The lobby's option groups.
    Header("LOBBY OPTION GROUPS");
    HelpNote("Each option table has groups; the lobby option of the same name picks how many of them spawn (none, group 1, "
             "groups 1-2, ...). A table whose lobby option is missing never spawns its groups.");
    const auto groupsOf = [&](const std::string& name) -> std::vector<std::vector<std::string>>* {
      for (auto& [table, groups] : changed.options) {
        if (table == name) {
          return &groups;
        }
      }
      return nullptr;
    };
    std::vector<const OptionTable*> unused;
    for (const OptionTable& table : KnownOptionTables()) {
      std::vector<std::vector<std::string>>* const groups = groupsOf(table.name);
      const std::string key = AdaptiveOptionKey(table.name);
      const LobbyOption lobby = FindLobbyOption(options, key);
      const bool hasGroups = groups != nullptr && !groups->empty();
      if (!hasGroups && !lobby.found) {
        unused.push_back(&table);
        continue;
      }
      ImGui::PushID(table.name);
      ImGui::Separator();
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(table.label);
      ImGui::SameLine();
      ImGui::TextDisabled("%s, lobby key %s", table.hydro ? "hydrocarbons" : "mass", key.c_str());
      const std::vector<std::string>& wanted = table.hydro ? selectedHydro : selectedMass;
      const int groupCount = groups != nullptr ? static_cast<int>(groups->size()) : 0;
      int removeGroup = -1;
      for (int g = 0; g < groupCount; ++g) {
        ImGui::PushID(g);
        const std::vector<std::string>& list = (*groups)[static_cast<std::size_t>(g)];
        ImGui::AlignTextToFramePadding();
        ImGui::Text("   Group %d", g + 1);
        ImGui::SameLine(ImGui::GetFontSize() * 5.5f);
        ImGui::TextDisabled("%zu %s", list.size(), table.hydro ? "hydro" : "mass");
        RowButtons buttons(right, {"x", "Add selected", "Select"});
        if (buttons.Button("x")) {
          removeGroup = g;
        }
        ImGui::SetItemTooltip("Remove group %d (its resources leave this table; the groups after it move up)", g + 1);
        if (buttons.Button("Add selected", !wanted.empty())) {
          for (auto& [name, its] : changed.options) {
            TakeOut(its, wanted);
          }
          (*groups)[static_cast<std::size_t>(g)].insert((*groups)[static_cast<std::size_t>(g)].end(), wanted.begin(), wanted.end());
          edited = true;
        }
        if (buttons.Button("Select", !list.empty())) {
          selectNames(list);
        }
        ImGui::PopID();
      }
      if (removeGroup >= 0) {
        groups->erase(groups->begin() + removeGroup);
        edited = true;
      }
      if (ImGui::SmallButton(wanted.empty() ? "+ Group" : "+ Group of the selected")) {
        if (groups == nullptr) {
          changed.options.emplace_back(table.name, std::vector<std::vector<std::string>>{});
        }
        std::vector<std::vector<std::string>>& its = *groupsOf(table.name);
        for (auto& [name, other] : changed.options) {
          TakeOut(other, wanted);
        }
        its.push_back(wanted);
        edited = true;
      }
      // The lobby option: there with one value per group (and none), or missing.
      const int groupsNow = groupsOf(table.name) != nullptr ? static_cast<int>(groupsOf(table.name)->size()) : 0;
      std::vector<int> sizes;
      if (std::vector<std::vector<std::string>>* const its = groupsOf(table.name); its != nullptr) {
        for (const std::vector<std::string>& list : *its) {
          sizes.push_back(static_cast<int>(list.size()));
        }
      }
      if (!lobby.found) {
        ImGui::SameLine();
        ImGui::TextColored(kWarn, "not in the lobby");
      } else if (lobby.values != groupsNow + 1) {
        ImGui::SameLine();
        ImGui::TextColored(kWarn, "lobby: %d values for %d groups", lobby.values, groupsNow);
      } else {
        ImGui::SameLine();
        ImGui::TextColored(kGood, "in the lobby");
      }
      RowButtons buttons(right, {"Remove from lobby", "Add to lobby"});
      if (lobby.found && buttons.Button("Remove from lobby")) {
        options = WithoutLobbyOption(options, key);
        optionsEdited = true;
      }
      if (groupsNow > 0 && (!lobby.found || lobby.values != groupsNow + 1) && buttons.Button(lobby.found ? "Rewrite" : "Add to lobby")) {
        options = WithLobbyOption(options, key, table.label, table.hydro, sizes);
        optionsEdited = true;
      }
      if (lobby.found && lobby.values == groupsNow + 1 && buttons.Button("Rewrite")) {
        options = WithLobbyOption(options, key, table.label, table.hydro, sizes);
        optionsEdited = true;
      }
      ImGui::SetItemTooltip("Writes the option into _options.lua: none, then one value per group (its texts are replaced)");
      ImGui::PopID();
    }
    if (!unused.empty()) {
      ImGui::Separator();
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::BeginCombo("##addtable", "Add an option table...")) {
        for (const OptionTable* const table : unused) {
          if (ImGui::Selectable(table->label)) {
            const std::vector<std::string>& wanted = table->hydro ? selectedHydro : selectedMass;
            for (auto& [name, other] : changed.options) {
              TakeOut(other, wanted);
            }
            if (std::vector<std::vector<std::string>>* const groups = groupsOf(table->name); groups != nullptr) {
              groups->push_back(wanted);
            } else {
              changed.options.emplace_back(table->name, std::vector<std::vector<std::string>>{wanted});
            }
            edited = true;
          }
          ImGui::SetItemTooltip("%s (%s): a first group%s", table->label, table->hydro ? "hydrocarbons" : "mass",
                                (table->hydro ? selectedHydro : selectedMass).empty() ? "" : " of the selected");
        }
        ImGui::EndCombo();
      }
    }

    // Crazyrush: the script's two flat lists.
    Header("CRAZYRUSH");
    {
      const auto list = [&](const char* const label, const char* const help, std::vector<std::string>& names) {
        ImGui::PushID(label);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(label);
        ImGui::SetItemTooltip("%s", help);
        ImGui::SameLine(ImGui::GetFontSize() * 9.0f);
        ImGui::TextDisabled("%zu mass", names.size());
        RowButtons buttons(right, {"Remove selected", "Add selected", "Select"});
        if (buttons.Button("Remove selected", !selectedMass.empty())) {
          std::vector<std::vector<std::string>> one{names};
          TakeOut(one, selectedMass);
          names = one.front();
          edited = true;
        }
        if (buttons.Button("Add selected", !selectedMass.empty())) {
          for (const std::string& name : selectedMass) {
            if (std::find(names.begin(), names.end(), name) == names.end()) {
              names.push_back(name);
            }
          }
          edited = true;
        }
        if (buttons.Button("Select", !names.empty())) {
          selectNames(names);
        }
        ImGui::PopID();
      };
      list("Forward", "forwardCrazyrushMexes: the mexes the crazyrush option spawns forward", changed.forwardCrazyrush);
      list("The one core mex", "crazyrushOneMexes: the one mex per player the crazyrush option keeps", changed.crazyrushOne);
    }

    // The script's unit groups: the wreckage options' wrecks and the civilian bases, which the lobby turns on.
    Header("SCRIPT GROUPS");
    HelpNote("Unit groups the map's script creates, most of them by lobby options: the wreckage options' groups become wrecks "
             "(reclaim), the civilian base and defence options' groups wrecks or live units. A group is in a game only when its "
             "option asks for it. Select a group's units, or move the units selected in the view into it.");
    {
      const std::vector<ScriptGroupCreation> creations = ScriptGroupCreations(mDocument.Script());
      const auto creates = [&](const std::string& army, const std::string& name, bool& wreckOut, bool& unitOut) {
        for (const ScriptGroupCreation& creation : creations) {
          if ((creation.army.empty() || creation.army == army) &&
              (creation.prefix ? name.rfind(creation.name, 0) == 0 : name == creation.name)) {
            (creation.wreck ? wreckOut : unitOut) = true;
          }
        }
        return wreckOut || unitOut;
      };
      std::vector<std::string> armies;
      for (const ScriptGroupCreation& creation : creations) {
        if (!creation.army.empty() && std::find(armies.begin(), armies.end(), creation.army) == armies.end()) {
          armies.push_back(creation.army);
        }
      }
      if (armies.empty()) {
        ImGui::TextDisabled("The map's script creates no unit groups.");
      }
      for (const std::string& army : armies) {
        UnitGroup root;
        for (const SaveEntry& entry : mDocument.SaveData().Armies()) {
          std::string error;
          if (entry.name == army) {
            (void)ParseUnitGroup(entry.Get("Units"), root, error);
          }
        }
        // The units selected in the view that are this army's.
        std::vector<std::string> picked;
        for (const auto& [owner, name] : mTools.UnitSelection()) {
          if (owner == army) {
            picked.push_back(name);
          }
        }
        ImGui::PushID(army.c_str());
        ImGui::TextUnformatted(army.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%zu of its units selected", picked.size());
        // Each group the script creates, at any depth of the army's tree.
        struct Row
        {
          std::vector<std::string> path;
          const UnitGroup* group;
          bool wreck;
          bool unit;
        };
        std::vector<Row> rows;
        std::vector<std::string> path;
        const std::function<void(const UnitGroup&)> walk = [&](const UnitGroup& group) {
          for (const UnitGroup& child : group.groups) {
            path.push_back(child.name);
            bool asWreck = false;
            bool asUnit = false;
            if (creates(army, child.name, asWreck, asUnit)) {
              rows.push_back({path, &child, asWreck, asUnit});
            } else {
              walk(child);
            }
            path.pop_back();
          }
        };
        walk(root);
        for (const Row& row : rows) {
          ImGui::PushID(row.path.back().c_str());
          std::vector<const SaveUnit*> units;
          CollectUnits(*row.group, units);
          double mass = 0.0;
          if (row.wreck) {
            for (const SaveUnit* const unit : units) {
              mass += UnitBlueprintWreck(unit->type, UnderWater(mDocument, unit->position[0], unit->position[2])).wreck.mass;
            }
          }
          ImGui::AlignTextToFramePadding();
          ImGui::Text("   %s", row.path.back().c_str());
          ImGui::SetItemTooltip("%s", row.wreck && row.unit ? "Created as wrecks or as live units, as a lobby option picks."
                                      : row.wreck           ? "Created as wrecks."
                                                            : "Created as live units.");
          ImGui::SameLine();
          if (row.wreck) {
            ImGui::TextDisabled("%zu units, %.0f mass%s", units.size(), mass, row.unit ? " or live" : " as wrecks");
          } else {
            ImGui::TextDisabled("%zu live units", units.size());
          }
          RowButtons buttons(right, {"Add selected", "Select"});
          if (buttons.Button("Add selected", !picked.empty())) {
            EdTools::UnitGroupAsk ask;
            ask.army = army;
            ask.names = picked;
            ask.path = row.path;
            mTools.AskUnitGroup(std::move(ask));
          }
          if (buttons.Button("Select", !units.empty())) {
            EdTools::UnitGroupAsk ask;
            ask.select = true;
            for (const SaveUnit* const unit : units) {
              ask.units.emplace_back(army, unit->name);
            }
            mTools.AskUnitGroup(std::move(ask));
          }
          ImGui::PopID();
        }

        // The wreckage options, as the adaptive template writes them: option k creates groups <start>2 .. <start>k.
        struct Loop
        {
          const char* key;
          const char* label;
          const char* start;
        };
        static constexpr Loop kLoops[] = {
          {"optional_wreckage", "Wreckage", "Optional_Wreckage_"},
          {"optional_naval_wreckage", "Naval wreckage", "Optional_Wreckage_Naval_"},
          {"optional_wreckage_middle", "Middle wreckage", "Optional_Wreckage_Middle_"},
        };
        for (const Loop& loop : kLoops) {
          const bool made = std::any_of(creations.begin(), creations.end(), [&](const ScriptGroupCreation& c) {
            return c.prefix && c.name == loop.start && (c.army.empty() || c.army == army);
          });
          if (!made || mDocument.Script().find(loop.key) == std::string::npos) {
            continue;
          }
          ImGui::PushID(loop.key);
          // The groups there are: <start>2, <start>3, ... up to the first missing one.
          int highest = 1;
          std::vector<double> levelMass;
          std::vector<std::size_t> levelUnits;
          for (int k = 2; k < 32; ++k) {
            const UnitGroup* group = nullptr;
            for (const Row& row : rows) {
              if (row.path.back() == loop.start + std::to_string(k)) {
                group = row.group;
              }
            }
            if (group == nullptr) {
              break;
            }
            std::vector<const SaveUnit*> units;
            CollectUnits(*group, units);
            double mass = 0.0;
            for (const SaveUnit* const unit : units) {
              mass += UnitBlueprintWreck(unit->type, UnderWater(mDocument, unit->position[0], unit->position[2])).wreck.mass;
            }
            levelMass.push_back(mass);
            levelUnits.push_back(units.size());
            highest = k;
          }
          const LobbyOption lobby = FindLobbyOption(options, loop.key);
          ImGui::AlignTextToFramePadding();
          ImGui::Text("%s", loop.label);
          ImGui::SameLine();
          ImGui::TextDisabled("lobby key %s, %d groups", loop.key, highest - 1);
          if (!lobby.found) {
            ImGui::SameLine();
            ImGui::TextColored(kWarn, "not in the lobby");
          } else if (lobby.values != highest) {
            ImGui::SameLine();
            ImGui::TextColored(kWarn, "lobby: %d values for %d groups", lobby.values, highest - 1);
          }
          const std::string next = loop.start + std::to_string(highest + 1);
          RowButtons buttons(right, {"Add to lobby", ("+ " + next).c_str()});
          if (highest > 1 && buttons.Button(lobby.found ? "Rewrite" : "Add to lobby")) {
            std::vector<std::pair<std::string, std::string>> values;
            values.emplace_back("disabled", std::string("No ") + loop.label + ".");
            double total = 0.0;
            std::size_t count = 0;
            for (int k = 2; k <= highest; ++k) {
              total += levelMass[static_cast<std::size_t>(k - 2)];
              count += levelUnits[static_cast<std::size_t>(k - 2)];
              char help[200];
              (void)std::snprintf(help, sizeof(help), "Spawns %s2%s%s: %zu wrecks, %.0f mass.", loop.start, k > 2 ? " to " : "",
                                  k > 2 ? (loop.start + std::to_string(k)).c_str() : "", count, total);
              values.emplace_back("level " + std::to_string(k - 1), help);
            }
            options = WithLobbyOptionValues(options, loop.key, loop.label, std::string("How many of the map's ") + loop.label +
                                                                            " groups spawn (wrecks to reclaim).",
                                            values);
            optionsEdited = true;
          }
          ImGui::SetItemTooltip("Writes the option into _options.lua: disabled, then one value per group level (its texts are replaced)");
          if (buttons.Button(("+ " + next).c_str())) {
            EdTools::UnitGroupAsk ask;
            ask.army = army;
            ask.names = picked;
            ask.path = {next};
            mTools.AskUnitGroup(std::move(ask));
          }
          ImGui::SetItemTooltip("A new group %s in %s, with the units selected in the view (%zu): the option's next level", next.c_str(),
                                army.c_str(), picked.size());
          ImGui::PopID();
        }
        ImGui::PopID();
      }
    }

    if (edited && !(changed == tables)) {
      // The script reads armies up to maxPlayerOnMap: never fewer than the lobby's slots.
      changed.maxPlayers = std::max(changed.maxPlayers, slots);
      mDocument.SetTablesText(WithAdaptiveTables(mDocument.TablesText(), changed));
    }
    if (optionsEdited && options != mDocument.OptionsText()) {
      mDocument.SetOptionsText(options);
    }
  }
} // namespace faf::editor
