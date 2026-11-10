#include "editor/doc/EdUnitFate.h"

#include <cctype>
#include <cstdlib>
#include <utility>

namespace faf::editor
{
  namespace
  {
    bool FindPath(const UnitGroup& group, const std::string& unit, std::vector<std::string>& path)
    {
      for (const SaveUnit& member : group.units) {
        if (member.name == unit) {
          return true;
        }
      }
      for (const UnitGroup& child : group.groups) {
        path.push_back(child.name);
        if (FindPath(child, unit, path)) {
          return true;
        }
        path.pop_back();
      }
      return false;
    }

    /** One group creation in the script: its name (or the start of it, before `..`) and whether as wrecks. */
    struct ScriptGroup
    {
      std::string name;
      bool prefix = false;
      bool wreck = false;
    };

    /** The arguments of the call whose `(` is at `open`, split at top-level commas (strings and nesting skipped). */
    std::vector<std::string> Arguments(const std::string& text, const std::size_t open)
    {
      std::vector<std::string> args(1);
      int depth = 0;
      for (std::size_t i = open + 1; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '\'' || c == '"') {
          const std::size_t close = text.find(c, i + 1);
          if (close == std::string::npos) {
            break;
          }
          args.back() += text.substr(i, close - i + 1);
          i = close;
          continue;
        }
        if (c == '(' || c == '{' || c == '[') {
          ++depth;
        } else if (c == ')' || c == '}' || c == ']') {
          if (depth == 0) {
            return args;
          }
          --depth;
        } else if (c == ',' && depth == 0) {
          args.emplace_back();
          continue;
        }
        args.back() += c;
      }
      return args;
    }

    std::string Trim(const std::string& text)
    {
      std::size_t a = 0;
      std::size_t b = text.size();
      while (a < b && std::isspace(static_cast<unsigned char>(text[a])) != 0) {
        ++a;
      }
      while (b > a && std::isspace(static_cast<unsigned char>(text[b - 1])) != 0) {
        --b;
      }
      return text.substr(a, b - a);
    }

    std::vector<ScriptGroup> ScriptGroups(const std::string& script)
    {
      std::vector<ScriptGroup> groups;
      // ScenarioUtilities' group creators: CreateArmyGroup(army, group, wreckage), CreateArmyGroupAsPlatoon(...),
      // CreateArmyTree(army, group) and their kin all take the group's name second.
      for (std::size_t at = script.find("CreateArmy"); at != std::string::npos; at = script.find("CreateArmy", at + 10)) {
        const std::size_t open = script.find('(', at);
        if (open == std::string::npos || open - at > 40) {
          continue;
        }
        const std::string function = script.substr(at, open - at);
        const std::vector<std::string> args = Arguments(script, open);
        if (args.size() < 2) {
          continue;
        }
        const std::string second = Trim(args[1]);
        if (second.size() < 2 || (second[0] != '\'' && second[0] != '"')) {
          continue; // a name made at run time: not matched
        }
        const std::size_t close = second.find(second[0], 1);
        ScriptGroup group;
        group.name = second.substr(1, close - 1);
        group.prefix = second.find("..", close) != std::string::npos;
        group.wreck = Trim(function) == "CreateArmyGroup" && args.size() >= 3 && Trim(args[2]) == "true";
        groups.push_back(std::move(group));
      }
      return groups;
    }

    /** A number after `name =` in text[from, to), or `otherwise`. */
    double NumberAfter(const std::string& text, const std::size_t from, const std::size_t to, const char* const name, const double otherwise)
    {
      const std::string key = name;
      for (std::size_t at = text.find(key, from); at != std::string::npos && at < to; at = text.find(key, at + 1)) {
        if (at > 0 && (std::isalnum(static_cast<unsigned char>(text[at - 1])) != 0 || text[at - 1] == '_')) {
          continue;
        }
        std::size_t i = at + key.size();
        while (i < to && (text[i] == ' ' || text[i] == '\t')) {
          ++i;
        }
        if (i < to && text[i] == '=') {
          return std::atof(text.c_str() + i + 1);
        }
      }
      return otherwise;
    }
  } // namespace

  std::vector<std::string> UnitGroupPath(const UnitGroup& root, const std::string& unit)
  {
    std::vector<std::string> path;
    if (!FindPath(root, unit, path)) {
      path.clear();
    }
    return path;
  }

  UnitFate FateOfUnit(const std::vector<std::string>& path, const bool civilian, const std::string& script)
  {
    UnitFate fate;
    // The game finds INITIAL and WRECKAGE by name anywhere in the army's tree (FindUnitGroup), and takes all under it.
    for (const std::string& group : path) {
      if (group == "WRECKAGE") {
        fate.kind = UnitFate::Kind::Wreck;
        fate.group = group;
        fate.text = "A wreck from the start: the game turns the army's WRECKAGE group into wrecks as the game begins.";
        return fate;
      }
    }
    for (const std::string& group : path) {
      if (group == "INITIAL") {
        fate.kind = UnitFate::Kind::Unit;
        fate.group = group;
        fate.text = civilian ? "A unit from the start (the army's INITIAL group), unless the lobby's Civilians option is \"removed\"."
                             : "A unit from the start: the army's INITIAL group.";
        return fate;
      }
    }
    const std::vector<ScriptGroup> made = ScriptGroups(script);
    for (auto group = path.rbegin(); group != path.rend(); ++group) {
      for (const ScriptGroup& creation : made) {
        if (creation.prefix ? group->rfind(creation.name, 0) == 0 : *group == creation.name) {
          fate.kind = creation.wreck ? UnitFate::Kind::ScriptWreck : UnitFate::Kind::ScriptUnit;
          fate.group = *group;
          fate.text = std::string("Only when the map's script creates the group ") + *group + (creation.wreck ? ", as wrecks" : ", as units") +
                      " (a lobby option often decides it).";
          return fate;
        }
      }
    }
    fate.group = path.empty() ? std::string() : path.back();
    fate.text = path.empty() ? "Not in a group: never in a game."
                             : "Never in a game: nothing creates the group " + fate.group + " (the map's script doesn't name it).";
    return fate;
  }

  WreckValue WreckOfUnit(const std::string& text, const double buildCostMass, const double buildCostEnergy, const bool underwater)
  {
    WreckValue wreck;
    // The blueprint's top-level `Wreckage = { ... }` table.
    std::size_t start = std::string::npos;
    for (std::size_t at = text.find("Wreckage"); at != std::string::npos; at = text.find("Wreckage", at + 1)) {
      std::size_t i = at + 8;
      while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) {
        ++i;
      }
      if (i < text.size() && text[i] == '=' && (at == 0 || std::isalnum(static_cast<unsigned char>(text[at - 1])) == 0)) {
        start = text.find('{', i);
        break;
      }
    }
    if (start == std::string::npos) {
      return wreck;
    }
    int depth = 0;
    std::size_t end = start;
    for (; end < text.size(); ++end) {
      depth += text[end] == '{' ? 1 : text[end] == '}' ? -1 : 0;
      if (depth == 0) {
        break;
      }
    }
    if (text.find("Blueprint", start) == std::string::npos || text.find("Blueprint", start) > end) {
      return wreck; // no wreck blueprint: the unit leaves none
    }
    wreck.exists = true;
    double mass = buildCostMass * NumberAfter(text, start, end, "MassMult", 0.0);
    double energy = buildCostEnergy * NumberAfter(text, start, end, "EnergyMult", 0.0);
    // TechCategory as lua/system/Blueprints.lua sets it while loading: the first of these the unit's Categories has.
    double tech = 0.9;
    if (const std::size_t at = text.find("Categories"); at != std::string::npos) {
      const std::size_t open = text.find('{', at);
      const std::size_t close = open == std::string::npos ? open : text.find('}', open);
      const std::string categories = close == std::string::npos ? std::string() : text.substr(open, close - open);
      const auto has = [&](const char* const category) {
        return categories.find(std::string("\"") + category + "\"") != std::string::npos ||
               categories.find(std::string("'") + category + "'") != std::string::npos;
      };
      // Unit.lua's CreateWreckageProp: TECH1 0.9, TECH2 0.8, TECH3 0.7, EXPERIMENTAL 0.6, anything else 0.9.
      static constexpr std::pair<const char*, double> kOrder[] = {{"EXPERIMENTAL", 0.6}, {"SUBCOMMANDER", 0.9}, {"COMMAND", 0.9},
                                                                   {"TECH1", 0.9},        {"TECH2", 0.8},        {"TECH3", 0.7}};
      for (const auto& [category, mult] : kOrder) {
        if (has(category)) {
          tech = mult;
          break;
        }
      }
    }
    mass *= tech;
    if (underwater) {
      mass *= 0.6;
      energy *= 0.6;
    }
    wreck.mass = mass;
    wreck.energy = energy;
    return wreck;
  }
} // namespace faf::editor
