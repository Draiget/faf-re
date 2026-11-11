#include "editor/doc/EdAdaptiveModel.h"

#include "editor/doc/EdUnitFate.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace faf::editor
{
  std::string ReadableKey(
    const std::string& key
  )
  {
    std::string text;
    for (std::size_t i = 0; i < key.size(); ++i) {
      const char c = key[i];
      if (c == '_') {
        text += ' ';
      } else if (
        i > 0 && std::isupper(static_cast<unsigned char>(c)) != 0 &&
        std::islower(static_cast<unsigned char>(key[i - 1])) != 0
      ) {
        text += ' ';
        text += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      } else {
        text += c;
      }
    }
    if (!text.empty()) {
      text[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(text[0])));
    }
    return text;
  }

  std::vector<AdaptiveOption> AdaptiveOptionsOf(
    const std::string& script,
    const std::vector<LobbyOptionInfo>& lobby,
    const AdaptiveTables& tables,
    const bool adaptiveScript
  )
  {
    std::vector<AdaptiveOption> out;
    const std::vector<ScriptGroupLoop> loops = ScriptGroupLoops(script);
    // The keys the script reads (local x = ScenarioInfo.Options.key, or the key itself).
    const auto scriptReads = [&](const std::string& key) {
      return script.find("Options." + key) != std::string::npos ||
        script.find("Options['" + key + "']") != std::string::npos;
    };
    const auto tableOf = [&](const std::string& key) -> const OptionTable* {
      for (const OptionTable& table : KnownOptionTables()) {
        if (AdaptiveOptionKey(table.name) == key) {
          return &table;
        }
      }
      return nullptr;
    };
    const auto make = [&](const std::string& key, const int index) {
      AdaptiveOption option;
      option.key = key;
      option.lobby = index;
      option.scriptReads = scriptReads(key);
      if (const OptionTable* const table = tableOf(key); table != nullptr) {
        option.kind = table->hydro ? AdaptiveOption::Kind::Hydros : AdaptiveOption::Kind::Mexes;
        option.table = table->name;
        option.tableLabel = table->label;
        option.scriptReads = option.scriptReads || adaptiveScript;
      } else {
        for (const ScriptGroupLoop& loop : loops) {
          if (loop.key == key) {
            option.kind = AdaptiveOption::Kind::UnitLevels;
            option.loop = loop;
          }
        }
      }
      const std::string label = index >= 0 ? lobby[static_cast<std::size_t>(index)].label : std::string();
      option.title = !label.empty() ? label : !option.tableLabel.empty() ? option.tableLabel : ReadableKey(key);
      return option;
    };
    const auto have = [&](const std::string& key) {
      return std::any_of(out.begin(), out.end(), [&](const AdaptiveOption& o) {
        return o.key == key;
      });
    };
    for (std::size_t i = 0; i < lobby.size(); ++i) {
      if (!have(lobby[i].key)) {
        out.push_back(make(lobby[i].key, static_cast<int>(i)));
      }
    }
    // Option tables with groups the lobby lacks (they never spawn until it has them).
    for (const auto& [name, groups] : tables.options) {
      const bool any = std::any_of(groups.begin(), groups.end(), [](const std::vector<std::string>& g) {
        return !g.empty();
      });
      const std::string key = AdaptiveOptionKey(name);
      if ((any || groups.size() > 1) && !have(key)) {
        out.push_back(make(key, -1));
      }
    }
    for (const ScriptGroupLoop& loop : loops) {
      if (!have(loop.key)) {
        out.push_back(make(loop.key, -1));
      }
    }
    return out;
  }

  std::string WithOption(
    const std::string& optionsText,
    const LobbyOptionInfo& option
  )
  {
    std::vector<LobbyValueText> values;
    for (const LobbyOptionInfo::Value& value : option.values) {
      LobbyValueText text;
      if (value.number) {
        char number[32];
        (void)std::snprintf(number, sizeof(number), "%.14g", value.numberKey);
        text.key = number;
      } else {
        text.key = "'" + value.key + "'";
      }
      text.text = value.text;
      text.help = value.help;
      values.push_back(std::move(text));
    }
    return WithLobbyOptionWritten(
      optionsText,
      option.key,
      option.label.empty() ? ReadableKey(option.key) : option.label,
      option.help,
      option.defaultIndex,
      values
    );
  }

  int TableGroupOfChoice(
    const LobbyOptionInfo::Value& value
  )
  {
    if (!value.number) {
      return -1;
    }
    const int key = static_cast<int>(value.numberKey);
    return key >= 2 ? key - 2 : -1;
  }

  std::string LoopGroupOfChoice(
    const ScriptGroupLoop& loop,
    const LobbyOptionInfo::Value& value
  )
  {
    if (!value.number) {
      return {};
    }
    const int key = static_cast<int>(value.numberKey);
    return key >= loop.from ? loop.prefix + std::to_string(key) : std::string();
  }

  std::vector<MadeGroup> GroupsMadeByChoice(
    const std::string& script,
    const std::vector<LobbyOptionInfo>& lobby,
    const std::string& key,
    const int valueIndex
  )
  {
    std::vector<MadeGroup> made;
    std::vector<std::string> names;
    for (const ScriptGroupCreation& creation : ScriptGroupCreations(script)) {
      if (!creation.prefix && std::find(names.begin(), names.end(), creation.name) == names.end()) {
        names.push_back(creation.name);
      }
    }
    for (const std::string& name : names) {
      const GroupLobbyRule rule = LobbyRuleOfGroup(script, lobby, name);
      const auto k = std::find(rule.keys.begin(), rule.keys.end(), key);
      if (k == rule.keys.end()) {
        continue;
      }
      const std::size_t at = static_cast<std::size_t>(k - rule.keys.begin());
      MadeGroup group;
      group.group = name;
      bool any = false;
      bool sure = false;
      for (const GroupLobbyRule::Case& c : rule.cases) {
        if (c.picks[at] != valueIndex || c.made == GroupLobbyRule::Made::No) {
          continue;
        }
        any = true;
        sure = sure || c.made == GroupLobbyRule::Made::Yes;
        group.wreck = group.wreck || c.asWreck;
        group.unit = group.unit || c.asUnit;
      }
      if (any) {
        group.maybe = !sure;
        made.push_back(std::move(group));
      }
    }
    return made;
  }

  LobbyOptionInfo::Value NextLevelValue(
    const LobbyOptionInfo& option,
    const std::string& text
  )
  {
    LobbyOptionInfo::Value value;
    double highest = 0.0;
    for (const LobbyOptionInfo::Value& v : option.values) {
      if (v.number) {
        highest = std::max(highest, v.numberKey);
      }
    }
    value.number = true;
    value.numberKey = highest + 1.0;
    char number[32];
    (void)std::snprintf(number, sizeof(number), "%.14g", value.numberKey);
    value.key = number;
    value.text = text;
    return value;
  }
} // namespace faf::editor
