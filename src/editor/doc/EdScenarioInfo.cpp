#include "editor/doc/EdScenarioInfo.h"

#include <algorithm>
#include <cctype>

namespace faf::editor
{
  namespace
  {
    /** Where `key = ` starts its value in `s` (the first such key as a whole word), or npos. */
    std::size_t ValueStart(
      const std::string& s,
      const std::string& key,
      std::size_t& keyAt
    )
    {
      std::size_t at = 0;
      while ((at = s.find(key, at)) != std::string::npos) {
        const bool wordStart =
          at == 0 || !(std::isalnum(static_cast<unsigned char>(s[at - 1])) != 0 || s[at - 1] == '_');
        std::size_t k = at + key.size();
        const bool wordEnd = k >= s.size() || !(std::isalnum(static_cast<unsigned char>(s[k])) != 0 || s[k] == '_');
        // Not inside a comment line.
        const std::size_t lineStart = s.rfind('\n', at);
        const std::size_t from = lineStart == std::string::npos ? 0 : lineStart + 1;
        const bool commented = s.find("--", from) < at;
        if (wordStart && wordEnd && !commented) {
          while (k < s.size() && (s[k] == ' ' || s[k] == '\t')) {
            ++k;
          }
          if (k < s.size() && s[k] == '=' && (k + 1 >= s.size() || s[k + 1] != '=')) {
            ++k;
            while (k < s.size() && (s[k] == ' ' || s[k] == '\t')) {
              ++k;
            }
            keyAt = at;
            return k;
          }
        }
        at += key.size();
      }
      return std::string::npos;
    }

    /** The end of the value starting at `at` (past a quoted string, or up to ',' / end of line / '}'). */
    std::size_t ValueEnd(
      const std::string& s,
      const std::size_t at
    )
    {
      if (at < s.size() && (s[at] == '\'' || s[at] == '"')) {
        const char quote = s[at];
        for (std::size_t i = at + 1; i < s.size(); ++i) {
          if (s[i] == '\\') {
            ++i;
          } else if (s[i] == quote) {
            return i + 1;
          }
        }
        return s.size();
      }
      std::size_t i = at;
      while (i < s.size() && s[i] != ',' && s[i] != '\n' && s[i] != '\r' && s[i] != '}' &&
             !(s[i] == '-' && i + 1 < s.size() && s[i + 1] == '-')) {
        ++i;
      }
      while (i > at && (s[i - 1] == ' ' || s[i - 1] == '\t')) {
        --i;
      }
      return i;
    }

    std::string Quoted(
      const std::string& text
    )
    {
      std::string out = "\"";
      for (const char c : text) {
        if (c == '"' || c == '\\') {
          out += '\\';
          out += c;
        } else if (c == '\n') {
          out += "\\n";
        } else if (c != '\r') {
          out += c;
        }
      }
      return out + "\"";
    }
  } // namespace

  const std::vector<ScenarioField>& ScenarioFields()
  {
    static const std::vector<ScenarioField> k = {
      {"name", "Name", true},
      {"description", "Description", true},
      {"type", "Type", true},
      {"map_version", "Version", false},
      {"norushradius", "No-rush radius", false},
    };
    return k;
  }

  bool ReadScenarioField(
    const std::string& scenario,
    const std::string& key,
    std::string& value
  )
  {
    std::size_t keyAt = 0;
    const std::size_t at = ValueStart(scenario, key, keyAt);
    if (at == std::string::npos) {
      return false;
    }
    const std::size_t end = ValueEnd(scenario, at);
    std::string raw = scenario.substr(at, end - at);
    if (!raw.empty() && (raw.front() == '\'' || raw.front() == '"')) {
      std::string out;
      for (std::size_t i = 1; i + 1 < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 2 < raw.size()) {
          const char e = raw[++i];
          out += e == 'n' ? '\n' : e;
        } else {
          out += raw[i];
        }
      }
      value = out;
    } else {
      value = raw;
    }
    return true;
  }

  std::string WithScenarioField(
    const std::string& scenario,
    const std::string& key,
    const std::string& value,
    const bool text
  )
  {
    std::string written = text ? Quoted(value) : value;
    if (!text) {
      // A number only (the scenario is Lua run by the game).
      const bool number = !value.empty() && value.find_first_not_of("0123456789.-") == std::string::npos;
      if (!number) {
        return scenario;
      }
    }
    std::size_t keyAt = 0;
    const std::size_t at = ValueStart(scenario, key, keyAt);
    if (at != std::string::npos) {
      return scenario.substr(0, at) + written + scenario.substr(ValueEnd(scenario, at));
    }
    // None yet: the first line inside ScenarioInfo = {.
    const std::size_t open = scenario.find("ScenarioInfo");
    const std::size_t brace = open == std::string::npos ? std::string::npos : scenario.find('{', open);
    if (brace == std::string::npos) {
      return scenario;
    }
    const std::string newline = scenario.find("\r\n") != std::string::npos ? "\r\n" : "\n";
    return scenario.substr(0, brace + 1) + newline + "    " + key + " = " + written + "," + scenario.substr(brace + 1);
  }

  namespace
  {
    /** The index past the end of the table opening at `open` ('{'), strings skipped; npos when it doesn't close. */
    std::size_t TableEnd(
      const std::string& s,
      const std::size_t open
    )
    {
      int depth = 0;
      for (std::size_t i = open; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '\'' || c == '"') {
          for (++i; i < s.size() && s[i] != c; ++i) {
            if (s[i] == '\\') {
              ++i;
            }
          }
        } else if (c == '-' && i + 1 < s.size() && s[i + 1] == '-') {
          while (i < s.size() && s[i] != '\n') {
            ++i;
          }
        } else if (c == '{') {
          ++depth;
        } else if (c == '}' && --depth == 0) {
          return i + 1;
        }
      }
      return std::string::npos;
    }

    /** The standard configuration's table: [open, end) of its braces; false when the file has none. */
    bool StandardTable(
      const std::string& s,
      std::size_t& open,
      std::size_t& end
    )
    {
      std::size_t at = s.find("['standard']");
      if (at == std::string::npos) {
        at = s.find("[\"standard\"]");
      }
      if (at == std::string::npos) {
        return false;
      }
      open = s.find('{', at);
      if (open == std::string::npos) {
        return false;
      }
      end = TableEnd(s, open);
      return end != std::string::npos;
    }

    /** `factions = {...}` directly inside [from, to): its key's start and its table's [open, end); false when none. */
    bool FactionsIn(
      const std::string& s,
      const std::size_t from,
      const std::size_t to,
      std::size_t& keyAt,
      std::size_t& open,
      std::size_t& end
    )
    {
      int depth = 0;
      for (std::size_t i = from; i < to; ++i) {
        const char c = s[i];
        if (c == '\'' || c == '"') {
          for (++i; i < to && s[i] != c; ++i) {
            if (s[i] == '\\') {
              ++i;
            }
          }
        } else if (c == '{') {
          ++depth;
        } else if (c == '}') {
          --depth;
        } else if (
          depth == 0 && s.compare(i, 8, "factions") == 0 &&
          (i == 0 || !(std::isalnum(static_cast<unsigned char>(s[i - 1])) != 0 || s[i - 1] == '_'))
        ) {
          std::size_t k = i + 8;
          while (k < to && (s[k] == ' ' || s[k] == '\t')) {
            ++k;
          }
          if (k < to && s[k] == '=') {
            open = s.find('{', k);
            if (open == std::string::npos || open >= to) {
              return false;
            }
            end = TableEnd(s, open);
            keyAt = i;
            return end != std::string::npos;
          }
        }
      }
      return false;
    }
  } // namespace

  const std::vector<std::string>& FactionKeys()
  {
    static const std::vector<std::string> k = {"uef", "aeon", "cybran", "seraphim"};
    return k;
  }

  SlotFactions ReadSlotFactions(
    const std::string& scenario
  )
  {
    SlotFactions out;
    std::size_t open = 0;
    std::size_t end = 0;
    std::size_t keyAt = 0;
    std::size_t fOpen = 0;
    std::size_t fEnd = 0;
    if (!StandardTable(scenario, open, end) || !FactionsIn(scenario, open + 1, end - 1, keyAt, fOpen, fEnd)) {
      return out;
    }
    // Each inner table: its quoted keys.
    for (std::size_t i = fOpen + 1; i < fEnd - 1; ++i) {
      if (scenario[i] != '{') {
        continue;
      }
      const std::size_t innerEnd = TableEnd(scenario, i);
      std::vector<std::string> slot;
      for (std::size_t k = i + 1; innerEnd != std::string::npos && k < innerEnd - 1; ++k) {
        const char c = scenario[k];
        if (c == '\'' || c == '"') {
          const std::size_t close = scenario.find(c, k + 1);
          if (close == std::string::npos) {
            break;
          }
          std::string key = scenario.substr(k + 1, close - k - 1);
          std::transform(key.begin(), key.end(), key.begin(), [](const unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
          });
          slot.push_back(key);
          k = close;
        }
      }
      out.push_back(std::move(slot));
      i = innerEnd == std::string::npos ? fEnd : innerEnd - 1;
    }
    return out;
  }

  std::string WithSlotFactions(
    const std::string& scenario,
    const SlotFactions& factions
  )
  {
    std::size_t open = 0;
    std::size_t end = 0;
    if (!StandardTable(scenario, open, end)) {
      return scenario;
    }
    // Restricted at all? (a slot with none or all four offers all)
    bool restricted = false;
    for (const std::vector<std::string>& slot : factions) {
      restricted = restricted || (!slot.empty() && slot.size() < FactionKeys().size());
    }
    std::string table;
    if (restricted) {
      table = "factions = {";
      for (std::size_t i = 0; i < factions.size(); ++i) {
        const std::vector<std::string>& slot =
          factions[i].empty() || factions[i].size() >= FactionKeys().size() ? FactionKeys() : factions[i];
        table += std::string(i > 0 ? ", " : " ") + "{";
        for (std::size_t k = 0; k < slot.size(); ++k) {
          table += std::string(k > 0 ? ", " : " ") + "'" + slot[k] + "'";
        }
        table += " }";
      }
      table += " }";
    }
    std::size_t keyAt = 0;
    std::size_t fOpen = 0;
    std::size_t fEnd = 0;
    if (FactionsIn(scenario, open + 1, end - 1, keyAt, fOpen, fEnd)) {
      std::size_t after = fEnd;
      if (!restricted) {
        // The key goes with its comma.
        while (after < scenario.size() && (scenario[after] == ' ' || scenario[after] == '\t')) {
          ++after;
        }
        if (after < scenario.size() && scenario[after] == ',') {
          ++after;
        }
      }
      return scenario.substr(0, keyAt) + table + scenario.substr(after);
    }
    if (!restricted) {
      return scenario;
    }
    // Added after the table's opening brace.
    return scenario.substr(0, open + 1) + " " + table + "," + scenario.substr(open + 1);
  }

  std::string WithoutLoc(
    const std::string& text
  )
  {
    if (text.rfind("<LOC", 0) == 0) {
      const std::size_t close = text.find('>');
      return close == std::string::npos ? std::string() : text.substr(close + 1);
    }
    return text;
  }
} // namespace faf::editor
