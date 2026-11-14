#include "editor/doc/EdScenarioInfo.h"

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
