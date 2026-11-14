#include "editor/tools/EdBuilders.h"

#include <cctype>

namespace faf::editor
{
  namespace
  {
    /** The index after the value starting at `at`: a quoted string, a {...} table, or text up to a top-level comma. */
    [[nodiscard]] std::size_t ValueEnd(
      const std::string& text,
      std::size_t at
    )
    {
      int depth = 0;
      for (; at < text.size(); ++at) {
        const char c = text[at];
        if (c == '\'' || c == '"') {
          for (++at; at < text.size() && text[at] != c; ++at) {
            if (text[at] == '\\') {
              ++at;
            }
          }
          continue;
        }
        if (c == '{') {
          ++depth;
        } else if (c == '}') {
          if (depth == 0) {
            return at;
          }
          --depth;
        } else if (c == ',' && depth == 0) {
          return at;
        }
      }
      return at;
    }

    /** The index of the brace closing the one at `open` (strings skipped), or the text's end. */
    [[nodiscard]] std::size_t MatchBrace(
      const std::string& text,
      std::size_t open
    )
    {
      int depth = 0;
      for (std::size_t at = open; at < text.size(); ++at) {
        const char c = text[at];
        if (c == '\'' || c == '"') {
          for (++at; at < text.size() && text[at] != c; ++at) {
            if (text[at] == '\\') {
              ++at;
            }
          }
          continue;
        }
        if (c == '{') {
          ++depth;
        } else if (c == '}' && --depth == 0) {
          return at;
        }
      }
      return text.size();
    }

    [[nodiscard]] std::string Trim(
      const std::string& text
    )
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

    /** `key = value, ...` pairs of the table body between `from` and `to` (the braces excluded). */
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> Pairs(
      const std::string& text,
      std::size_t from,
      const std::size_t to
    )
    {
      std::vector<std::pair<std::string, std::string>> out;
      while (from < to) {
        while (from < to && (std::isspace(static_cast<unsigned char>(text[from])) != 0 || text[from] == ',')) {
          ++from;
        }
        if (from >= to) {
          break;
        }
        const std::size_t equals = text.find('=', from);
        if (equals == std::string::npos || equals >= to) {
          break;
        }
        std::string key = Trim(text.substr(from, equals - from));
        if (key.size() >= 4 && key.front() == '[' && key.back() == ']') {
          key = Trim(key.substr(1, key.size() - 2));
        }
        if (key.size() >= 2 && (key.front() == '\'' || key.front() == '"')) {
          key = key.substr(1, key.size() - 2);
        }
        const std::size_t end = std::min(ValueEnd(text, equals + 1), to);
        out.emplace_back(key, Trim(text.substr(equals + 1, end - equals - 1)));
        from = end + 1;
      }
      return out;
    }

    [[nodiscard]] std::string Quoted(
      const std::string& text
    )
    {
      return "'" + text + "'";
    }
  } // namespace

  std::string MissionBuilder::Get(
    const std::string& key
  ) const
  {
    for (const auto& [k, v] : fields) {
      if (k == key) {
        return v;
      }
    }
    return {};
  }

  void MissionBuilder::Set(
    const std::string& key,
    const std::string& value
  )
  {
    for (auto& [k, v] : fields) {
      if (k == key) {
        v = value;
        return;
      }
    }
    fields.emplace_back(key, value);
  }

  bool ParseBuilders(
    const std::string& text,
    std::vector<MissionBuilder>& builders,
    std::string& error
  )
  {
    builders.clear();
    if (Trim(text).empty()) {
      return true;
    }
    std::size_t at = text.find("Builders");
    while (at != std::string::npos && at > 0 &&
           (std::isalnum(static_cast<unsigned char>(text[at - 1])) != 0 || text[at - 1] == '_')) {
      at = text.find("Builders", at + 1);
    }
    if (at == std::string::npos) {
      return true; // a table without builders
    }
    const std::size_t open = text.find('{', at);
    if (open == std::string::npos) {
      error = "the Builders table has no {";
      return false;
    }
    const std::size_t close = MatchBrace(text, open);
    if (close >= text.size()) {
      error = "the Builders table isn't closed";
      return false;
    }
    for (const auto& [name, value] : Pairs(text, open + 1, close)) {
      if (value.empty() || value.front() != '{') {
        continue;
      }
      MissionBuilder builder;
      builder.name = name;
      const std::size_t inner = MatchBrace(value, 0);
      builder.fields = Pairs(value, 1, inner);
      builders.push_back(std::move(builder));
    }
    return true;
  }

  std::string FormatBuilders(
    const std::vector<MissionBuilder>& builders
  )
  {
    std::string out = "{\n                    Builders = {\n";
    for (const MissionBuilder& builder : builders) {
      out += "                        ['" + builder.name + "'] = {\n";
      for (const auto& [key, value] : builder.fields) {
        out += "                            " + key + " = " + value + ",\n";
      }
      out += "                        },\n";
    }
    out += "                    },\n                }";
    return out;
  }

  MissionBuilder NewBuilder(
    const std::string& name,
    const std::string& platoonTemplate,
    const std::string& location
  )
  {
    MissionBuilder builder;
    builder.name = name;
    builder.Set("PlatoonTemplate", Quoted(platoonTemplate));
    builder.Set("Priority", "100");
    builder.Set("InstanceCount", "1");
    builder.Set("LocationType", Quoted(location));
    builder.Set("PlatoonType", "'Land'");
    builder.Set("RequiresConstruction", "true");
    builder.Set("BuildConditions", "{}");
    return builder;
  }
} // namespace faf::editor
