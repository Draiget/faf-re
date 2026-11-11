#include "editor/doc/EdAdaptiveTables.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <optional>

namespace faf::editor
{
  namespace
  {
    /** A Lua value as far as the tables go: a string or number (its text), or a table of values. */
    struct Value
    {
      std::string atom;
      bool isTable = false;
      std::vector<Value> items;
      /** Where it is in the text: from its first character to past its last. */
      std::size_t start = 0;
      std::size_t end = 0;
    };

    /** Reads `_tables.lua`'s simple Lua: comments, numbers, quoted strings, nested tables, commas and semicolons. */
    class Reader
    {
    public:
      explicit Reader(
        const std::string& text
      )
        : mText(text)
      {}

      void SkipSpace()
      {
        while (mAt < mText.size()) {
          if (std::isspace(static_cast<unsigned char>(mText[mAt])) != 0) {
            ++mAt;
          } else if (mText.compare(mAt, 4, "--[[") == 0) {
            const std::size_t end = mText.find("]]", mAt + 4);
            mAt = end == std::string::npos ? mText.size() : end + 2;
          } else if (mText.compare(mAt, 2, "--") == 0) {
            const std::size_t end = mText.find('\n', mAt);
            mAt = end == std::string::npos ? mText.size() : end + 1;
          } else {
            break;
          }
        }
      }

      std::optional<Value> ReadValue(
        std::string& error
      )
      {
        SkipSpace();
        if (mAt >= mText.size()) {
          error = "the file ends inside a value";
          return std::nullopt;
        }
        const char c = mText[mAt];
        Value value;
        value.start = mAt;
        if (c == '{') {
          value.isTable = true;
          ++mAt;
          for (;;) {
            SkipSpace();
            if (mAt < mText.size() && mText[mAt] == '}') {
              ++mAt;
              value.end = mAt;
              return value;
            }
            std::optional<Value> item = ReadValue(error);
            if (!item) {
              return std::nullopt;
            }
            value.items.push_back(std::move(*item));
            SkipSpace();
            if (mAt < mText.size() && (mText[mAt] == ',' || mText[mAt] == ';')) {
              ++mAt;
            }
          }
        }
        if (c == '\'' || c == '"') {
          const std::size_t end = mText.find(c, mAt + 1);
          if (end == std::string::npos) {
            error = "a string doesn't end";
            return std::nullopt;
          }
          value.atom = mText.substr(mAt, end + 1 - mAt);
          mAt = end + 1;
          value.end = mAt;
          return value;
        }
        const std::size_t start = mAt;
        while (mAt < mText.size() &&
               (std::isalnum(static_cast<unsigned char>(mText[mAt])) != 0 || mText[mAt] == '.' || mText[mAt] == '-' ||
                mText[mAt] == '_')) {
          ++mAt;
        }
        if (mAt == start) {
          error = std::string("unexpected '") + c + "'";
          return std::nullopt;
        }
        value.atom = mText.substr(start, mAt - start);
        value.end = mAt;
        return value;
      }

      std::size_t& At() noexcept
      {
        return mAt;
      }

    private:
      const std::string& mText;
      std::size_t mAt = 0;
    };

    /** Each top-level `name = value`: its name, where its value starts and ends, and the value. */
    struct Assignment
    {
      std::string name;
      std::size_t valueStart = 0;
      std::size_t valueEnd = 0;
      Value value;
    };

    bool ReadAssignments(
      const std::string& text,
      std::vector<Assignment>& out,
      std::string& error
    )
    {
      Reader reader(text);
      for (;;) {
        reader.SkipSpace();
        std::size_t& at = reader.At();
        if (at >= text.size()) {
          return true;
        }
        const std::size_t nameStart = at;
        while (at < text.size() && (std::isalnum(static_cast<unsigned char>(text[at])) != 0 || text[at] == '_')) {
          ++at;
        }
        if (at == nameStart) {
          error = "expected a name at offset " + std::to_string(at);
          return false;
        }
        Assignment assignment;
        assignment.name = text.substr(nameStart, at - nameStart);
        reader.SkipSpace();
        if (at >= text.size() || text[at] != '=') {
          error = "expected '=' after " + assignment.name;
          return false;
        }
        ++at;
        reader.SkipSpace();
        assignment.valueStart = at;
        std::optional<Value> value = reader.ReadValue(error);
        if (!value) {
          error = assignment.name + ": " + error;
          return false;
        }
        assignment.valueEnd = at;
        assignment.value = std::move(*value);
        out.push_back(std::move(assignment));
      }
    }

    std::vector<std::string> Names(
      const Value& list,
      const bool hydro
    )
    {
      std::vector<std::string> names;
      for (const Value& item : list.items) {
        if (!item.isTable) {
          names.push_back(AdaptiveMarkerName(item.atom, hydro));
        }
      }
      return names;
    }

    std::vector<std::vector<std::string>> Groups(
      const Value& table,
      const bool hydro
    )
    {
      std::vector<std::vector<std::string>> groups;
      for (const Value& item : table.items) {
        groups.push_back(
          item.isTable ? Names(item, hydro) : std::vector<std::string>{AdaptiveMarkerName(item.atom, hydro)}
        );
      }
      return groups;
    }

    std::string ListText(
      const std::vector<std::string>& names,
      const bool hydro
    )
    {
      std::string text = "{";
      for (std::size_t i = 0; i < names.size(); ++i) {
        const std::string entry = AdaptiveEntry(names[i], hydro);
        text += (i > 0 ? "," : "") + (entry.empty() ? "'" + names[i] + "'" : entry);
      }
      return text + "}";
    }

    /** Per-army tables one army a line, as the template lays them out (the line is the army's number). */
    std::string ArmyText(
      const std::vector<std::vector<std::string>>& armies,
      const bool hydro
    )
    {
      std::string text = "{";
      for (std::size_t i = 0; i < armies.size(); ++i) {
        text += (i > 0 ? ",\n    " : "   ") + ListText(armies[i], hydro);
      }
      return text + "}";
    }

    std::string GroupsText(
      const std::vector<std::vector<std::string>>& groups,
      const bool hydro
    )
    {
      std::string text = "{";
      for (std::size_t i = 0; i < groups.size(); ++i) {
        text += (i > 0 ? "," : "") + ListText(groups[i], hydro);
      }
      return text + "}";
    }

    /**
     * A table of rows (an army's mexes, an option's groups) written into its text as it is (user ask 2026-11-11: the
     * FAF Map Editor generated these files; replace only what changed): a row whose entries are the same keeps its
     * text, a changed one is written, and what lies between the rows (commas, line breaks, the template's alignment,
     * comments) stays; a new row takes the separator before the last one, a dropped row goes with the separator before
     * it. `fresh` is the whole table written anew, for a value that isn't a table of tables.
     */
    std::string RowsWithin(
      const std::string& text,
      const Value& table,
      const std::vector<std::vector<std::string>>& rows,
      const bool hydro,
      const std::string& fresh,
      const char* const separator
    )
    {
      if (!table.isTable || table.items.empty() || rows.empty()) {
        return fresh;
      }
      for (const Value& item : table.items) {
        if (!item.isTable) {
          return fresh;
        }
      }
      const std::vector<Value>& items = table.items;
      const auto between = [&](const std::size_t from, const std::size_t to) {
        return text.substr(from, to - from);
      };
      // A new row's separator: a comma, and the last row's line break and indentation (not a comment by it).
      std::string added = separator;
      if (items.size() >= 2) {
        const std::string last = between(items[items.size() - 2].end, items[items.size() - 1].start);
        const std::size_t newline = last.rfind('\n');
        added = newline == std::string::npos ? last : "," + last.substr(newline);
      }
      std::string out = "{" + between(table.start + 1, items[0].start);
      for (std::size_t r = 0; r < rows.size(); ++r) {
        if (r > 0) {
          out += r < items.size() ? between(items[r - 1].end, items[r].start) : added;
        }
        if (r < items.size() && Names(items[r], hydro) == rows[r]) {
          out += between(items[r].start, items[r].end);
        } else if (r < items.size()) {
          // A changed row: the entries it keeps as written (`00` stays `00`), the new ones written.
          std::string row = "{";
          for (std::size_t e = 0; e < rows[r].size(); ++e) {
            std::string entry;
            for (const Value& was : items[r].items) {
              if (!was.isTable && AdaptiveMarkerName(was.atom, hydro) == rows[r][e]) {
                entry = was.atom;
                break;
              }
            }
            if (entry.empty()) {
              entry = ListText({rows[r][e]}, hydro);
              entry = entry.substr(1, entry.size() - 2); // "{7}" is 7
            }
            row += (e > 0 ? "," : "") + entry;
          }
          out += row + "}";
        } else {
          out += ListText(rows[r], hydro);
        }
      }
      // What followed the table's last row (a trailing comma, a comment) up to the closing brace; dropped rows don't
      // come.
      out += between(items.back().end, table.end - 1);
      return out + "}";
    }
  } // namespace

  namespace
  {
    /**
     * Where an `_options.lua` entry with `key = '<key>'` (in `options = { ... }`) starts and ends: from its `{` to past
     * its `}`, its comma and the rest of that line. Strings and comments are skipped; `close` is where `options`' own
     * table ends (the last `}` at the outermost level), or npos.
     */
    struct OptionSpan
    {
      std::size_t from = std::string::npos;
      std::size_t to = std::string::npos;
      std::size_t close = std::string::npos;
    };

    OptionSpan FindOptionSpan(
      const std::string& text,
      const std::string& key
    )
    {
      OptionSpan span;
      std::vector<std::size_t> opens;
      std::size_t entry = std::string::npos;
      const auto longClose = [&](const std::size_t at) {
        // A long bracket [[ ... ]] or [=[ ... ]=]: its end, or the text's end.
        std::size_t level = 0;
        while (at + 1 + level < text.size() && text[at + 1 + level] == '=') {
          ++level;
        }
        const std::string end = "]" + std::string(level, '=') + "]";
        const std::size_t found = text.find(end, at);
        return found == std::string::npos ? text.size() : found + end.size();
      };
      for (std::size_t i = 0; i < text.size();) {
        const char c = text[i];
        if (c == '-' && i + 1 < text.size() && text[i + 1] == '-') {
          if (
            i + 2 < text.size() && text[i + 2] == '[' && i + 3 < text.size() &&
            (text[i + 3] == '[' || text[i + 3] == '=')
          ) {
            i = longClose(i + 2);
          } else {
            const std::size_t line = text.find('\n', i);
            i = line == std::string::npos ? text.size() : line;
          }
          continue;
        }
        if (c == '"' || c == '\'') {
          std::size_t j = i + 1;
          while (j < text.size() && text[j] != c && text[j] != '\n') {
            j += text[j] == '\\' ? 2 : 1;
          }
          // `key = '<key>'` one level into options' table: that entry.
          if (
            opens.size() == 2 && entry == std::string::npos && j < text.size() &&
            text.compare(i + 1, j - i - 1, key) == 0 && j - i - 1 == key.size()
          ) {
            std::size_t back = i;
            while (back > 0 && std::isspace(static_cast<unsigned char>(text[back - 1])) != 0) {
              --back;
            }
            if (back > 0 && text[back - 1] == '=') {
              --back;
              while (back > 0 && std::isspace(static_cast<unsigned char>(text[back - 1])) != 0) {
                --back;
              }
              if (
                back >= 3 && text.compare(back - 3, 3, "key") == 0 &&
                (back == 3 || (std::isalnum(static_cast<unsigned char>(text[back - 4])) == 0 && text[back - 4] != '_'))
              ) {
                entry = opens.back();
              }
            }
          }
          i = j + 1;
          continue;
        }
        if (c == '[' && i + 1 < text.size() && (text[i + 1] == '[' || text[i + 1] == '=')) {
          i = longClose(i);
          continue;
        }
        if (c == '{') {
          opens.push_back(i);
        } else if (c == '}' && !opens.empty()) {
          const std::size_t open = opens.back();
          opens.pop_back();
          if (open == entry && span.from == std::string::npos) {
            span.from = open;
            std::size_t end = i + 1;
            while (end < text.size() && (text[end] == ' ' || text[end] == '\t')) {
              ++end;
            }
            if (end < text.size() && (text[end] == ',' || text[end] == ';')) {
              ++end;
            }
            while (end < text.size() && (text[end] == ' ' || text[end] == '\t' || text[end] == '\r')) {
              ++end;
            }
            if (end < text.size() && text[end] == '\n') {
              ++end;
            }
            span.to = end;
          }
          if (opens.empty()) {
            span.close = i;
          }
        }
        ++i;
      }
      return span;
    }

    /** A number after `name =` inside text[from, to), or `otherwise`. */
    int NumberAfter(
      const std::string& text,
      const std::size_t from,
      const std::size_t to,
      const std::string& name,
      const int otherwise
    )
    {
      for (std::size_t at = text.find(name, from); at != std::string::npos && at < to; at = text.find(name, at + 1)) {
        std::size_t i = at + name.size();
        while (i < to && std::isspace(static_cast<unsigned char>(text[i])) != 0) {
          ++i;
        }
        if (i < to && text[i] == '=') {
          ++i;
          while (i < to && std::isspace(static_cast<unsigned char>(text[i])) != 0) {
            ++i;
          }
          if (i < to && std::isdigit(static_cast<unsigned char>(text[i])) != 0) {
            return std::atoi(text.c_str() + i);
          }
        }
      }
      return otherwise;
    }
  } // namespace

  std::string AdaptiveOptionKey(
    const std::string& tableName
  )
  {
    std::string key;
    for (const char c : tableName) {
      if (std::isupper(static_cast<unsigned char>(c)) != 0) {
        key += '_';
        key += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      } else {
        key += c;
      }
    }
    return key;
  }

  LobbyOption FindLobbyOption(
    const std::string& text,
    const std::string& key
  )
  {
    LobbyOption option;
    const OptionSpan span = FindOptionSpan(text, key);
    if (span.from == std::string::npos) {
      return option;
    }
    option.found = true;
    option.defaultKey = NumberAfter(text, span.from, span.to, "default", 0);
    // The values: one `text =` each (the option's own label and help are `label =` and `help =`).
    const std::size_t values = text.find("values", span.from);
    for (std::size_t at = values; at != std::string::npos && at < span.to; at = text.find("text", at + 4)) {
      std::size_t i = at + 4;
      while (i < span.to && std::isspace(static_cast<unsigned char>(text[i])) != 0) {
        ++i;
      }
      const bool word = at == 0 || (std::isalnum(static_cast<unsigned char>(text[at - 1])) == 0 && text[at - 1] != '_');
      if (word && i < span.to && text[i] == '=') {
        ++option.values;
      }
    }
    return option;
  }

  std::string WithLobbyOption(
    const std::string& text,
    const std::string& key,
    const std::string& label,
    const bool hydro,
    const std::vector<int>& groupSizes
  )
  {
    const OptionSpan span = FindOptionSpan(text, key);
    const int groups = static_cast<int>(groupSizes.size());
    int defaultKey = 1;
    if (span.from != std::string::npos) {
      const int kept = NumberAfter(text, span.from, span.to, "default", 1);
      defaultKey = kept >= 1 && kept <= groups + 1 ? kept : 1;
    }
    const std::string what = hydro ? "hydrocarbons" : "mexes";
    std::string lower = label;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    std::string entry = "{\n    default = " + std::to_string(defaultKey) + ",\n    label = \"" + label +
      "\",\n    help = \"Which of the " + lower + " spawn.\",\n    key = '" + key + "',\n    pref = '" + key +
      "',\n    values = {\n";
    entry += "        { text = \"none\", help = \"No " + lower + ".\", key = 1, },\n";
    int count = 0;
    for (int g = 1; g <= groups; ++g) {
      count += groupSizes[static_cast<std::size_t>(g - 1)];
      const std::string name = g == 1 ? "group 1" : "groups 1-" + std::to_string(g);
      entry += "        { text = \"" + name + "\", help = \"" +
        (g == 1 ? std::string("Group 1 spawns") : "Groups 1 to " + std::to_string(g) + " spawn") + " (" +
        std::to_string(count) + " " + what + ").\", key = " + std::to_string(g + 1) + ", },\n";
    }
    entry += "    },\n},\n";
    if (span.from != std::string::npos) {
      return text.substr(0, span.from) + entry + text.substr(span.to);
    }
    if (span.close == std::string::npos) {
      // No options table to add it to: a new file (an existing text that isn't one is kept above it).
      return (text.empty() ? std::string() : text + "\n") + "options = {\n\n" + entry + "\n}\n";
    }
    // Before options' closing brace, after a comma for the entry before it.
    std::size_t before = span.close;
    while (before > 0 && std::isspace(static_cast<unsigned char>(text[before - 1])) != 0) {
      --before;
    }
    const bool needComma = before > 0 && text[before - 1] == '}';
    return text.substr(0, before) + (needComma ? "," : "") + "\n\n" + entry + text.substr(span.close);
  }

  std::string WithLobbyOptionValues(
    const std::string& text,
    const std::string& key,
    const std::string& label,
    const std::string& help,
    const std::vector<std::pair<std::string, std::string>>& values
  )
  {
    const OptionSpan span = FindOptionSpan(text, key);
    const int count = static_cast<int>(values.size());
    int defaultKey = 1;
    if (span.from != std::string::npos) {
      const int kept = NumberAfter(text, span.from, span.to, "default", 1);
      defaultKey = kept >= 1 && kept <= count ? kept : 1;
    }
    const auto quoted = [](std::string s) {
      std::string out;
      for (const char c : s) {
        out += c == '"' ? std::string("\\\"") : std::string(1, c);
      }
      return out;
    };
    std::string entry = "{\n    default = " + std::to_string(defaultKey) + ",\n    label = \"" + quoted(label) +
      "\",\n    help = \"" + quoted(help) + "\",\n    key = '" + key + "',\n    pref = '" + key +
      "',\n    values = {\n";
    for (int i = 0; i < count; ++i) {
      entry += "        { text = \"" + quoted(values[static_cast<std::size_t>(i)].first) + "\", help = \"" +
        quoted(values[static_cast<std::size_t>(i)].second) + "\", key = " + std::to_string(i + 1) + ", },\n";
    }
    entry += "    },\n},\n";
    if (span.from != std::string::npos) {
      return text.substr(0, span.from) + entry + text.substr(span.to);
    }
    if (span.close == std::string::npos) {
      return (text.empty() ? std::string() : text + "\n") + "options = {\n\n" + entry + "\n}\n";
    }
    std::size_t before = span.close;
    while (before > 0 && std::isspace(static_cast<unsigned char>(text[before - 1])) != 0) {
      --before;
    }
    const bool needComma = before > 0 && text[before - 1] == '}';
    return text.substr(0, before) + (needComma ? "," : "") + "\n\n" + entry + text.substr(span.close);
  }

  std::string WithLobbyOptionWritten(
    const std::string& text,
    const std::string& key,
    const std::string& label,
    const std::string& help,
    const int defaultIndex,
    const std::vector<LobbyValueText>& values
  )
  {
    const OptionSpan span = FindOptionSpan(text, key);
    const auto quoted = [](const std::string& s) {
      std::string out;
      for (const char c : s) {
        out += c == '"' ? std::string("\\\"") : c == '\\' ? std::string("\\\\") : std::string(1, c);
      }
      return out;
    };
    const int count = static_cast<int>(values.size());
    std::string entry =
      "{\n    default = " + std::to_string(defaultIndex >= 1 && defaultIndex <= count ? defaultIndex : 1) +
      ",\n    label = \"" + quoted(label) + "\",\n    help = \"" + quoted(help) + "\",\n    key = '" + key +
      "',\n    pref = '" + key + "',\n    values = {\n";
    for (const LobbyValueText& value : values) {
      entry += "        { text = \"" + quoted(value.text) + "\", help = \"" + quoted(value.help) +
        "\", key = " + value.key + ", },\n";
    }
    entry += "    },\n},\n";
    if (span.from != std::string::npos) {
      return text.substr(0, span.from) + entry + text.substr(span.to);
    }
    if (span.close == std::string::npos) {
      return (text.empty() ? std::string() : text + "\n") + "options = {\n\n" + entry + "\n}\n";
    }
    std::size_t before = span.close;
    while (before > 0 && std::isspace(static_cast<unsigned char>(text[before - 1])) != 0) {
      --before;
    }
    const bool needComma = before > 0 && text[before - 1] == '}';
    return text.substr(0, before) + (needComma ? "," : "") + "\n\n" + entry + text.substr(span.close);
  }

  std::string WithoutLobbyOption(
    const std::string& text,
    const std::string& key
  )
  {
    const OptionSpan span = FindOptionSpan(text, key);
    if (span.from == std::string::npos) {
      return text;
    }
    // The entry and its line's indentation.
    std::size_t from = span.from;
    while (from > 0 && (text[from - 1] == ' ' || text[from - 1] == '\t')) {
      --from;
    }
    return text.substr(0, from) + text.substr(span.to);
  }

  const std::vector<OptionTable>& KnownOptionTables()
  {
    static const std::vector<OptionTable> tables = {
      {"extraHydros", "Extra hydrocarbons", true},
      {"extraMexes", "Extra mexes", false},
      {"middleMexes", "Middle mexes", false},
      {"sideMexes", "Side mexes", false},
      {"underwaterMexes", "Underwater mexes", false},
      {"islandMexes", "Island mexes", false},
      {"expansionMexes", "Expansion mexes", false},
      {"coreMexes", "Core mexes", false},
      {"extraBaseMexes", "Extra base mexes", false},
      {"topSideMexes", "Top side mexes", false},
      {"bottomSideMexes", "Bottom side mexes", false},
    };
    return tables;
  }

  std::string AdaptiveTablesPath(
    const std::string& script
  )
  {
    const std::size_t end = script.find("_tables.lua");
    if (end == std::string::npos) {
      return {};
    }
    const std::size_t quote = script.find_last_of("'\"", end);
    if (quote == std::string::npos || end - quote > 400) {
      return {};
    }
    const std::string path = script.substr(quote + 1, end + std::string("_tables.lua").size() - quote - 1);
    return path.rfind("/maps/", 0) == 0 ? path : std::string();
  }

  std::string WithScenarioAdaptive(
    const std::string& scenario
  )
  {
    std::string out = scenario;
    if (const std::size_t at = out.find("AdaptiveMap"); at != std::string::npos) {
      const std::size_t equals = out.find('=', at);
      const std::size_t end = out.find_first_of(",\n", equals);
      if (equals != std::string::npos && end != std::string::npos) {
        out.replace(equals + 1, end - equals - 1, " true");
      }
      return out;
    }
    const std::size_t info = out.find("ScenarioInfo");
    const std::size_t brace = info == std::string::npos ? std::string::npos : out.find('{', info);
    if (brace == std::string::npos) {
      return out;
    }
    const std::size_t lineEnd = out.find('\n', brace);
    out.insert(lineEnd == std::string::npos ? brace + 1 : lineEnd + 1, "    AdaptiveMap = true,\n");
    return out;
  }

  std::string AdaptiveEntry(
    const std::string& markerName,
    const bool hydro
  )
  {
    const std::string prefix = hydro ? "Hydrocarbon " : "Mass ";
    if (markerName.rfind(prefix, 0) != 0 || markerName.size() == prefix.size()) {
      return {};
    }
    const std::string suffix = markerName.substr(prefix.size());
    bool digits = true;
    for (const char c : suffix) {
      digits = digits && std::isdigit(static_cast<unsigned char>(c)) != 0;
    }
    if (digits && suffix.size() <= 6) {
      // A number when the script's MassString gives this name back (two digits at least, no other leading zero).
      const int number = std::atoi(suffix.c_str());
      const std::string back = number > 9 ? std::to_string(number) : "0" + std::to_string(number);
      if (back == suffix) {
        return std::to_string(number);
      }
    }
    return "'" + suffix + "'";
  }

  std::string AdaptiveMarkerName(
    const std::string& entry,
    const bool hydro
  )
  {
    const std::string prefix = hydro ? "Hydrocarbon " : "Mass ";
    if (entry.size() >= 2 && (entry.front() == '\'' || entry.front() == '"')) {
      return prefix + entry.substr(1, entry.size() - 2);
    }
    const int number = std::atoi(entry.c_str());
    return prefix + (number > 9 ? std::to_string(number) : "0" + std::to_string(number));
  }

  bool ParseAdaptiveTables(
    const std::string& text,
    AdaptiveTables& tables,
    std::string& error
  )
  {
    std::vector<Assignment> assignments;
    if (!ReadAssignments(text, assignments, error)) {
      return false;
    }
    tables = AdaptiveTables{};
    for (const Assignment& assignment : assignments) {
      const Value& value = assignment.value;
      if (assignment.name == "maxPlayerOnMap" && !value.isTable) {
        tables.maxPlayers = std::atoi(value.atom.c_str());
      } else if (assignment.name == "spwnMexArmy" && value.isTable) {
        tables.mexArmy = Groups(value, false);
      } else if (assignment.name == "spwnHydroArmy" && value.isTable) {
        tables.hydroArmy = Groups(value, true);
      } else if (assignment.name == "forwardCrazyrushMexes" && value.isTable) {
        tables.forwardCrazyrush = Names(value, false);
      } else if (assignment.name == "crazyrushOneMexes" && value.isTable) {
        tables.crazyrushOne = Names(value, false);
      } else {
        for (const OptionTable& option : KnownOptionTables()) {
          if (assignment.name == option.name && value.isTable) {
            tables.options.emplace_back(option.name, Groups(value, option.hydro));
          }
        }
      }
    }
    return true;
  }

  std::string WithAdaptiveTables(
    const std::string& text,
    const AdaptiveTables& given
  )
  {
    // A line for every army up to maxPlayerOnMap: the script reads the line of each army not in the game with
    // table.getn, which fails on a missing one.
    AdaptiveTables tables = given;
    const std::size_t armies = static_cast<std::size_t>(std::max(tables.maxPlayers, 0));
    tables.mexArmy.resize(std::max(tables.mexArmy.size(), armies));
    tables.hydroArmy.resize(std::max(tables.hydroArmy.size(), armies));
    // Each table the script reads, as its text.
    std::vector<std::pair<std::string, std::string>> wanted = {
      {"maxPlayerOnMap", std::to_string(tables.maxPlayers)},
      {"spwnMexArmy", ArmyText(tables.mexArmy, false)},
      {"spwnHydroArmy", ArmyText(tables.hydroArmy, true)},
    };
    for (const OptionTable& option : KnownOptionTables()) {
      std::vector<std::vector<std::string>> groups;
      for (const auto& [name, its] : tables.options) {
        if (name == option.name) {
          groups = its;
        }
      }
      if (groups.empty()) {
        groups.emplace_back(); // the template's `{{}}`: one empty group
      }
      wanted.emplace_back(option.name, GroupsText(groups, option.hydro));
    }
    wanted.emplace_back("forwardCrazyrushMexes", ListText(tables.forwardCrazyrush, false));
    wanted.emplace_back("crazyrushOneMexes", ListText(tables.crazyrushOne, false));

    std::vector<Assignment> assignments;
    std::string error;
    if (text.empty() || !ReadAssignments(text, assignments, error)) {
      std::string out =
        "-- The adaptive map's tables (the \"Ultimate maps\" script's _tables.lua), written by the FAF map editor.\n";
      for (const auto& [name, value] : wanted) {
        out += "\n" + name + " = " + value + "\n";
      }
      return text.empty() ? out : text + "\n" + out;
    }
    // Only the tables whose meaning changed are written (an untouched one keeps its layout and comments).
    AdaptiveTables before;
    (void)ParseAdaptiveTables(text, before, error);
    const auto groupsOf = [](const AdaptiveTables& from, const std::string& name) {
      for (const auto& [option, groups] : from.options) {
        if (option == name) {
          return groups;
        }
      }
      return std::vector<std::vector<std::string>>{{}};
    };
    const auto unchanged = [&](const std::string& name) {
      if (name == "maxPlayerOnMap") {
        return before.maxPlayers == tables.maxPlayers;
      }
      if (name == "spwnMexArmy") {
        return before.mexArmy == tables.mexArmy;
      }
      if (name == "spwnHydroArmy") {
        return before.hydroArmy == tables.hydroArmy;
      }
      if (name == "forwardCrazyrushMexes") {
        return before.forwardCrazyrush == tables.forwardCrazyrush;
      }
      if (name == "crazyrushOneMexes") {
        return before.crazyrushOne == tables.crazyrushOne;
      }
      return groupsOf(before, name) == groupsOf(tables, name);
    };
    // Replaced from the end, so earlier offsets stay right; missing ones appended.
    std::string out = text;
    std::vector<std::pair<std::string, std::string>> missing;
    for (const auto& [name, value] : wanted) {
      bool found = false;
      for (const Assignment& assignment : assignments) {
        found = found || assignment.name == name;
      }
      if (!found) {
        missing.emplace_back(name, value);
      }
    }
    for (auto it = assignments.rbegin(); it != assignments.rend(); ++it) {
      for (const auto& [name, value] : wanted) {
        if (it->name != name || unchanged(name)) {
          continue;
        }
        // Tables of rows: only the rows that changed (the rest of the table's text kept).
        std::string written = value;
        if (name == "spwnMexArmy") {
          written = RowsWithin(text, it->value, tables.mexArmy, false, value, ",\n    ");
        } else if (name == "spwnHydroArmy") {
          written = RowsWithin(text, it->value, tables.hydroArmy, true, value, ",\n    ");
        } else {
          for (const OptionTable& option : KnownOptionTables()) {
            if (name == option.name) {
              written = RowsWithin(text, it->value, groupsOf(tables, name), option.hydro, value, ",");
            }
          }
        }
        out.replace(it->valueStart, it->valueEnd - it->valueStart, written);
      }
    }
    for (const auto& [name, value] : missing) {
      out += (out.empty() || out.back() == '\n' ? "\n" : "\n\n") + name + " = " + value + "\n";
    }
    return out;
  }
} // namespace faf::editor
