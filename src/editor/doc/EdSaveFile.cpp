#include "editor/doc/EdSaveFile.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <regex>

namespace faf::editor
{
  namespace
  {
    /** Skips whitespace and Lua comments (`-- ...`, `--[[ ... ]]`, the saves' `--[[ ]]--` banners) from `at`. */
    std::size_t SkipSpace(const std::string& text, std::size_t at)
    {
      for (;;) {
        while (at < text.size() && std::isspace(static_cast<unsigned char>(text[at])) != 0) {
          ++at;
        }
        if (text.compare(at, 2, "--") != 0) {
          return at;
        }
        if (text.compare(at, 4, "--[[") == 0) {
          const std::size_t end = text.find("]]", at + 4);
          at = end == std::string::npos ? text.size() : end + 2;
          if (text.compare(at, 2, "--") == 0) {
            at += 2;
          }
          continue;
        }
        const std::size_t end = text.find('\n', at);
        at = end == std::string::npos ? text.size() : end + 1;
      }
    }

    /** The end of a quoted string starting at `at` (its quote), past the closing quote. */
    std::size_t SkipString(const std::string& text, std::size_t at)
    {
      const char quote = text[at];
      for (++at; at < text.size(); ++at) {
        if (text[at] == '\\') {
          ++at;
        } else if (text[at] == quote) {
          return at + 1;
        }
      }
      return text.size();
    }

    /** The matching closer of the bracket at `at` ('{' or '('), skipping strings and comments; npos if none. */
    std::size_t MatchBracket(const std::string& text, std::size_t at)
    {
      int depth = 0;
      while (at < text.size()) {
        const char c = text[at];
        if (c == '\'' || c == '"') {
          at = SkipString(text, at);
          continue;
        }
        if (c == '-' && text.compare(at, 2, "--") == 0) {
          at = SkipSpace(text, at);
          continue;
        }
        if (c == '{' || c == '(') {
          ++depth;
        } else if (c == '}' || c == ')') {
          if (--depth == 0) {
            return at;
          }
        }
        ++at;
      }
      return std::string::npos;
    }

    /** `['key']`, `["key"]` or a bare `key` at `at`; the name, and `at` past it. */
    bool ReadKey(const std::string& text, std::size_t& at, std::string& key)
    {
      at = SkipSpace(text, at);
      if (at < text.size() && text[at] == '[') {
        at = SkipSpace(text, at + 1);
        if (at >= text.size() || (text[at] != '\'' && text[at] != '"')) {
          return false;
        }
        const std::size_t end = SkipString(text, at);
        key = text.substr(at + 1, end - at - 2);
        at = SkipSpace(text, end);
        if (at >= text.size() || text[at] != ']') {
          return false;
        }
        ++at;
        return true;
      }
      const std::size_t start = at;
      while (at < text.size() && (std::isalnum(static_cast<unsigned char>(text[at])) != 0 || text[at] == '_')) {
        ++at;
      }
      key = text.substr(start, at - start);
      return !key.empty();
    }

    /** A value's text from `at` to the ',' or '}' that ends it at its own depth; `at` left on that character. */
    std::string ReadValue(const std::string& text, std::size_t& at)
    {
      at = SkipSpace(text, at);
      const std::size_t start = at;
      while (at < text.size()) {
        const char c = text[at];
        if (c == '\'' || c == '"') {
          at = SkipString(text, at);
        } else if (c == '{' || c == '(') {
          const std::size_t close = MatchBracket(text, at);
          at = close == std::string::npos ? text.size() : close + 1;
        } else if (c == ',' || c == '}') {
          break;
        } else {
          ++at;
        }
      }
      std::size_t end = at;
      while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0) {
        --end;
      }
      return text.substr(start, end - start);
    }

    /** The entries `['name'] = { ['key'] = value, ... },` between `open` ('{') and `close`. */
    bool ParseEntries(const std::string& text, const std::size_t open, const std::size_t close, std::vector<SaveEntry>& out, std::string& error,
                      std::vector<SaveEntrySpan>* spans = nullptr)
    {
      out.clear();
      if (spans != nullptr) {
        spans->clear();
      }
      std::size_t at = open + 1;
      for (;;) {
        const std::size_t lead = at;
        at = SkipSpace(text, at);
        if (at >= close) {
          return true;
        }
        SaveEntrySpan span;
        span.lead = lead;
        span.start = at;
        SaveEntry entry;
        if (!ReadKey(text, at, entry.name)) {
          error = "an entry without a name at offset " + std::to_string(at);
          return false;
        }
        at = SkipSpace(text, at);
        if (at >= text.size() || text[at] != '=') {
          error = "'" + entry.name + "' has no '='";
          return false;
        }
        at = SkipSpace(text, at + 1);
        if (at >= text.size() || text[at] != '{') {
          error = "'" + entry.name + "' is not a table";
          return false;
        }
        const std::size_t entryClose = MatchBracket(text, at);
        if (entryClose == std::string::npos || entryClose > close) {
          error = "'" + entry.name + "' is not closed";
          return false;
        }
        std::size_t inner = at + 1;
        for (;;) {
          inner = SkipSpace(text, inner);
          if (inner >= entryClose) {
            break;
          }
          std::string key;
          if (!ReadKey(text, inner, key)) {
            error = "a property of '" + entry.name + "' without a key";
            return false;
          }
          inner = SkipSpace(text, inner);
          if (inner >= text.size() || text[inner] != '=') {
            error = "property '" + key + "' of '" + entry.name + "' has no '='";
            return false;
          }
          ++inner;
          const std::size_t valueStart = SkipSpace(text, inner);
          entry.properties.emplace_back(key, ReadValue(text, inner));
          span.values.emplace_back(valueStart, valueStart + entry.properties.back().second.size());
          inner = SkipSpace(text, inner);
          if (inner < entryClose && text[inner] == ',') {
            ++inner;
          }
        }
        out.push_back(std::move(entry));
        // The entry ends after its comma (when it has one); what follows belongs to the next one.
        at = entryClose + 1;
        const std::size_t comma = SkipSpace(text, at);
        if (comma < close && text[comma] == ',') {
          at = comma + 1;
        }
        span.end = at;
        if (spans != nullptr) {
          spans->push_back(std::move(span));
        }
      }
    }

    /** The block `<name> = {` (after `after`), its braces and its entries' indent. */
    bool FindBlock(const std::string& text, const std::regex& opening, const std::size_t after, std::size_t& open, std::size_t& close, int& indent)
    {
      std::smatch match;
      const auto begin = text.begin() + static_cast<std::ptrdiff_t>(after);
      if (!std::regex_search(begin, text.end(), match, opening)) {
        return false;
      }
      open = after + static_cast<std::size_t>(match.position(0) + match.length(0)) - 1;
      close = MatchBracket(text, open);
      if (close == std::string::npos) {
        return false;
      }
      // The line's indent, plus one level, as the game's saves nest.
      const std::size_t lineStart = text.rfind('\n', open);
      std::size_t column = lineStart == std::string::npos ? 0 : lineStart + 1;
      int spaces = 0;
      while (column < text.size() && text[column] == ' ') {
        ++spaces;
        ++column;
      }
      indent = spaces + 4;
      return true;
    }

    std::string Quote(const std::string& text)
    {
      std::string out = "'";
      for (const char c : text) {
        if (c == '\'' || c == '\\') {
          out += '\\';
        }
        out += c;
      }
      return out + "'";
    }

    std::string Number(const double value)
    {
      char text[48];
      (void)std::snprintf(text, sizeof(text), "%.9g", value);
      return text;
    }
  } // namespace

  std::string SaveEntry::Get(const std::string& key) const
  {
    for (const auto& [k, value] : properties) {
      if (k == key) {
        return value;
      }
    }
    return {};
  }

  void SaveEntry::Set(const std::string& key, const std::string& value)
  {
    for (auto& [k, v] : properties) {
      if (k == key) {
        v = value;
        return;
      }
    }
    properties.emplace_back(key, value);
  }

  std::vector<double> ValueNumbers(const std::string& value)
  {
    std::vector<double> numbers;
    const std::size_t open = value.find('(');
    std::size_t at = open == std::string::npos ? 0 : open + 1;
    while (at < value.size()) {
      const char c = value[at];
      if (std::isdigit(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '+' || c == '.') {
        char* end = nullptr;
        const double number = std::strtod(value.c_str() + at, &end);
        if (end == value.c_str() + at) {
          ++at;
          continue;
        }
        numbers.push_back(number);
        at = static_cast<std::size_t>(end - value.c_str());
      } else {
        ++at;
      }
    }
    return numbers;
  }

  std::string ValueString(const std::string& value)
  {
    const std::size_t open = value.find_first_of("'\"");
    if (open == std::string::npos) {
      return {};
    }
    const std::size_t end = SkipString(value, open);
    return value.substr(open + 1, end - open - 2);
  }

  std::string Vector3Value(const double x, const double y, const double z)
  {
    return "VECTOR3( " + Number(x) + ", " + Number(y) + ", " + Number(z) + " )";
  }

  std::string RectangleValue(const double x0, const double y0, const double x1, const double y1)
  {
    return "RECTANGLE( " + Number(x0) + ", " + Number(y0) + ", " + Number(x1) + ", " + Number(y1) + " )";
  }

  std::string StringValue(const std::string& text)
  {
    return "STRING( " + Quote(text) + " )";
  }

  bool SaveFile::Parse(std::string text, std::string& error)
  {
    mText = std::move(text);
    mMarkerBlock = {};
    mAreaBlock = {};
    mArmyBlock = {};
    mMarkers.clear();
    mAreas.clear();
    mArmies.clear();
    // The master chain's markers (the chains below it list marker names in `Markers = {` blocks of their own).
    const std::size_t chain = mText.find("_MASTERCHAIN_");
    if (chain != std::string::npos &&
        FindBlock(mText, std::regex(R"(Markers\s*=\s*\{)"), chain, mMarkerBlock.open, mMarkerBlock.close, mMarkerBlock.indent)) {
      mMarkerBlock.found = true;
      if (!ParseEntries(mText, mMarkerBlock.open, mMarkerBlock.close, mMarkers, error, &mMarkerBlock.spans)) {
        error = "markers: " + error;
        return false;
      }
    }
    if (FindBlock(mText, std::regex(R"(Areas\s*=\s*\{)"), 0, mAreaBlock.open, mAreaBlock.close, mAreaBlock.indent)) {
      mAreaBlock.found = true;
      if (!ParseEntries(mText, mAreaBlock.open, mAreaBlock.close, mAreas, error, &mAreaBlock.spans)) {
        error = "areas: " + error;
        return false;
      }
    }
    if (FindBlock(mText, std::regex(R"(\bArmies\s*=\s*\{)"), 0, mArmyBlock.open, mArmyBlock.close, mArmyBlock.indent)) {
      mArmyBlock.found = true;
      if (!ParseEntries(mText, mArmyBlock.open, mArmyBlock.close, mArmies, error, &mArmyBlock.spans)) {
        error = "armies: " + error;
        return false;
      }
    }
    mMarkersRead = mMarkers;
    mAreasRead = mAreas;
    mArmiesRead = mArmies;
    return true;
  }

  void SaveFile::MarkSaved()
  {
    std::string error;
    (void)Parse(Text(), error);
  }

  bool SaveFile::Changed() const
  {
    return mMarkers != mMarkersRead || mAreas != mAreasRead || mArmies != mArmiesRead;
  }

  std::string SaveFile::Text() const
  {
    // The later block first, so the earlier one's offsets still hold.
    struct Replace
    {
      const Block* block;
      std::string text;
    };
    std::vector<Replace> replaces;
    if (mMarkerBlock.found && mMarkers != mMarkersRead) {
      replaces.push_back({&mMarkerBlock, Rebuild(mMarkerBlock, mMarkers, mMarkersRead)});
    }
    if (mAreaBlock.found && mAreas != mAreasRead) {
      replaces.push_back({&mAreaBlock, Rebuild(mAreaBlock, mAreas, mAreasRead)});
    }
    if (mArmyBlock.found && mArmies != mArmiesRead) {
      replaces.push_back({&mArmyBlock, Rebuild(mArmyBlock, mArmies, mArmiesRead)});
    }
    std::sort(replaces.begin(), replaces.end(), [](const Replace& a, const Replace& b) { return a.block->open > b.block->open; });
    std::string out = mText;
    for (const Replace& replace : replaces) {
      out.replace(replace.block->open + 1, replace.block->close - replace.block->open - 1, replace.text);
    }
    return out;
  }

  std::string SaveFile::Rebuild(const Block& block, const std::vector<SaveEntry>& now, const std::vector<SaveEntry>& read) const
  {
    const std::string nl = mText.find("\r\n") != std::string::npos ? "\r\n" : "\n";
    // A value written by the editor in the file's line ends.
    const auto lineEnds = [&nl](const std::string& value) {
      if (nl == "\n") {
        return value;
      }
      std::string out;
      for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\n' && (i == 0 || value[i - 1] != '\r')) {
          out += '\r';
        }
        out += value[i];
      }
      return out;
    };
    const std::string pad(static_cast<std::size_t>(block.indent), ' ');
    const std::string inner(static_cast<std::size_t>(block.indent + 4), ' ');
    const auto format = [&](const SaveEntry& entry) {
      std::string out = "[" + Quote(entry.name) + "] = {" + nl;
      for (const auto& [key, value] : entry.properties) {
        out += inner + "[" + Quote(key) + "] = " + lineEnds(value) + "," + nl;
      }
      return out + pad + "},";
    };
    std::string body;
    std::vector<bool> used(read.size(), false);
    for (const SaveEntry& entry : now) {
      std::size_t found = read.size();
      for (std::size_t i = 0; i < read.size() && i < block.spans.size(); ++i) {
        if (!used[i] && read[i].name == entry.name) {
          found = i;
          break;
        }
      }
      if (found == read.size()) {
        body += nl + pad + format(entry);
        continue;
      }
      used[found] = true;
      const SaveEntrySpan& span = block.spans[found];
      std::string piece = mText.substr(span.start, span.end - span.start);
      if (!(entry == read[found])) {
        bool sameKeys = entry.properties.size() == read[found].properties.size() && span.values.size() == entry.properties.size();
        for (std::size_t k = 0; sameKeys && k < entry.properties.size(); ++k) {
          sameKeys = entry.properties[k].first == read[found].properties[k].first;
        }
        if (sameKeys) {
          for (std::size_t k = entry.properties.size(); k-- > 0;) {
            if (entry.properties[k].second != read[found].properties[k].second) {
              const auto [from, to] = span.values[k];
              piece.replace(from - span.start, to - from, lineEnds(entry.properties[k].second));
            }
          }
        } else {
          piece = format(entry);
        }
      }
      body += mText.substr(span.lead, span.start - span.lead) + piece;
    }
    const std::size_t tail = block.spans.empty() ? block.open + 1 : block.spans.back().end;
    body += mText.substr(tail, block.close - tail);
    return body;
  }

  SaveEntry NewArmyEntry(const std::string& name)
  {
    SaveEntry army;
    army.name = name;
    army.properties = {
      {"personality", "''"},
      {"plans", "''"},
      {"color", "0"},
      {"faction", "0"},
      {"Economy", "{\n                mass = 0,\n                energy = 0,\n            }"},
      {"Alliances", "{\n            }"},
      {"Units", "GROUP {\n                orders = '',\n                platoon = '',\n                Units = {\n                    ['INITIAL'] = GROUP {\n"
                "                        orders = '',\n                        platoon = '',\n                        Units = {\n                        },\n"
                "                    },\n                },\n            }"},
      {"PlatoonBuilders", "{\n                next_platoon_builder_id = '0',\n                Builders = {\n                },\n            }"},
    };
    return army;
  }

  std::vector<ScenarioTeam> ScenarioTeams(const std::string& scenario)
  {
    std::vector<ScenarioTeam> teams;
    std::size_t open = 0, close = 0;
    int indent = 0;
    if (!FindBlock(scenario, std::regex(R"(\bteams\s*=\s*\{)"), 0, open, close, indent)) {
      return teams;
    }
    // Each table one level in: its name and its armies.
    const std::regex nameKey(R"(\bname\s*=\s*['"]([^'"]*)['"])");
    const std::regex armiesKey(R"(\barmies\s*=\s*\{([^}]*)\})");
    const std::regex quoted(R"(['"]([^'"]+)['"])");
    for (std::size_t at = open + 1; at < close;) {
      const std::size_t start = scenario.find('{', at);
      if (start == std::string::npos || start >= close) {
        break;
      }
      const std::size_t end = MatchBracket(scenario, start);
      if (end == std::string::npos || end > close) {
        break;
      }
      const std::string table = scenario.substr(start, end - start + 1);
      ScenarioTeam team;
      std::smatch match;
      if (std::regex_search(table, match, nameKey)) {
        team.name = match[1].str();
      }
      if (std::regex_search(table, match, armiesKey)) {
        const std::string list = match[1].str();
        for (auto it = std::sregex_iterator(list.begin(), list.end(), quoted); it != std::sregex_iterator(); ++it) {
          team.armies.push_back((*it)[1].str());
        }
      }
      teams.push_back(std::move(team));
      at = end + 1;
    }
    return teams;
  }

  std::string WithScenarioTeams(const std::string& scenario, const std::vector<ScenarioTeam>& teams)
  {
    std::size_t open = 0, close = 0;
    int indent = 0;
    if (!FindBlock(scenario, std::regex(R"(\bteams\s*=\s*\{)"), 0, open, close, indent)) {
      return scenario;
    }
    std::string body = "\n";
    for (const ScenarioTeam& team : teams) {
      std::string list;
      for (const std::string& army : team.armies) {
        list += Quote(army) + ",";
      }
      body += std::string(static_cast<std::size_t>(indent), ' ') + "{ name = " + Quote(team.name) + ", armies = {" + list + "} },\n";
    }
    body += std::string(static_cast<std::size_t>(std::max(indent - 4, 0)), ' ');
    return scenario.substr(0, open + 1) + body + scenario.substr(close);
  }

  std::vector<std::string> ScenarioArmies(const std::string& scenario)
  {
    // Every team's armies, in order (a map with one FFA team has them all there).
    if (const std::vector<ScenarioTeam> teams = ScenarioTeams(scenario); !teams.empty()) {
      std::vector<std::string> armies;
      for (const ScenarioTeam& team : teams) {
        armies.insert(armies.end(), team.armies.begin(), team.armies.end());
      }
      return armies;
    }
    std::vector<std::string> armies;
    std::smatch match;
    if (!std::regex_search(scenario, match, std::regex(R"(armies\s*=\s*\{([^}]*)\})"))) {
      return armies;
    }
    const std::string list = match[1].str();
    const std::regex name(R"(['"]([^'"]+)['"])");
    for (auto it = std::sregex_iterator(list.begin(), list.end(), name); it != std::sregex_iterator(); ++it) {
      armies.push_back((*it)[1].str());
    }
    return armies;
  }

  std::string WithScenarioArmies(const std::string& scenario, const std::vector<std::string>& armies)
  {
    std::string list;
    for (const std::string& army : armies) {
      list += Quote(army) + ",";
    }
    return std::regex_replace(scenario, std::regex(R"(armies\s*=\s*\{[^}]*\})"), "armies = {" + list + "}",
                              std::regex_constants::format_first_only);
  }

  std::vector<std::string> ScenarioExtraArmies(const std::string& scenario)
  {
    std::vector<std::string> armies;
    std::smatch match;
    if (std::regex_search(scenario, match, std::regex(R"(\['ExtraArmies'\]\s*=\s*STRING\(\s*'([^']*)'\s*\))"))) {
      const std::string list = match[1].str();
      std::size_t at = 0;
      while (at < list.size()) {
        const std::size_t space = list.find(' ', at);
        const std::string word = list.substr(at, space == std::string::npos ? std::string::npos : space - at);
        if (!word.empty()) {
          armies.push_back(word);
        }
        at = space == std::string::npos ? list.size() : space + 1;
      }
    }
    return armies;
  }

  std::string WithScenarioExtraArmies(const std::string& scenario, const std::vector<std::string>& armies)
  {
    std::string list;
    for (const std::string& army : armies) {
      list += (list.empty() ? "" : " ") + army;
    }
    return std::regex_replace(scenario, std::regex(R"(\['ExtraArmies'\]\s*=\s*STRING\(\s*'[^']*'\s*\))"),
                              "['ExtraArmies'] = STRING( '" + list + "' )", std::regex_constants::format_first_only);
  }

  std::optional<std::string> ScriptPlayableArea(const std::string& script)
  {
    std::smatch match;
    if (std::regex_search(script, match, std::regex(R"(SetPlayableArea\s*\(\s*['"]([^'"]+)['"])"))) {
      return match[1].str();
    }
    return std::nullopt;
  }

  std::string WithScriptPlayableArea(const std::string& script, const std::string& area)
  {
    const std::regex call(R"([ \t]*ScenarioFramework\.SetPlayableArea\s*\(\s*['"][^'"]+['"][^)]*\)[ \t]*\r?\n?)");
    if (area.empty()) {
      return std::regex_replace(script, call, "");
    }
    const std::string line = "    ScenarioFramework.SetPlayableArea('" + area + "', false)\n";
    if (std::regex_search(script, call)) {
      return std::regex_replace(script, call, line, std::regex_constants::format_first_only);
    }
    std::string out = script;
    // The import the call needs, at the top, if the script has none.
    if (out.find("ScenarioFramework = import") == std::string::npos) {
      out = "local ScenarioFramework = import('/lua/ScenarioFramework.lua')\n" + out;
    }
    // After InitializeArmies in OnPopulate, or as OnPopulate's first line.
    std::smatch match;
    if (std::regex_search(out, match, std::regex(R"(ScenarioUtils\.InitializeArmies\(\)[ \t]*\r?\n)"))) {
      const std::size_t at = static_cast<std::size_t>(match.position(0) + match.length(0));
      return out.insert(at, line);
    }
    if (std::regex_search(out, match, std::regex(R"(function\s+OnPopulate\s*\([^)]*\)[ \t]*\r?\n)"))) {
      const std::size_t at = static_cast<std::size_t>(match.position(0) + match.length(0));
      return out.insert(at, line);
    }
    return out + "\nfunction OnPopulate()\n" + line + "end\n";
  }
} // namespace faf::editor
