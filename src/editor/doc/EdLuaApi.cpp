#include "editor/doc/EdLuaApi.h"

#include <algorithm>
#include <cctype>
#include <set>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] bool IsWordChar(
      const char c
    )
    {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    }

    [[nodiscard]] std::string Lower(
      std::string_view text
    )
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return out;
    }

    /** The modules a map script reaches through an alias (the table's owners that are modules, not classes). */
    [[nodiscard]] bool IsModule(
      std::string_view owner
    )
    {
      return owner == "ScenarioUtils" || owner == "ScenarioFramework";
    }

    /** Lua's own functions and libraries, and words that look like calls but aren't. */
    const std::set<std::string, std::less<>>& LuaOwn()
    {
      static const std::set<std::string, std::less<>> kOwn = {
        "assert",       "collectgarbage",
        "dofile",       "error",
        "getfenv",      "getmetatable",
        "ipairs",       "load",
        "loadfile",     "loadstring",
        "next",         "pairs",
        "pcall",        "print",
        "rawequal",     "rawget",
        "rawset",       "require",
        "select",       "setfenv",
        "setmetatable", "tonumber",
        "tostring",     "type",
        "unpack",       "xpcall",
        "table",        "math",
        "string",       "coroutine",
        "os",           "io",
        "debug",        "function",
        "if",           "while",
        "for",          "return",
        "and",          "or",
        "not",          "elseif",
        "until",        "local",
        "end",          "then",
        "do",           "repeat",
        "else",         "in",
        "import",       "LOG",
        "WARN",         "SPEW",
        "_ALERT",       "ForkThread",
        "KillThread",   "WaitSeconds",
        "WaitTicks",    "WaitFor",
        "Class",        "State",
      };
      return kOwn;
    }
  } // namespace

  const std::vector<EdLuaApiEntry>& LuaApi()
  {
    static const std::vector<EdLuaApiEntry> kApi = {
#include "editor/doc/EdLuaApiTable.inc"
    };
    return kApi;
  }

  const EdLuaApiEntry* LuaApiFind(
    std::string_view owner,
    std::string_view name
  )
  {
    for (const EdLuaApiEntry& entry : LuaApi()) {
      if (owner == entry.owner && name == entry.name) {
        return &entry;
      }
    }
    return nullptr;
  }

  std::string LuaSignature(
    const EdLuaApiEntry& entry
  )
  {
    std::string out;
    if (entry.owner[0] != 0) {
      out += std::string(entry.owner) + (IsModule(entry.owner) ? "." : ":");
    }
    out += std::string(entry.name) + "(" + entry.params + ")";
    if (entry.returns[0] != 0) {
      out += std::string(" -> ") + entry.returns;
    }
    return out;
  }

  EdLuaWord LuaWordBefore(
    std::string_view text,
    std::size_t cursor
  )
  {
    EdLuaWord word;
    cursor = std::min(cursor, text.size());
    std::size_t start = cursor;
    while (start > 0 && IsWordChar(text[start - 1])) {
      --start;
    }
    word.prefix = std::string(text.substr(start, cursor - start));
    word.start = start;
    if (start > 0 && (text[start - 1] == '.' || text[start - 1] == ':')) {
      word.separator = text[start - 1];
      std::size_t q = start - 1;
      while (q > 0 && IsWordChar(text[q - 1])) {
        --q;
      }
      word.qualifier = std::string(text.substr(q, start - 1 - q));
    }
    return word;
  }

  std::vector<const EdLuaApiEntry*> LuaCompletions(
    const EdLuaWord& word,
    const std::size_t max
  )
  {
    std::vector<const EdLuaApiEntry*> starts;
    std::vector<const EdLuaApiEntry*> contains;
    const std::string prefix = Lower(word.prefix);
    std::set<std::string> names; // one per name (several classes have the same method)
    const auto offer = [&](const EdLuaApiEntry& entry) {
      if (!names.insert(entry.name).second) {
        return;
      }
      const std::string name = Lower(entry.name);
      if (name.rfind(prefix, 0) == 0) {
        starts.push_back(&entry);
      } else if (!prefix.empty() && name.find(prefix) != std::string::npos) {
        contains.push_back(&entry);
      }
    };
    for (const EdLuaApiEntry& entry : LuaApi()) {
      const std::string_view owner = entry.owner;
      if (word.separator == '.') {
        if (owner == word.qualifier) {
          offer(entry);
        }
      } else if (word.separator == ':') {
        if (!owner.empty() && !IsModule(owner)) {
          offer(entry);
        }
      } else if (owner.empty()) {
        offer(entry);
      }
    }
    std::vector<const EdLuaApiEntry*> out = starts;
    out.insert(out.end(), contains.begin(), contains.end());
    if (out.size() > max) {
      out.resize(max);
    }
    return out;
  }

  bool LuaCallAt(
    std::string_view text,
    std::size_t cursor,
    EdLuaCall& call
  )
  {
    cursor = std::min(cursor, text.size());
    // Back to the innermost unclosed '(' on this statement, counting commas at its depth.
    int depth = 0;
    int commas = 0;
    for (std::size_t i = cursor; i > 0; --i) {
      const char c = text[i - 1];
      if (c == ')' || c == ']' || c == '}') {
        ++depth;
      } else if (c == '(' || c == '[' || c == '{') {
        if (depth == 0) {
          if (c != '(') {
            return false;
          }
          // The name before the '('.
          std::size_t end = i - 1;
          while (end > 0 && text[end - 1] == ' ') {
            --end;
          }
          const EdLuaWord word = LuaWordBefore(text, end);
          if (word.prefix.empty()) {
            return false;
          }
          call.qualifier = word.qualifier;
          call.separator = word.separator;
          call.name = word.prefix;
          call.argument = commas;
          return true;
        }
        --depth;
      } else if (c == ',' && depth == 0) {
        ++commas;
      } else if (c == '\n' && i >= 2 && text[i - 2] == '\n') {
        // Calls span lines, but not a blank line.
        return false;
      }
    }
    return false;
  }

  const EdLuaApiEntry* LuaApiForCall(
    std::string_view qualifier,
    const char separator,
    std::string_view name
  )
  {
    if (separator == '.') {
      return LuaApiFind(qualifier, name);
    }
    if (separator == ':') {
      for (const EdLuaApiEntry& entry : LuaApi()) {
        if (name == entry.name && entry.owner[0] != 0 && !IsModule(entry.owner)) {
          return &entry;
        }
      }
      return nullptr;
    }
    return LuaApiFind("", name);
  }

  int EditDistance(
    std::string_view a,
    std::string_view b
  )
  {
    std::vector<int> row(b.size() + 1);
    for (std::size_t j = 0; j <= b.size(); ++j) {
      row[j] = static_cast<int>(j);
    }
    for (std::size_t i = 1; i <= a.size(); ++i) {
      int diagonal = row[0];
      row[0] = static_cast<int>(i);
      for (std::size_t j = 1; j <= b.size(); ++j) {
        const int up = row[j];
        row[j] = std::min({row[j] + 1, row[j - 1] + 1, diagonal + (a[i - 1] == b[j - 1] ? 0 : 1)});
        diagonal = up;
      }
    }
    return row[b.size()];
  }

  std::vector<EdLuaTypo> LuaTypos(
    std::string_view text
  )
  {
    // What the text defines itself: functions, locals and assigned globals.
    std::set<std::string, std::less<>> defined;
    const auto wordAt = [&](std::size_t i) {
      std::size_t j = i;
      while (j < text.size() && IsWordChar(text[j])) {
        ++j;
      }
      return std::string(text.substr(i, j - i));
    };
    for (std::size_t i = 0; i < text.size(); ++i) {
      for (const std::string_view key : {std::string_view("function "), std::string_view("local ")}) {
        if (text.substr(i, key.size()) == key && (i == 0 || !IsWordChar(text[i - 1]))) {
          std::size_t j = i + key.size();
          while (j < text.size() && text[j] == ' ') {
            ++j;
          }
          if (text.substr(j, 9) == "function ") {
            j += 9;
          }
          defined.insert(wordAt(j));
        }
      }
    }
    std::vector<EdLuaTypo> out;
    int line = 1;
    bool inComment = false;
    bool inString = false;
    char quote = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
      const char c = text[i];
      if (c == '\n') {
        ++line;
        inComment = false;
        continue;
      }
      if (inComment) {
        continue;
      }
      if (inString) {
        inString = !(c == quote && text[i - 1] != '\\');
        continue;
      }
      if (c == '-' && i + 1 < text.size() && text[i + 1] == '-') {
        inComment = true;
        continue;
      }
      if (c == '"' || c == '\'') {
        inString = true;
        quote = c;
        continue;
      }
      // A word at a word's start, not after '.' or ':', followed by '('.
      if (!IsWordChar(c) || (i > 0 && (IsWordChar(text[i - 1]) || text[i - 1] == '.' || text[i - 1] == ':'))) {
        continue;
      }
      if (std::isdigit(static_cast<unsigned char>(c)) != 0) {
        continue;
      }
      const std::string word = wordAt(i);
      std::size_t after = i + word.size();
      while (after < text.size() && text[after] == ' ') {
        ++after;
      }
      if (after >= text.size() || text[after] != '(' || word.size() < 4) {
        continue;
      }
      if (defined.count(word) != 0 || LuaOwn().count(word) != 0 || LuaApiFind("", word) != nullptr) {
        continue;
      }
      // The nearest known global, one or two letters off.
      std::string best;
      int bestDistance = 3;
      for (const EdLuaApiEntry& entry : LuaApi()) {
        if (entry.owner[0] != 0) {
          continue;
        }
        const std::string_view name = entry.name;
        if (name.size() + 2 < word.size() || word.size() + 2 < name.size()) {
          continue;
        }
        const int distance = EditDistance(word, name);
        if (distance < bestDistance) {
          bestDistance = distance;
          best = entry.name;
        }
      }
      if (!best.empty()) {
        out.push_back({i, line, word, best});
      }
      i += word.size() - 1;
    }
    return out;
  }
} // namespace faf::editor
