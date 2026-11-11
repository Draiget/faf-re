#include "editor/doc/EdLuaSyntax.h"

#include <cctype>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    bool IsWord(const std::string& word, const char* const* list)
    {
      for (; *list != nullptr; ++list) {
        if (word == *list) {
          return true;
        }
      }
      return false;
    }

    const char* const kKeywords[] = {"and",   "break", "do",     "else", "elseif", "end",   "for",   "function", "if",
                                     "in",    "local", "not",    "or",   "repeat", "return", "then", "until",    "while",
                                     "continue", nullptr};
    const char* const kConstants[] = {"true", "false", "nil", nullptr};
    // The globals FAF's map scripts reach for most (lua/ScenarioUtilities, the sim's globals).
    const char* const kEngine[] = {"ScenarioInfo", "ScenarioUtils",  "ScenarioFramework", "import",     "LOG",      "WARN",       "SPEW",
                                   "ForkThread",   "KillThread",     "WaitSeconds",       "WaitTicks",  "ArmyBrains", "GetArmyBrain",
                                   "ListArmies",   "Entity",         "Warp",              "VECTOR3",    "Vector",   "table",
                                   "string",       "math",           "self",              "_G",         "pairs",    "ipairs",
                                   "type",         "tostring",       "tonumber",          "setmetatable", "getmetatable",
                                   "CreateEmitterAtEntity", "CreateUnitHPR", "CreateProp", "GetTerrainHeight", "GetSurfaceHeight",
                                   nullptr};

    /** `[[`, `[=[`: its level, or -1. */
    int LongLevel(const std::string& t, const std::size_t at)
    {
      if (at >= t.size() || t[at] != '[') {
        return -1;
      }
      std::size_t q = at + 1;
      int level = 0;
      while (q < t.size() && t[q] == '=') {
        ++level;
        ++q;
      }
      return q < t.size() && t[q] == '[' ? level : -1;
    }

    std::size_t LongEnd(const std::string& t, const std::size_t from, const int level)
    {
      const std::string close = "]" + std::string(static_cast<std::size_t>(level), '=') + "]";
      const std::size_t e = t.find(close, from);
      return e == std::string::npos ? t.size() : e + close.size();
    }
  } // namespace

  std::vector<LuaSpan> LuaSpans(const std::string& t)
  {
    std::vector<LuaSpan> spans;
    const std::size_t n = t.size();
    const auto push = [&](const std::size_t a, const std::size_t b, const LuaSpanKind kind) {
      if (b <= a) {
        return;
      }
      if (!spans.empty() && spans.back().kind == kind && spans.back().end == a) {
        spans.back().end = b;
      } else {
        spans.push_back({a, b, kind});
      }
    };
    std::size_t i = 0;
    while (i < n) {
      const char c = t[i];
      const std::size_t start = i;
      if (std::isspace(static_cast<unsigned char>(c)) != 0) {
        while (i < n && std::isspace(static_cast<unsigned char>(t[i])) != 0) {
          ++i;
        }
        push(start, i, LuaSpanKind::Plain);
        continue;
      }
      if ((c == '-' && i + 1 < n && t[i + 1] == '-') || c == '#') {
        i += c == '#' ? 1 : 2;
        if (c == '-') {
          if (const int level = LongLevel(t, i); level >= 0) {
            i = LongEnd(t, i + static_cast<std::size_t>(level) + 2, level);
            push(start, i, LuaSpanKind::Comment);
            continue;
          }
        }
        while (i < n && t[i] != '\n') {
          ++i;
        }
        push(start, i, LuaSpanKind::Comment);
        continue;
      }
      if (const int level = LongLevel(t, i); level >= 0) {
        i = LongEnd(t, i + static_cast<std::size_t>(level) + 2, level);
        push(start, i, LuaSpanKind::String);
        continue;
      }
      if (c == '"' || c == '\'') {
        ++i;
        while (i < n && t[i] != c && t[i] != '\n') {
          i += t[i] == '\\' && i + 1 < n ? 2 : 1;
        }
        i = i < n && t[i] == c ? i + 1 : i;
        push(start, i, LuaSpanKind::String);
        continue;
      }
      if (std::isdigit(static_cast<unsigned char>(c)) != 0 || (c == '.' && i + 1 < n && std::isdigit(static_cast<unsigned char>(t[i + 1])) != 0)) {
        while (i < n && (std::isalnum(static_cast<unsigned char>(t[i])) != 0 || (t[i] == '.' && !(i + 1 < n && t[i + 1] == '.')))) {
          ++i;
        }
        push(start, i, LuaSpanKind::Number);
        continue;
      }
      if (std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_') {
        while (i < n && (std::isalnum(static_cast<unsigned char>(t[i])) != 0 || t[i] == '_')) {
          ++i;
        }
        const std::string word = t.substr(start, i - start);
        LuaSpanKind kind = LuaSpanKind::Plain;
        if (IsWord(word, kKeywords)) {
          kind = LuaSpanKind::Keyword;
        } else if (IsWord(word, kConstants)) {
          kind = LuaSpanKind::Constant;
        } else if (IsWord(word, kEngine)) {
          kind = LuaSpanKind::Engine;
        } else {
          std::size_t j = i;
          while (j < n && (t[j] == ' ' || t[j] == '\t')) {
            ++j;
          }
          if (j < n && (t[j] == '(' || t[j] == '{' || t[j] == '"' || t[j] == '\'')) {
            kind = LuaSpanKind::Call;
          }
        }
        push(start, i, kind);
        continue;
      }
      ++i;
      push(start, i, LuaSpanKind::Operator);
    }
    return spans;
  }
} // namespace faf::editor
