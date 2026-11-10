#include "editor/doc/EdLuaText.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    bool IsNameChar(const char c)
    {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    }

    /** Past the quoted string that starts at `at`; npos when it doesn't end. */
    std::size_t StringEnd(const std::string& text, const std::size_t at)
    {
      const char quote = text[at];
      std::size_t end = at + 1;
      while (end < text.size() && text[end] != quote) {
        end += text[end] == '\\' ? 2 : 1;
      }
      return end < text.size() ? end + 1 : std::string::npos;
    }

    /** Past the long string `[[ ... ]]` or `[==[ ... ]==]` that starts at `at`; npos when it doesn't end. */
    std::size_t LongStringEnd(const std::string& text, const std::size_t at)
    {
      std::size_t level = 0;
      std::size_t open = at + 1;
      while (open < text.size() && text[open] == '=') {
        ++level;
        ++open;
      }
      if (open >= text.size() || text[open] != '[') {
        return std::string::npos;
      }
      const std::string close = "]" + std::string(level, '=') + "]";
      const std::size_t end = text.find(close, open + 1);
      return end == std::string::npos ? std::string::npos : end + close.size();
    }

    /** Past spaces, `-- line` and `--[[ block ]]` comments. */
    std::size_t SkipSpace(const std::string& text, std::size_t at)
    {
      while (at < text.size()) {
        if (std::isspace(static_cast<unsigned char>(text[at])) != 0) {
          ++at;
        } else if (text.compare(at, 4, "--[[") == 0) {
          const std::size_t end = text.find("]]", at + 4);
          at = end == std::string::npos ? text.size() : end + 2;
        } else if (text.compare(at, 2, "--") == 0) {
          const std::size_t end = text.find('\n', at);
          at = end == std::string::npos ? text.size() : end + 1;
        } else {
          break;
        }
      }
      return at;
    }

    bool ReadValue(const std::string& text, std::size_t& at, LuaText& value, std::string& error, const int depth)
    {
      if (depth > 64) {
        error = "tables nested too deep";
        return false;
      }
      at = SkipSpace(text, at);
      if (at >= text.size()) {
        error = "the text ends inside a value";
        return false;
      }
      value = LuaText{};
      value.start = at;
      const char c = text[at];
      if (c == '{') {
        value.isTable = true;
        ++at;
        for (;;) {
          at = SkipSpace(text, at);
          if (at >= text.size()) {
            error = "a table doesn't end";
            return false;
          }
          if (text[at] == '}') {
            ++at;
            value.end = at;
            return true;
          }
          // `name = value`, `['name'] = value`, or a list item.
          std::string key;
          std::size_t look = at;
          if (text[look] == '[') {
            const std::size_t close = text.find(']', look);
            if (close != std::string::npos) {
              std::string inside = text.substr(look + 1, close - look - 1);
              if (inside.size() >= 2 && (inside.front() == '\'' || inside.front() == '"')) {
                inside = inside.substr(1, inside.size() - 2);
              }
              const std::size_t equals = SkipSpace(text, close + 1);
              if (equals < text.size() && text[equals] == '=') {
                key = inside;
                at = equals + 1;
              }
            }
          } else if (IsNameChar(text[look]) && std::isdigit(static_cast<unsigned char>(text[look])) == 0) {
            while (look < text.size() && IsNameChar(text[look])) {
              ++look;
            }
            const std::size_t equals = SkipSpace(text, look);
            if (equals < text.size() && text[equals] == '=' && (equals + 1 >= text.size() || text[equals + 1] != '=')) {
              key = text.substr(at, look - at);
              at = equals + 1;
            }
          }
          LuaText item;
          if (!ReadValue(text, at, item, error, depth + 1)) {
            return false;
          }
          if (key.empty()) {
            value.items.push_back(std::move(item));
          } else {
            value.fields.emplace_back(key, std::move(item));
          }
          at = SkipSpace(text, at);
          if (at < text.size() && (text[at] == ',' || text[at] == ';')) {
            ++at;
          }
        }
      }
      if (c == '\'' || c == '"') {
        const std::size_t end = StringEnd(text, at);
        if (end == std::string::npos) {
          error = "a string doesn't end";
          return false;
        }
        value.atom = text.substr(at, end - at);
        at = end;
        value.end = at;
        return true;
      }
      if (c == '[' && at + 1 < text.size() && (text[at + 1] == '[' || text[at + 1] == '=')) {
        const std::size_t end = LongStringEnd(text, at);
        if (end == std::string::npos) {
          error = "a long string doesn't end";
          return false;
        }
        value.atom = text.substr(at, end - at);
        at = end;
        value.end = at;
        return true;
      }
      const std::size_t start = at;
      while (at < text.size() && (IsNameChar(text[at]) || text[at] == '.' || text[at] == '-' || text[at] == '+')) {
        ++at;
      }
      if (at == start) {
        error = std::string("unexpected '") + c + "'";
        return false;
      }
      // A call, as the map files write their typed values: STRING( 'ARMY_9' ), VECTOR3( 1, 2, 3 ). Kept as its text.
      if (const std::size_t open = SkipSpace(text, at); open < text.size() && text[open] == '(' && IsNameChar(text[start])) {
        int depth = 0;
        std::size_t end = open;
        while (end < text.size()) {
          const char d = text[end];
          if (d == '\'' || d == '"') {
            end = StringEnd(text, end);
            if (end == std::string::npos) {
              break;
            }
            continue;
          }
          if (d == '(') {
            ++depth;
          } else if (d == ')' && --depth == 0) {
            ++end;
            break;
          }
          ++end;
        }
        if (end == std::string::npos || depth != 0) {
          error = "a call doesn't end";
          return false;
        }
        at = end;
      }
      value.atom = text.substr(start, at - start);
      value.end = at;
      return true;
    }
  } // namespace

  const LuaText* LuaText::Field(const std::string& name) const
  {
    for (const auto& [key, field] : fields) {
      if (key == name) {
        return &field;
      }
    }
    return nullptr;
  }

  bool LuaText::IsNumber() const
  {
    if (isTable || atom.empty()) {
      return false;
    }
    char* end = nullptr;
    (void)std::strtod(atom.c_str(), &end);
    return end != nullptr && *end == '\0';
  }

  double LuaText::Number(const double fallback) const
  {
    return IsNumber() ? std::strtod(atom.c_str(), nullptr) : fallback;
  }

  bool ReadLuaValue(const std::string& text, std::size_t at, LuaText& value, std::string& error)
  {
    return ReadValue(text, at, value, error, 0);
  }

  bool ReadLuaAssignment(const std::string& text, const std::string& name, LuaText& value, std::string& error)
  {
    // The assignment at the top level: braces and strings outside it are skipped.
    std::size_t at = 0;
    int depth = 0;
    while (at < text.size()) {
      const std::size_t next = SkipSpace(text, at);
      if (next != at) {
        at = next;
        continue;
      }
      const char c = text[at];
      if (c == '\'' || c == '"' || (c == '[' && at + 1 < text.size() && (text[at + 1] == '[' || text[at + 1] == '='))) {
        const std::size_t end = c == '[' ? LongStringEnd(text, at) : StringEnd(text, at);
        at = end == std::string::npos ? at + 1 : end;
        continue;
      }
      if (c == '{') {
        ++depth;
        ++at;
        continue;
      }
      if (c == '}') {
        --depth;
        ++at;
        continue;
      }
      if (depth == 0 && IsNameChar(c) && (at == 0 || !IsNameChar(text[at - 1]))) {
        std::size_t end = at;
        while (end < text.size() && IsNameChar(text[end])) {
          ++end;
        }
        const std::size_t equals = SkipSpace(text, end);
        if (text.compare(at, end - at, name) == 0 && end - at == name.size() && equals < text.size() && text[equals] == '=') {
          at = equals + 1;
          return ReadValue(text, at, value, error, 0);
        }
        at = end;
        continue;
      }
      ++at;
    }
    error = "no " + name + " = ...";
    return false;
  }

  std::string LuaNumber(const double value)
  {
    char text[64];
    (void)std::snprintf(text, sizeof(text), "%.3f", value);
    std::string out = text;
    while (out.size() > 1 && out.back() == '0') {
      out.pop_back();
    }
    if (!out.empty() && out.back() == '.') {
      out.pop_back();
    }
    return out == "-0" ? "0" : out;
  }
} // namespace faf::editor
