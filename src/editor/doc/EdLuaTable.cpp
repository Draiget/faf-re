#include "editor/doc/EdLuaTable.h"

#include <cctype>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    struct Reader
    {
      const std::string& t;
      std::size_t at = 0;
      std::string error;

      bool Fail(
        const char* what
      )
      {
        if (error.empty()) {
          error = std::string(what) + " at offset " + std::to_string(at);
        }
        return false;
      }

      void Space()
      {
        for (;;) {
          while (at < t.size() && std::isspace(static_cast<unsigned char>(t[at])) != 0) {
            ++at;
          }
          if (at + 1 < t.size() && t[at] == '-' && t[at + 1] == '-') {
            at += 2;
            std::size_t level = 0;
            if (LongBracket(level)) {
              const std::string close = "]" + std::string(level, '=') + "]";
              const std::size_t end = t.find(close, at);
              at = end == std::string::npos ? t.size() : end + close.size();
            } else {
              const std::size_t nl = t.find('\n', at);
              at = nl == std::string::npos ? t.size() : nl + 1;
            }
            continue;
          }
          return;
        }
      }

      /** At `[=*[`: steps over it and gives its level. */
      bool LongBracket(
        std::size_t& level
      )
      {
        if (at >= t.size() || t[at] != '[') {
          return false;
        }
        std::size_t i = at + 1;
        level = 0;
        while (i < t.size() && t[i] == '=') {
          ++level;
          ++i;
        }
        if (i < t.size() && t[i] == '[') {
          at = i + 1;
          return true;
        }
        return false;
      }

      bool Name(
        std::string& out
      )
      {
        if (at >= t.size() || (std::isalpha(static_cast<unsigned char>(t[at])) == 0 && t[at] != '_')) {
          return false;
        }
        const std::size_t start = at;
        while (at < t.size() &&
               (std::isalnum(static_cast<unsigned char>(t[at])) != 0 || t[at] == '_' || t[at] == '.')) {
          ++at;
        }
        out = t.substr(start, at - start);
        return true;
      }

      bool String(
        std::string& out
      )
      {
        std::size_t level = 0;
        const std::size_t before = at;
        if (LongBracket(level)) {
          const std::string close = "]" + std::string(level, '=') + "]";
          const std::size_t end = t.find(close, at);
          if (end == std::string::npos) {
            return Fail("an unterminated long string");
          }
          out = t.substr(at, end - at);
          if (!out.empty() && out[0] == '\n') {
            out.erase(0, 1);
          }
          at = end + close.size();
          return true;
        }
        at = before;
        const char quote = t[at++];
        while (at < t.size()) {
          const char c = t[at++];
          if (c == quote) {
            return true;
          }
          if (c != '\\') {
            out += c;
            continue;
          }
          if (at >= t.size()) {
            break;
          }
          const char e = t[at++];
          switch (e) {
          case 'n':
            out += '\n';
            break;
          case 't':
            out += '\t';
            break;
          case 'r':
            out += '\r';
            break;
          case '\n':
            out += '\n';
            break;
          default:
            if (std::isdigit(static_cast<unsigned char>(e)) != 0) {
              int code = e - '0';
              for (int k = 0; k < 2 && at < t.size() && std::isdigit(static_cast<unsigned char>(t[at])) != 0; ++k) {
                code = code * 10 + (t[at++] - '0');
              }
              out += static_cast<char>(code);
            } else {
              out += e;
            }
            break;
          }
        }
        return Fail("an unterminated string");
      }

      bool Value(
        JsonTree& out,
        const int depth
      )
      {
        if (depth > 200) {
          return Fail("nesting too deep");
        }
        Space();
        if (at >= t.size()) {
          return Fail("a value expected");
        }
        const char c = t[at];
        if (c == '{') {
          return Table(out, depth);
        }
        if (c == '"' || c == '\'') {
          out = JsonTree::Text({});
          return String(out.s);
        }
        if (c == '[') {
          std::size_t level = 0;
          const std::size_t before = at;
          if (LongBracket(level)) {
            at = before;
            out = JsonTree::Text({});
            return String(out.s);
          }
          return Fail("a value expected");
        }
        if (c == '-' || c == '.' || std::isdigit(static_cast<unsigned char>(c)) != 0) {
          char* end = nullptr;
          const double d = std::strtod(t.c_str() + at, &end);
          if (end == t.c_str() + at) {
            return Fail("a number expected");
          }
          at = static_cast<std::size_t>(end - t.c_str());
          out = JsonTree::Number(d);
          return true;
        }
        std::string name;
        if (Name(name)) {
          if (name == "true" || name == "false") {
            out = JsonTree::Flag(name == "true");
            return true;
          }
          if (name == "nil") {
            out = JsonTree{};
            return true;
          }
          // A call with a table or string argument: `Sound { ... }`, `LOC('...')` (kept as its argument).
          Space();
          if (at < t.size() && t[at] == '{') {
            if (!Table(out, depth)) {
              return false;
            }
            out.Set("__call", JsonTree::Text(name));
            return true;
          }
          if (at < t.size() && t[at] == '(') {
            ++at;
            if (!Value(out, depth + 1)) {
              return false;
            }
            Space();
            if (at < t.size() && t[at] == ')') {
              ++at;
            }
            return true;
          }
          // A bare name (a constant of the game's Lua): kept as text.
          out = JsonTree::Text(name);
          return true;
        }
        return Fail("a value expected");
      }

      bool Table(
        JsonTree& out,
        const int depth
      )
      {
        ++at; // {
        out = JsonTree::MakeArray();
        bool named = false;
        for (;;) {
          Space();
          if (at >= t.size()) {
            return Fail("an unterminated table");
          }
          if (t[at] == '}') {
            ++at;
            if (named) {
              out.kind = JsonTree::Kind::Object;
            }
            return true;
          }
          std::string key;
          bool keyed = false;
          if (t[at] == '[' && at + 1 < t.size() && t[at + 1] != '[' && t[at + 1] != '=') {
            ++at;
            JsonTree k;
            if (!Value(k, depth + 1)) {
              return false;
            }
            Space();
            if (at >= t.size() || t[at] != ']') {
              return Fail("']' expected");
            }
            ++at;
            key = k.kind == JsonTree::Kind::Number ? std::to_string(static_cast<long long>(k.n)) : k.s;
            keyed = true;
          } else {
            const std::size_t before = at;
            std::string name;
            if (Name(name)) {
              Space();
              if (at < t.size() && t[at] == '=' && (at + 1 >= t.size() || t[at + 1] != '=')) {
                key = name;
                keyed = true;
              } else {
                at = before;
              }
            }
          }
          if (keyed) {
            Space();
            if (at >= t.size() || t[at] != '=') {
              return Fail("'=' expected");
            }
            ++at;
          }
          JsonTree value;
          if (!Value(value, depth + 1)) {
            return false;
          }
          if (keyed) {
            out.fields.emplace_back(key, std::move(value));
            named = true;
          } else {
            out.items.push_back(std::move(value));
          }
          Space();
          if (at < t.size() && (t[at] == ',' || t[at] == ';')) {
            ++at;
          }
        }
      }
    };
  } // namespace

  std::expected<void, std::string> ParseLuaAssignments(
    const std::string& text,
    JsonTree& out
  )
  {
    Reader r{text, 0, {}};
    out = JsonTree::MakeObject();
    for (;;) {
      r.Space();
      if (r.at >= text.size()) {
        return {};
      }
      std::string name;
      if (text.compare(r.at, 6, "local ") == 0) {
        r.at += 6;
        r.Space();
      }
      if (!r.Name(name)) {
        return std::unexpected("a name expected at offset " + std::to_string(r.at));
      }
      r.Space();
      if (r.at >= text.size() || text[r.at] != '=') {
        // A statement that isn't an assignment (a call such as `UnitBlueprint { ... }`): its table.
        JsonTree value;
        if (r.at < text.size() && text[r.at] == '{') {
          if (!r.Table(value, 0)) {
            return std::unexpected(r.error);
          }
          value.Set("__call", JsonTree::Text(name));
          out.fields.emplace_back(name, std::move(value));
          continue;
        }
        return std::unexpected("'=' expected after " + name + " at offset " + std::to_string(r.at));
      }
      ++r.at;
      JsonTree value;
      if (!r.Value(value, 0)) {
        return std::unexpected(r.error);
      }
      out.fields.emplace_back(name, std::move(value));
    }
  }

  std::expected<JsonTree, std::string> ParseLuaValue(
    const std::string& text
  )
  {
    Reader r{text, 0, {}};
    JsonTree out;
    if (!r.Value(out, 0)) {
      return std::unexpected(r.error);
    }
    return out;
  }
} // namespace faf::editor
