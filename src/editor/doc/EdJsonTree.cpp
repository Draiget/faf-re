#include "editor/doc/EdJsonTree.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  const JsonTree* JsonTree::Get(
    const std::string& key
  ) const
  {
    if (kind != Kind::Object) {
      return nullptr;
    }
    for (const auto& [name, value] : fields) {
      if (name == key) {
        return &value;
      }
    }
    return nullptr;
  }

  double JsonTree::Num(
    const std::string& key,
    const double fallback
  ) const
  {
    const JsonTree* const v = Get(key);
    if (v == nullptr) {
      return fallback;
    }
    if (v->kind == Kind::Number) {
      return v->n;
    }
    if (v->kind == Kind::Bool) {
      return v->b ? 1.0 : 0.0;
    }
    if (v->kind == Kind::String) {
      char* end = nullptr;
      const double d = std::strtod(v->s.c_str(), &end);
      return end != v->s.c_str() ? d : fallback;
    }
    return fallback;
  }

  bool JsonTree::Bool(
    const std::string& key,
    const bool fallback
  ) const
  {
    const JsonTree* const v = Get(key);
    if (v == nullptr) {
      return fallback;
    }
    if (v->kind == Kind::Bool) {
      return v->b;
    }
    if (v->kind == Kind::Number) {
      return v->n != 0.0;
    }
    if (v->kind == Kind::String) {
      return v->s == "true" || v->s == "1";
    }
    return fallback;
  }

  std::string JsonTree::Str(
    const std::string& key,
    const std::string& fallback
  ) const
  {
    const JsonTree* const v = Get(key);
    if (v == nullptr) {
      return fallback;
    }
    if (v->kind == Kind::String) {
      return v->s;
    }
    if (v->kind == Kind::Number) {
      char text[64];
      (void)std::snprintf(text, sizeof(text), "%.9g", v->n);
      return text;
    }
    if (v->kind == Kind::Bool) {
      return v->b ? "true" : "false";
    }
    return fallback;
  }

  JsonTree JsonTree::Number(
    const double value
  )
  {
    JsonTree node;
    node.kind = Kind::Number;
    node.n = value;
    return node;
  }

  JsonTree JsonTree::Text(
    std::string value
  )
  {
    JsonTree node;
    node.kind = Kind::String;
    node.s = std::move(value);
    return node;
  }

  JsonTree JsonTree::Flag(
    const bool value
  )
  {
    JsonTree node;
    node.kind = Kind::Bool;
    node.b = value;
    return node;
  }

  JsonTree JsonTree::MakeArray()
  {
    JsonTree node;
    node.kind = Kind::Array;
    return node;
  }

  JsonTree JsonTree::MakeObject()
  {
    JsonTree node;
    node.kind = Kind::Object;
    return node;
  }

  JsonTree& JsonTree::Set(
    const std::string& key,
    JsonTree value
  )
  {
    kind = Kind::Object;
    for (auto& [name, existing] : fields) {
      if (name == key) {
        existing = std::move(value);
        return existing;
      }
    }
    fields.emplace_back(key, std::move(value));
    return fields.back().second;
  }

  JsonTree& JsonTree::Push(
    JsonTree value
  )
  {
    kind = Kind::Array;
    items.push_back(std::move(value));
    return items.back();
  }

  namespace
  {
    struct Parser
    {
      const std::string& t;
      std::size_t at = 0;
      std::string error;

      void Space()
      {
        while (at < t.size() && (t[at] == ' ' || t[at] == '\t' || t[at] == '\r' || t[at] == '\n')) {
          ++at;
        }
      }

      bool Fail(
        const char* what
      )
      {
        if (error.empty()) {
          error = std::string(what) + " at offset " + std::to_string(at);
        }
        return false;
      }

      bool String(
        std::string& out
      )
      {
        if (at >= t.size() || t[at] != '"') {
          return Fail("a string expected");
        }
        ++at;
        while (at < t.size()) {
          const char c = t[at++];
          if (c == '"') {
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
          case 'b':
            out += '\b';
            break;
          case 'f':
            out += '\f';
            break;
          case 'u': {
            if (at + 4 > t.size()) {
              return Fail("a short \\u escape");
            }
            const unsigned code = static_cast<unsigned>(std::strtoul(t.substr(at, 4).c_str(), nullptr, 16));
            at += 4;
            // UTF-8 for the basic plane (the editor writes ASCII; others may write escapes).
            if (code < 0x80) {
              out += static_cast<char>(code);
            } else if (code < 0x800) {
              out += static_cast<char>(0xC0 | (code >> 6));
              out += static_cast<char>(0x80 | (code & 0x3F));
            } else {
              out += static_cast<char>(0xE0 | (code >> 12));
              out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
              out += static_cast<char>(0x80 | (code & 0x3F));
            }
            break;
          }
          default:
            out += e;
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
          ++at;
          out.kind = JsonTree::Kind::Object;
          Space();
          if (at < t.size() && t[at] == '}') {
            ++at;
            return true;
          }
          for (;;) {
            Space();
            std::string key;
            if (!String(key)) {
              return false;
            }
            Space();
            if (at >= t.size() || t[at] != ':') {
              return Fail("':' expected");
            }
            ++at;
            JsonTree value;
            if (!Value(value, depth + 1)) {
              return false;
            }
            out.fields.emplace_back(std::move(key), std::move(value));
            Space();
            if (at < t.size() && t[at] == ',') {
              ++at;
              continue;
            }
            if (at < t.size() && t[at] == '}') {
              ++at;
              return true;
            }
            return Fail("',' or '}' expected");
          }
        }
        if (c == '[') {
          ++at;
          out.kind = JsonTree::Kind::Array;
          Space();
          if (at < t.size() && t[at] == ']') {
            ++at;
            return true;
          }
          for (;;) {
            JsonTree value;
            if (!Value(value, depth + 1)) {
              return false;
            }
            out.items.push_back(std::move(value));
            Space();
            if (at < t.size() && t[at] == ',') {
              ++at;
              continue;
            }
            if (at < t.size() && t[at] == ']') {
              ++at;
              return true;
            }
            return Fail("',' or ']' expected");
          }
        }
        if (c == '"') {
          out.kind = JsonTree::Kind::String;
          return String(out.s);
        }
        if (t.compare(at, 4, "true") == 0) {
          at += 4;
          out = JsonTree::Flag(true);
          return true;
        }
        if (t.compare(at, 5, "false") == 0) {
          at += 5;
          out = JsonTree::Flag(false);
          return true;
        }
        if (t.compare(at, 4, "null") == 0) {
          at += 4;
          out = JsonTree{};
          return true;
        }
        char* end = nullptr;
        const double d = std::strtod(t.c_str() + at, &end);
        if (end == t.c_str() + at) {
          return Fail("a value expected");
        }
        at = static_cast<std::size_t>(end - t.c_str());
        out = JsonTree::Number(d);
        return true;
      }
    };

    void Quote(
      const std::string& s,
      std::string& out
    )
    {
      out += '"';
      for (const char c : s) {
        switch (c) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\n':
          out += "\\n";
          break;
        case '\r':
          out += "\\r";
          break;
        case '\t':
          out += "\\t";
          break;
        default:
          if (static_cast<unsigned char>(c) < 0x20) {
            char esc[8];
            (void)std::snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
            out += esc;
          } else {
            out += c;
          }
          break;
        }
      }
      out += '"';
    }

    bool Flat(
      const JsonTree& node
    )
    {
      for (const JsonTree& item : node.items) {
        if (item.kind == JsonTree::Kind::Array || item.kind == JsonTree::Kind::Object) {
          return false;
        }
      }
      for (const auto& field : node.fields) {
        if (field.second.kind == JsonTree::Kind::Array || field.second.kind == JsonTree::Kind::Object) {
          return false;
        }
      }
      return true;
    }

    void Write(
      const JsonTree& node,
      const int indent,
      std::string& out
    )
    {
      switch (node.kind) {
      case JsonTree::Kind::Null:
        out += "null";
        return;
      case JsonTree::Kind::Bool:
        out += node.b ? "true" : "false";
        return;
      case JsonTree::Kind::Number: {
        if (std::isfinite(node.n) && node.n == std::floor(node.n) && std::abs(node.n) < 1e15) {
          char text[32];
          (void)std::snprintf(text, sizeof(text), "%.0f", node.n);
          out += text;
        } else {
          char text[40];
          (void)std::snprintf(text, sizeof(text), "%.9g", std::isfinite(node.n) ? node.n : 0.0);
          out += text;
        }
        return;
      }
      case JsonTree::Kind::String:
        Quote(node.s, out);
        return;
      case JsonTree::Kind::Array:
      case JsonTree::Kind::Object: {
        const bool object = node.kind == JsonTree::Kind::Object;
        const std::size_t count = object ? node.fields.size() : node.items.size();
        out += object ? '{' : '[';
        if (count == 0) {
          out += object ? '}' : ']';
          return;
        }
        // Short lists of plain values stay on one line.
        const bool oneLine = Flat(node) && count <= 12;
        const std::string pad(static_cast<std::size_t>(indent + 2), ' ');
        for (std::size_t i = 0; i < count; ++i) {
          out += i == 0 ? "" : ",";
          out += oneLine ? (i == 0 ? "" : " ") : "\n" + pad;
          if (object) {
            Quote(node.fields[i].first, out);
            out += ": ";
            Write(node.fields[i].second, indent + 2, out);
          } else {
            Write(node.items[i], indent + 2, out);
          }
        }
        if (!oneLine) {
          out += "\n" + std::string(static_cast<std::size_t>(indent), ' ');
        }
        out += object ? '}' : ']';
        return;
      }
      }
    }
  } // namespace

  std::expected<JsonTree, std::string> ParseJsonTree(
    const std::string& text
  )
  {
    Parser p{text, 0, {}};
    JsonTree out;
    if (!p.Value(out, 0)) {
      return std::unexpected(p.error);
    }
    p.Space();
    if (p.at != text.size()) {
      return std::unexpected("text after the value at offset " + std::to_string(p.at));
    }
    return out;
  }

  std::string WriteJsonTree(
    const JsonTree& node,
    const int indent
  )
  {
    std::string out;
    Write(node, indent, out);
    return out;
  }
} // namespace faf::editor
