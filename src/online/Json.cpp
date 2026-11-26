// Engine addition (in-game launcher plan, WP1): the reader, moved from src/editor/doc/EdFafApi.cpp unchanged but for
// keeping a number's digits (WP2). The builders and the writer are WP2's.

#include "online/Json.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace faf::online
{
  namespace
  {
    struct JsonReader
    {
      const std::string& text;
      std::size_t at = 0;
      std::string error;

      void Space()
      {
        while (at < text.size() && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' || text[at] == '\n')) {
          ++at;
        }
      }

      static void PutUtf8(
        std::string& out,
        std::uint32_t code
      )
      {
        if (code < 0x80u) {
          out += static_cast<char>(code);
        } else if (code < 0x800u) {
          out += static_cast<char>(0xC0u | (code >> 6));
          out += static_cast<char>(0x80u | (code & 0x3Fu));
        } else if (code < 0x10000u) {
          out += static_cast<char>(0xE0u | (code >> 12));
          out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
          out += static_cast<char>(0x80u | (code & 0x3Fu));
        } else {
          out += static_cast<char>(0xF0u | (code >> 18));
          out += static_cast<char>(0x80u | ((code >> 12) & 0x3Fu));
          out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
          out += static_cast<char>(0x80u | (code & 0x3Fu));
        }
      }

      bool Hex4(
        std::uint32_t& code
      )
      {
        if (at + 4 > text.size()) {
          return false;
        }
        code = static_cast<std::uint32_t>(std::strtoul(text.substr(at, 4).c_str(), nullptr, 16));
        at += 4;
        return true;
      }

      bool String(
        std::string& out
      )
      {
        ++at; // the opening quote
        while (at < text.size()) {
          const char c = text[at++];
          if (c == '"') {
            return true;
          }
          if (c != '\\') {
            out += c;
            continue;
          }
          if (at >= text.size()) {
            break;
          }
          const char e = text[at++];
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
            std::uint32_t code = 0;
            if (!Hex4(code)) {
              error = "a broken \\u escape";
              return false;
            }
            // A surrogate pair.
            if (code >= 0xD800u && code < 0xDC00u && at + 6 <= text.size() && text[at] == '\\' && text[at + 1] == 'u') {
              at += 2;
              std::uint32_t low = 0;
              if (Hex4(low) && low >= 0xDC00u && low < 0xE000u) {
                code = 0x10000u + ((code - 0xD800u) << 10) + (low - 0xDC00u);
              }
            }
            PutUtf8(out, code);
            break;
          }
          default:
            out += e;
            break;
          }
        }
        error = "a string doesn't end";
        return false;
      }

      bool Value(
        JsonNode& node,
        const int depth
      )
      {
        if (depth > 128) {
          error = "nested too deep";
          return false;
        }
        Space();
        if (at >= text.size()) {
          error = "the text ends inside a value";
          return false;
        }
        const char c = text[at];
        if (c == '{') {
          node.kind = JsonNode::Kind::Object;
          ++at;
          Space();
          if (at < text.size() && text[at] == '}') {
            ++at;
            return true;
          }
          for (;;) {
            Space();
            if (at >= text.size() || text[at] != '"') {
              error = "an object's key isn't a string";
              return false;
            }
            std::string key;
            if (!String(key)) {
              return false;
            }
            Space();
            if (at >= text.size() || text[at] != ':') {
              error = "no ':' after a key";
              return false;
            }
            ++at;
            JsonNode child;
            if (!Value(child, depth + 1)) {
              return false;
            }
            node.members.emplace_back(std::move(key), std::move(child));
            Space();
            if (at < text.size() && text[at] == ',') {
              ++at;
              continue;
            }
            if (at < text.size() && text[at] == '}') {
              ++at;
              return true;
            }
            error = "an object doesn't end";
            return false;
          }
        }
        if (c == '[') {
          node.kind = JsonNode::Kind::Array;
          ++at;
          Space();
          if (at < text.size() && text[at] == ']') {
            ++at;
            return true;
          }
          for (;;) {
            JsonNode child;
            if (!Value(child, depth + 1)) {
              return false;
            }
            node.items.push_back(std::move(child));
            Space();
            if (at < text.size() && text[at] == ',') {
              ++at;
              continue;
            }
            if (at < text.size() && text[at] == ']') {
              ++at;
              return true;
            }
            error = "an array doesn't end";
            return false;
          }
        }
        if (c == '"') {
          node.kind = JsonNode::Kind::String;
          return String(node.text);
        }
        if (text.compare(at, 4, "true") == 0 || text.compare(at, 5, "false") == 0) {
          node.kind = JsonNode::Kind::Bool;
          node.boolean = text[at] == 't';
          at += node.boolean ? 4 : 5;
          return true;
        }
        if (text.compare(at, 4, "null") == 0) {
          at += 4;
          return true;
        }
        char* end = nullptr;
        node.number = std::strtod(text.c_str() + at, &end);
        if (end == text.c_str() + at) {
          error = std::string("unexpected '") + c + "'";
          return false;
        }
        node.kind = JsonNode::Kind::Number;
        node.text.assign(text, at, static_cast<std::size_t>(end - (text.c_str() + at))); // the digits as written
        at = static_cast<std::size_t>(end - text.c_str());
        return true;
      }
    };
  } // namespace

  const JsonNode* JsonNode::Get(
    const std::string& key
  ) const
  {
    for (const auto& [name, value] : members) {
      if (name == key) {
        return &value;
      }
    }
    return nullptr;
  }

  std::string JsonNode::String(
    const std::string& key
  ) const
  {
    const JsonNode* const value = Get(key);
    if (value == nullptr) {
      return {};
    }
    if (value->kind == Kind::Number) {
      const double n = value->number;
      return std::floor(n) == n ? std::to_string(static_cast<long long>(n)) : std::to_string(n);
    }
    return value->kind == Kind::String ? value->text : std::string();
  }

  double JsonNode::Number(
    const std::string& key,
    const double fallback
  ) const
  {
    const JsonNode* const value = Get(key);
    return value != nullptr && value->kind == Kind::Number ? value->number : fallback;
  }

  bool JsonNode::Bool(
    const std::string& key
  ) const
  {
    const JsonNode* const value = Get(key);
    return value != nullptr && value->kind == Kind::Bool && value->boolean;
  }

  std::expected<JsonNode, std::string> ParseJson(
    const std::string& text
  )
  {
    JsonReader reader{text, 0, {}};
    JsonNode out;
    if (!reader.Value(out, 0)) {
      return std::unexpected(reader.error);
    }
    reader.Space();
    if (reader.at != text.size()) {
      return std::unexpected("text after the value");
    }
    return out;
  }

  JsonNode JsonString(
    std::string text
  )
  {
    JsonNode node;
    node.kind = JsonNode::Kind::String;
    node.text = std::move(text);
    return node;
  }

  JsonNode JsonNumber(
    const double number
  )
  {
    JsonNode node;
    node.kind = JsonNode::Kind::Number;
    node.number = number;
    return node;
  }

  JsonNode JsonDigits(
    std::string digits
  )
  {
    JsonNode node;
    node.kind = JsonNode::Kind::Number;
    node.number = std::strtod(digits.c_str(), nullptr);
    node.text = std::move(digits);
    return node;
  }

  JsonNode JsonBool(
    const bool value
  )
  {
    JsonNode node;
    node.kind = JsonNode::Kind::Bool;
    node.boolean = value;
    return node;
  }

  JsonNode JsonObject(
    std::vector<std::pair<std::string, JsonNode>> members
  )
  {
    JsonNode node;
    node.kind = JsonNode::Kind::Object;
    node.members = std::move(members);
    return node;
  }

  JsonNode JsonArray(
    std::vector<JsonNode> items
  )
  {
    JsonNode node;
    node.kind = JsonNode::Kind::Array;
    node.items = std::move(items);
    return node;
  }

  namespace
  {
    void WriteString(
      std::string& out,
      const std::string& text
    )
    {
      out += '"';
      for (const char c : text) {
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
        case '\b':
          out += "\\b";
          break;
        case '\f':
          out += "\\f";
          break;
        default:
          if (static_cast<unsigned char>(c) < 0x20u) {
            char escaped[8];
            (void)std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(c));
            out += escaped;
          } else {
            out += c;
          }
        }
      }
      out += '"';
    }

    /** Digits a number may be written with as they are: an optional '-', digits, '.', exponent. */
    bool LooksLikeNumber(
      const std::string& digits
    )
    {
      if (digits.empty()) {
        return false;
      }
      for (const char c : digits) {
        if ((c < '0' || c > '9') && c != '-' && c != '+' && c != '.' && c != 'e' && c != 'E') {
          return false;
        }
      }
      return true;
    }

    void Write(
      std::string& out,
      const JsonNode& node
    )
    {
      switch (node.kind) {
      case JsonNode::Kind::Null:
        out += "null";
        break;
      case JsonNode::Kind::Bool:
        out += node.boolean ? "true" : "false";
        break;
      case JsonNode::Kind::Number: {
        if (LooksLikeNumber(node.text)) {
          out += node.text;
        } else if (!std::isfinite(node.number)) {
          out += "null";
        } else {
          char number[40];
          const double n = node.number;
          if (std::floor(n) == n && std::fabs(n) < 1e15) {
            (void)std::snprintf(number, sizeof(number), "%lld", static_cast<long long>(n));
          } else {
            (void)std::snprintf(number, sizeof(number), "%.17g", n);
          }
          out += number;
        }
        break;
      }
      case JsonNode::Kind::String:
        WriteString(out, node.text);
        break;
      case JsonNode::Kind::Array:
        out += '[';
        for (std::size_t i = 0; i < node.items.size(); ++i) {
          if (i != 0) {
            out += ',';
          }
          Write(out, node.items[i]);
        }
        out += ']';
        break;
      case JsonNode::Kind::Object:
        out += '{';
        for (std::size_t i = 0; i < node.members.size(); ++i) {
          if (i != 0) {
            out += ',';
          }
          WriteString(out, node.members[i].first);
          out += ':';
          Write(out, node.members[i].second);
        }
        out += '}';
        break;
      }
    }
  } // namespace

  std::string ToJson(
    const JsonNode& node
  )
  {
    std::string out;
    Write(out, node);
    return out;
  }
} // namespace faf::online
