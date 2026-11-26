// Engine addition (in-game launcher plan, WP1): moved from src/editor/doc/EdFafApi.cpp unchanged.

#include "online/Json.h"

#include <cmath>
#include <cstdint>
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
} // namespace faf::online
