#include "netlink/Json.h"

#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::netlink
{
  namespace
  {
    const JsonValue kNull;
  } // namespace

  const JsonValue& JsonValue::operator[](const std::size_t i) const
  {
    return mKind == Kind::Array && i < mItems.size() ? mItems[i] : kNull;
  }

  const JsonValue* JsonValue::Find(const std::string_view key) const
  {
    if (mKind != Kind::Object) {
      return nullptr;
    }
    for (const auto& [name, value] : mMembers) {
      if (name == key) {
        return &value;
      }
    }
    return nullptr;
  }

  const JsonValue& JsonValue::Get(const std::string_view key) const
  {
    const JsonValue* v = Find(key);
    return v != nullptr ? *v : kNull;
  }

  void JsonValue::Set(std::string key, JsonValue v)
  {
    for (auto& [name, value] : mMembers) {
      if (name == key) {
        value = std::move(v);
        return;
      }
    }
    mMembers.emplace_back(std::move(key), std::move(v));
  }

  class JsonReader
  {
  public:
    explicit JsonReader(const std::string_view text) : mText(text) {}

    std::optional<JsonValue> ParseDocument(std::string* error)
    {
      JsonValue v;
      SkipSpace();
      if (!ParseValue(v, 0)) {
        if (error != nullptr) {
          *error = mError + " at offset " + std::to_string(mPos);
        }
        return std::nullopt;
      }
      SkipSpace();
      if (mPos != mText.size()) {
        if (error != nullptr) {
          *error = "trailing characters at offset " + std::to_string(mPos);
        }
        return std::nullopt;
      }
      return v;
    }

  private:
    static constexpr int kMaxDepth = 64;

    bool Fail(const char* what)
    {
      mError = what;
      return false;
    }

    void SkipSpace()
    {
      while (mPos < mText.size()) {
        const char c = mText[mPos];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
          break;
        }
        ++mPos;
      }
    }

    bool Literal(const std::string_view word)
    {
      if (mText.substr(mPos, word.size()) != word) {
        return Fail("bad literal");
      }
      mPos += word.size();
      return true;
    }

    bool ParseValue(JsonValue& out, const int depth)
    {
      if (depth > kMaxDepth) {
        return Fail("nesting too deep");
      }
      if (mPos >= mText.size()) {
        return Fail("unexpected end");
      }
      switch (mText[mPos]) {
        case 'n':
          out = JsonValue();
          return Literal("null");
        case 't':
          out = JsonValue(true);
          return Literal("true");
        case 'f':
          out = JsonValue(false);
          return Literal("false");
        case '"': {
          std::string s;
          if (!ParseString(s)) {
            return false;
          }
          out = JsonValue(std::move(s));
          return true;
        }
        case '[':
          return ParseArray(out, depth);
        case '{':
          return ParseObject(out, depth);
        default:
          return ParseNumber(out);
      }
    }

    bool ParseArray(JsonValue& out, const int depth)
    {
      out = JsonValue::Array();
      ++mPos;
      SkipSpace();
      if (mPos < mText.size() && mText[mPos] == ']') {
        ++mPos;
        return true;
      }
      for (;;) {
        JsonValue item;
        SkipSpace();
        if (!ParseValue(item, depth + 1)) {
          return false;
        }
        out.mItems.push_back(std::move(item));
        SkipSpace();
        if (mPos >= mText.size()) {
          return Fail("unterminated array");
        }
        if (mText[mPos] == ',') {
          ++mPos;
          continue;
        }
        if (mText[mPos] == ']') {
          ++mPos;
          return true;
        }
        return Fail("expected , or ]");
      }
    }

    bool ParseObject(JsonValue& out, const int depth)
    {
      out = JsonValue::Object();
      ++mPos;
      SkipSpace();
      if (mPos < mText.size() && mText[mPos] == '}') {
        ++mPos;
        return true;
      }
      for (;;) {
        SkipSpace();
        if (mPos >= mText.size() || mText[mPos] != '"') {
          return Fail("expected member name");
        }
        std::string key;
        if (!ParseString(key)) {
          return false;
        }
        SkipSpace();
        if (mPos >= mText.size() || mText[mPos] != ':') {
          return Fail("expected :");
        }
        ++mPos;
        SkipSpace();
        JsonValue value;
        if (!ParseValue(value, depth + 1)) {
          return false;
        }
        out.mMembers.emplace_back(std::move(key), std::move(value));
        SkipSpace();
        if (mPos >= mText.size()) {
          return Fail("unterminated object");
        }
        if (mText[mPos] == ',') {
          ++mPos;
          continue;
        }
        if (mText[mPos] == '}') {
          ++mPos;
          return true;
        }
        return Fail("expected , or }");
      }
    }

    static void AppendUtf8(std::string& s, const std::uint32_t cp)
    {
      if (cp < 0x80) {
        s += static_cast<char>(cp);
      } else if (cp < 0x800) {
        s += static_cast<char>(0xC0 | (cp >> 6));
        s += static_cast<char>(0x80 | (cp & 0x3F));
      } else if (cp < 0x10000) {
        s += static_cast<char>(0xE0 | (cp >> 12));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
      } else {
        s += static_cast<char>(0xF0 | (cp >> 18));
        s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
      }
    }

    bool Hex4(std::uint32_t& out)
    {
      if (mPos + 4 > mText.size()) {
        return Fail("short \\u escape");
      }
      out = 0;
      for (int i = 0; i < 4; ++i) {
        const char c = mText[mPos++];
        out <<= 4;
        if (c >= '0' && c <= '9') {
          out |= static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
          out |= static_cast<std::uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
          out |= static_cast<std::uint32_t>(c - 'A' + 10);
        } else {
          return Fail("bad \\u escape");
        }
      }
      return true;
    }

    bool ParseString(std::string& out)
    {
      ++mPos; // opening quote
      while (mPos < mText.size()) {
        const char c = mText[mPos++];
        if (c == '"') {
          return true;
        }
        if (c != '\\') {
          out += c;
          continue;
        }
        if (mPos >= mText.size()) {
          break;
        }
        const char e = mText[mPos++];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            std::uint32_t cp = 0;
            if (!Hex4(cp)) {
              return false;
            }
            if (cp >= 0xD800 && cp < 0xDC00 && mPos + 1 < mText.size() && mText[mPos] == '\\' && mText[mPos + 1] == 'u') {
              mPos += 2;
              std::uint32_t low = 0;
              if (!Hex4(low)) {
                return false;
              }
              cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            }
            AppendUtf8(out, cp);
            break;
          }
          default:
            return Fail("bad escape");
        }
      }
      return Fail("unterminated string");
    }

    bool ParseNumber(JsonValue& out)
    {
      const std::size_t start = mPos;
      bool isInt = true;
      if (mPos < mText.size() && mText[mPos] == '-') {
        ++mPos;
      }
      while (mPos < mText.size()) {
        const char c = mText[mPos];
        if (c >= '0' && c <= '9') {
          ++mPos;
        } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
          isInt = false;
          ++mPos;
        } else {
          break;
        }
      }
      const std::string_view num = mText.substr(start, mPos - start);
      if (num.empty() || num == "-") {
        return Fail("bad value");
      }
      if (isInt) {
        std::int64_t v = 0;
        const auto [p, ec] = std::from_chars(num.data(), num.data() + num.size(), v);
        if (ec == std::errc() && p == num.data() + num.size()) {
          out = JsonValue(v);
          return true;
        }
      }
      // strtod needs a terminated buffer.
      const std::string copy(num);
      char* end = nullptr;
      const double d = std::strtod(copy.c_str(), &end);
      if (end != copy.c_str() + copy.size()) {
        return Fail("bad number");
      }
      out = JsonValue(d);
      return true;
    }

    std::string_view mText;
    std::size_t mPos = 0;
    std::string mError;
  };

  std::optional<JsonValue> ParseJson(const std::string_view text, std::string* error)
  {
    return JsonReader(text).ParseDocument(error);
  }

  namespace
  {
    void WriteEscapedUnit(std::string& out, const std::uint32_t unit)
    {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(unit));
      out += buf;
    }

    void WriteString(std::string& out, const std::string& s)
    {
      out += '"';
      for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
          ++i;
          switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '{':
            case '}':
              WriteEscapedUnit(out, c);
              break;
            default:
              if (c < 0x20 || c == 0x7F) {
                WriteEscapedUnit(out, c);
              } else {
                out += static_cast<char>(c);
              }
          }
          continue;
        }
        // UTF-8 sequence -> code point -> \u escapes (surrogate pair above
        // U+FFFF). Invalid bytes become U+FFFD.
        std::uint32_t cp = 0xFFFD;
        std::size_t len = 1;
        if ((c & 0xE0) == 0xC0 && i + 1 < s.size()) {
          cp = ((c & 0x1Fu) << 6) | (static_cast<unsigned char>(s[i + 1]) & 0x3Fu);
          len = 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < s.size()) {
          cp = ((c & 0x0Fu) << 12) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6) |
               (static_cast<unsigned char>(s[i + 2]) & 0x3Fu);
          len = 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < s.size()) {
          cp = ((c & 0x07u) << 18) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 12) |
               ((static_cast<unsigned char>(s[i + 2]) & 0x3Fu) << 6) | (static_cast<unsigned char>(s[i + 3]) & 0x3Fu);
          len = 4;
        }
        i += len;
        if (cp >= 0x10000) {
          cp -= 0x10000;
          WriteEscapedUnit(out, 0xD800 + (cp >> 10));
          WriteEscapedUnit(out, 0xDC00 + (cp & 0x3FF));
        } else {
          WriteEscapedUnit(out, cp);
        }
      }
      out += '"';
    }

    void WriteValue(std::string& out, const JsonValue& v)
    {
      switch (v.GetKind()) {
        case JsonValue::Kind::Null:
          out += "null";
          break;
        case JsonValue::Kind::Bool:
          out += v.AsBool() ? "true" : "false";
          break;
        case JsonValue::Kind::Number:
          if (v.IsInteger()) {
            out += std::to_string(v.AsInt());
          } else if (std::isfinite(v.AsDouble())) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.17g", v.AsDouble());
            out += buf;
          } else {
            out += "null";
          }
          break;
        case JsonValue::Kind::String:
          WriteString(out, v.AsString());
          break;
        case JsonValue::Kind::Array: {
          out += '[';
          bool first = true;
          for (const JsonValue& item : v.Items()) {
            if (!first) {
              out += ',';
            }
            first = false;
            WriteValue(out, item);
          }
          out += ']';
          break;
        }
        case JsonValue::Kind::Object: {
          out += '{';
          bool first = true;
          for (const auto& [key, value] : v.Members()) {
            if (!first) {
              out += ',';
            }
            first = false;
            WriteString(out, key);
            out += ':';
            WriteValue(out, value);
          }
          out += '}';
          break;
        }
      }
    }
  } // namespace

  std::string WriteJson(const JsonValue& value)
  {
    std::string out;
    WriteValue(out, value);
    return out;
  }
} // namespace faf::netlink
