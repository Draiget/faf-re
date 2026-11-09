#pragma once

// Minimal JSON value, reader and writer for the ICE adapter contract
// (docs/LAUNCHER_ADAPTER_CONTRACT.md): JSON-RPC from the FAF client and the
// CandidatesMessage signalling of FAF's Java adapter. Engine addition, not
// recovered code.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace faf::netlink
{
  class JsonValue
  {
  public:
    enum class Kind
    {
      Null,
      Bool,
      Number,
      String,
      Array,
      Object
    };

    JsonValue() = default;
    JsonValue(std::nullptr_t) {}
    JsonValue(bool b) : mKind(Kind::Bool), mBool(b) {}
    JsonValue(int v) : mKind(Kind::Number), mInt(v), mNumber(v), mIsInt(true) {}
    JsonValue(std::int64_t v) : mKind(Kind::Number), mInt(v), mNumber(static_cast<double>(v)), mIsInt(true) {}
    JsonValue(double v) : mKind(Kind::Number), mInt(static_cast<std::int64_t>(v)), mNumber(v) {}
    JsonValue(const char* s) : mKind(Kind::String), mString(s) {}
    JsonValue(std::string s) : mKind(Kind::String), mString(std::move(s)) {}
    JsonValue(std::string_view s) : mKind(Kind::String), mString(s) {}

    static JsonValue Array() { JsonValue v; v.mKind = Kind::Array; return v; }
    static JsonValue Object() { JsonValue v; v.mKind = Kind::Object; return v; }

    Kind GetKind() const { return mKind; }
    bool IsNull() const { return mKind == Kind::Null; }
    bool IsBool() const { return mKind == Kind::Bool; }
    bool IsNumber() const { return mKind == Kind::Number; }
    bool IsString() const { return mKind == Kind::String; }
    bool IsArray() const { return mKind == Kind::Array; }
    bool IsObject() const { return mKind == Kind::Object; }

    bool AsBool(bool fallback = false) const { return mKind == Kind::Bool ? mBool : fallback; }
    // Integers are kept exactly when the text had no fraction or exponent.
    std::int64_t AsInt(std::int64_t fallback = 0) const
    {
      if (mKind != Kind::Number) {
        return fallback;
      }
      return mIsInt ? mInt : static_cast<std::int64_t>(mNumber);
    }
    double AsDouble(double fallback = 0) const { return mKind == Kind::Number ? mNumber : fallback; }
    bool IsInteger() const { return mKind == Kind::Number && mIsInt; }
    const std::string& AsString() const { return mString; }

    // Arrays.
    std::size_t Size() const { return mKind == Kind::Array ? mItems.size() : mMembers.size(); }
    const JsonValue& operator[](std::size_t i) const;
    void Push(JsonValue v) { mItems.push_back(std::move(v)); }
    const std::vector<JsonValue>& Items() const { return mItems; }

    // Objects keep their members in insertion order (Jackson writes record
    // components in declaration order, and so does Write).
    const JsonValue* Find(std::string_view key) const;
    const JsonValue& Get(std::string_view key) const;
    void Set(std::string key, JsonValue v);
    const std::vector<std::pair<std::string, JsonValue>>& Members() const { return mMembers; }

  private:
    friend class JsonReader;

    Kind mKind = Kind::Null;
    bool mBool = false;
    std::int64_t mInt = 0;
    double mNumber = 0;
    bool mIsInt = false;
    std::string mString;
    std::vector<JsonValue> mItems;
    std::vector<std::pair<std::string, JsonValue>> mMembers;
  };

  // Parses one JSON text; leading and trailing whitespace is allowed.
  std::optional<JsonValue> ParseJson(std::string_view text, std::string* error = nullptr);

  // Writes compact JSON. Every character outside printable ASCII, and '{' and
  // '}' inside strings, are written as \u escapes: the JJsonRpc reader on the
  // other side casts each byte to a char and counts braces without looking at
  // strings (contract §2, "Framing").
  std::string WriteJson(const JsonValue& value);
} // namespace faf::netlink
