#pragma once

// A small JSON tree: parsed whole (nesting respected, unlike the key search of EdJson.h) and written back. For the
// editor's own `.editor` files (paths, detail classes, unit wizard templates).

#include <expected>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  struct JsonTree
  {
    enum class Kind
    {
      Null,
      Bool,
      Number,
      String,
      Array,
      Object,
    };
    Kind kind = Kind::Null;
    bool b = false;
    double n = 0.0;
    std::string s;
    std::vector<JsonTree> items;                          // Array
    std::vector<std::pair<std::string, JsonTree>> fields; // Object, in file order

    /** A member of an object, or null when there is none (or this isn't an object). */
    [[nodiscard]] const JsonTree* Get(const std::string& key) const;
    [[nodiscard]] double Num(const std::string& key, double fallback) const;
    [[nodiscard]] float Float(
      const std::string& key,
      const float fallback
    ) const
    {
      return static_cast<float>(Num(key, fallback));
    }
    [[nodiscard]] int Int(
      const std::string& key,
      const int fallback
    ) const
    {
      return static_cast<int>(Num(key, fallback));
    }
    [[nodiscard]] bool Bool(const std::string& key, bool fallback) const;
    [[nodiscard]] std::string Str(const std::string& key, const std::string& fallback) const;

    static JsonTree Number(double value);
    static JsonTree Text(std::string value);
    static JsonTree Flag(bool value);
    static JsonTree MakeArray();
    static JsonTree MakeObject();
    /** Adds a member (objects) and returns it. */
    JsonTree& Set(const std::string& key, JsonTree value);
    /** Adds an item (arrays) and returns it. */
    JsonTree& Push(JsonTree value);
  };

  /** Parses `text`; the error (and the offset) on bad JSON. */
  [[nodiscard]] std::expected<JsonTree, std::string> ParseJsonTree(const std::string& text);
  /** The node as JSON text: objects and arrays of objects one member a line, `indent` spaces deep. */
  [[nodiscard]] std::string WriteJsonTree(const JsonTree& node, int indent = 0);
} // namespace faf::editor
