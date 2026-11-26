#pragma once

// Engine addition (in-game launcher plan, WP1): the JSON reader the map editor used for FAF's API answers
// (src/editor/doc/EdFafApi before WP1), shared with the game's launcher. Unchanged in behaviour.

#include <expected>
#include <string>
#include <utility>
#include <vector>

namespace faf::online
{
  /** A JSON value: what the API answers are made of. */
  struct JsonNode
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
    bool boolean = false;
    double number = 0.0;
    std::string text;
    std::vector<JsonNode> items;
    std::vector<std::pair<std::string, JsonNode>> members;

    [[nodiscard]] const JsonNode* Get(const std::string& key) const;
    /** A member's text; a whole number reads as its digits; empty when missing or of another kind. */
    [[nodiscard]] std::string String(const std::string& key) const;
    [[nodiscard]] double Number(const std::string& key, double fallback = 0.0) const;
    [[nodiscard]] bool Bool(const std::string& key) const;
  };

  /** `text` read as JSON (strings with their \u escapes as UTF-8); the error otherwise. */
  [[nodiscard]] std::expected<JsonNode, std::string> ParseJson(const std::string& text);
} // namespace faf::online
