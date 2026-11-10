#pragma once

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * A Lua value as a map's data files write them, read from text without a Lua state: a number, a string, a boolean, a
   * name, or a table of named fields and list items. Each value keeps where its text starts and ends, so an edit can
   * replace one value and leave the rest of the file (comments, layout) as it was.
   */
  struct LuaText
  {
    /** A number, `'string'` or `"string"` (with its quotes), `true`/`false`, or a name; empty for a table. */
    std::string atom;
    bool isTable = false;
    /** `name = value` and `['name'] = value` fields, in file order. */
    std::vector<std::pair<std::string, LuaText>> fields;
    /** List items, in order. */
    std::vector<LuaText> items;
    std::size_t start = 0;
    std::size_t end = 0;

    [[nodiscard]] const LuaText* Field(const std::string& name) const;
    [[nodiscard]] bool IsNumber() const;
    [[nodiscard]] double Number(double fallback = 0.0) const;
    [[nodiscard]] bool IsTrue() const { return atom == "true"; }
  };

  /** The value that starts at `at` (after spaces and comments); false with `error`. */
  bool ReadLuaValue(const std::string& text, std::size_t at, LuaText& value, std::string& error);

  /** A top-level `name = value` of a file, its value read; false when the file has no such assignment or it doesn't read. */
  bool ReadLuaAssignment(const std::string& text, const std::string& name, LuaText& value, std::string& error);

  /** A number as a map file writes it: no trailing zeros, at most 3 decimals. */
  std::string LuaNumber(double value);
} // namespace faf::editor
