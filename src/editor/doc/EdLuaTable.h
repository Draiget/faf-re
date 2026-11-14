#pragma once

// Lua table literals read as data, never run (FAF Studio's generated tables, blueprints): `Name = { key = value,
// ['key'] = value, value, ... }` at the top level, nested tables, strings ('', "", [[ ]]), numbers, true / false / nil,
// comments. A table with named keys is a JsonTree object (its positional values are its `items` as well), one without
// an array. Calls such as `Sound { ... }` keep their table (the call's name is the member "__call").

#include "editor/doc/EdJsonTree.h"

#include <string>

namespace faf::editor
{
  /** The top-level assignments of `text` as an object (name -> value); false with `error`. */
  bool ParseLuaAssignments(const std::string& text, JsonTree& out, std::string& error);
  /** One value (`{ ... }`, a string, a number ...) at the start of `text`. */
  bool ParseLuaValue(const std::string& text, JsonTree& out, std::string& error);
} // namespace faf::editor
