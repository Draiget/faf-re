#pragma once

#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /** What the Properties panel shows: the selection's active (first) item, by kind. */
  struct SelectionProperties
  {
    enum class Kind
    {
      None,
      Prop,
      Marker,
      Unit,
      Decal,
    };
    Kind kind = Kind::None;
    /** How many are selected (the panel edits the first). */
    int count = 0;
    /** A marker's or unit's name; a prop's blueprint file; "decal <index>". */
    std::string name;
    /** A marker's type, a prop's blueprint path, a unit's blueprint id, a decal's texture. */
    std::string type;
    /** A unit's army. */
    std::string owner;
    /** A prop's reclaim and mesh, as the Props panel shows them. */
    std::string details;
    /** x, height, z. */
    float position[3] = {0.0f, 0.0f, 0.0f};
    /** The turn about the vertical, in degrees (props, units, markers, decals). */
    float heading = 0.0f;
    /** A decal's size (x, z). */
    float size[2] = {0.0f, 0.0f};
    /** A marker's other properties, as `_save.lua` writes them (`STRING( 'x' )`, `FLOAT( 1 )`). */
    std::vector<std::pair<std::string, std::string>> fields;
  };

  /** A change the Properties panel asks for, made by the view as one undo step. */
  struct PropertyEdit
  {
    enum class What
    {
      None,
      Position,
      Heading,
      Size,
      Name,
      Field,
    };
    What what = What::None;
    float values[3] = {0.0f, 0.0f, 0.0f};
    std::string key;
    std::string value;
  };
} // namespace faf::editor
