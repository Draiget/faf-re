#pragma once

#include <string>
#include <vector>

#include "editor/doc/EdUnits.h"

namespace faf::editor
{
  /**
   * FAForeverMapEditor's units file (`.scunits`, JsonUtility's dump of its UnitsStorage): each unit's blueprint id,
   * position in FAFME's world units, rotation as a Unity quaternion (UnitInstance.RotationFromScmapRotation: the
   * Orientation with its second value negated, as Euler angles), orders and platoon, and the units' centre.
   */
  std::string UnitsToScunits(const std::vector<SaveUnit>& units);
  /** A `.scunits` file's units (no names; game positions and Orientation) and their centre; false with `error`. */
  bool UnitsFromScunits(const std::string& text, std::vector<SaveUnit>& units, float (&centre)[3], std::string& error);
  /**
   * Units from another map moved onto this one (`width` x `height`): when one lies off it, all of them move so their
   * centre is the map's (FAFME moves only the ones off the map, which pulls a group apart). True when they moved.
   */
  bool FitUnitsOnMap(std::vector<SaveUnit>& units, const float (&centre)[3], float width, float height);
} // namespace faf::editor
