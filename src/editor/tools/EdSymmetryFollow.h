#pragma once

#include "editor/tools/EdHeightBrush.h"

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Follow symmetry (the consolidated design's Select tool: "follow symmetry on move, turn and delete"): an object's
   * mirrored copies are the objects of its kind nearest the images of its place under the map's symmetry, and an edit
   * of the object is carried to each of them through the same image (its place, its heading).
   */
  struct FollowItem
  {
    float x = 0.0f;
    float z = 0.0f;
    std::string key; // what must match: a prop's blueprint, a marker's type, a unit's blueprint
  };

  /**
   * For each of `selected` (indices into `items`), the item at each copy 1..n-1 of its place (HeightBrushCentres over a
   * `width` x `height` sample field): the nearest item with the same key within `tolerance` of the image, not itself
   * selected and not taken by another copy; -1 where none is. `partners[i][c - 1]` for copy c.
   */
  [[nodiscard]] std::vector<std::vector<int>> FindSymmetryPartners(
    const std::vector<FollowItem>& items,
    const std::vector<int>& selected,
    int width,
    int height,
    Symmetry symmetry,
    int turns,
    float tolerance
  );

  /**
   * The copies of a place and heading (radians; the model's front is (sin, cos) on the ground), the place itself
   * first, as the brushes and the prop placement make them. Returns how many.
   */
  int SymmetricPlaces(
    int width,
    int height,
    Symmetry symmetry,
    int turns,
    float x,
    float z,
    float heading,
    float (&outX)[kMaxSymmetryCopies],
    float (&outZ)[kMaxSymmetryCopies],
    float (&outHeading)[kMaxSymmetryCopies]
  );
} // namespace faf::editor
