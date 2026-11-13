#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Arrange (the Select tool's and the Edit menu's): a selection's places lined up, spread, put on a circle, snapped or
   * mirrored. Places are on the map's ground plane: x to the right, z down (the map's top is z 0).
   */
  enum class ArrangeOp
  {
    AlignLeft,    // every x to the leftmost
    AlignCentreX, // every x to the middle of the leftmost and the rightmost
    AlignRight,
    AlignTop, // every z to the topmost (the smallest z)
    AlignCentreZ,
    AlignBottom,
    DistributeX, // the leftmost and rightmost stay, the others evenly between them in their order
    DistributeZ,
    Circle,  // on a circle about their middle, its radius their mean distance from it, evenly in their order round it
    Snap,    // to the grid of `step`
    MirrorX, // left-right about their middle; headings mirrored
    MirrorZ, // top-bottom about their middle; headings mirrored
    Count
  };

  /** The places of a selection and their headings (radians; facing (sin h, cos h) in x, z). */
  struct ArrangePlaces
  {
    std::vector<float> x;
    std::vector<float> z;
    std::vector<float> heading;
  };

  /** Changes `places` (headings only by the mirrors); false (unchanged) when there are too few for `op` or `step` <= 0.
   */
  bool Arrange(ArrangeOp op, ArrangePlaces& places, float step = 1.0f);

  /** The fewest places `op` needs: 2, or 3 for Distribute and Circle, 1 for Snap. */
  [[nodiscard]] int ArrangeMinimum(ArrangeOp op) noexcept;

  /** Its name for menus and logs ("Align left"), and the id for commands and test switches ("alignleft"). */
  [[nodiscard]] const char* ArrangeTitle(ArrangeOp op) noexcept;
  [[nodiscard]] const char* ArrangeId(ArrangeOp op) noexcept;
  /** The op with this id; Count when there is none. */
  [[nodiscard]] ArrangeOp ArrangeFromId(const std::string& id) noexcept;
} // namespace faf::editor
