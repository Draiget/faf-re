#pragma once

#include <algorithm>

namespace faf::editor
{
  /**
   * A list's or grid's height that fills what its panel has left (design: lists and grids fill their panel), keeping
   * `reserve` for what follows it and never under `minimum`: `available` is the panel's room from the list's top.
   * FillHeight (ui/EdUiScale.h) gives it from the cursor.
   */
  [[nodiscard]] inline float FillHeightFor(
    const float available,
    const float reserve,
    const float minimum
  )
  {
    return std::max(minimum, available - reserve);
  }
} // namespace faf::editor
