#pragma once

#include <array>
#include <optional>
#include <string>
#include <vector>

#include "editor/tools/EdHeightBrush.h"

namespace faf::editor
{
  /**
   * Each slot's mirror under the symmetry: the slot whose start is nearest its start's first copy (-1 when the slot has
   * no start, the symmetry makes no copy, or the nearest is itself). `starts` is by slot, x and z.
   */
  std::vector<int> MirrorPartners(const std::vector<std::optional<std::array<float, 2>>>& starts, int width, int height,
                                  Symmetry symmetry, int turns);

  /**
   * The slot order with each start followed by its mirror, the pairs in the order their first slot had: so slots 1 and
   * 2, 3 and 4... face each other, which FAF's lobby splits into fair teams with its "odd vs even" auto teams. Slots
   * without a mirror keep their place among the rest, after the pairs. Returns indices into the old order.
   */
  std::vector<int> PairMirroredSlots(const std::vector<int>& partners);

  /** The next free `ARMY_<n>` after every `ARMY_<k>` given (ARMY_1 when there are none). */
  std::string NextArmyName(const std::vector<std::string>& names);
} // namespace faf::editor
