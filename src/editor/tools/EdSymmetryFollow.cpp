#include "editor/tools/EdSymmetryFollow.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  std::vector<std::vector<int>> FindSymmetryPartners(
    const std::vector<FollowItem>& items,
    const std::vector<int>& selected,
    const int width,
    const int height,
    const Symmetry symmetry,
    const int turns,
    const float tolerance
  )
  {
    std::vector<std::vector<int>> partners(selected.size());
    std::vector<bool> taken(items.size(), false);
    for (const int index : selected) {
      if (index >= 0 && static_cast<std::size_t>(index) < items.size()) {
        taken[static_cast<std::size_t>(index)] = true; // a selected item is edited itself, never as a copy
      }
    }
    for (std::size_t s = 0; s < selected.size(); ++s) {
      const int index = selected[s];
      if (index < 0 || static_cast<std::size_t>(index) >= items.size()) {
        continue;
      }
      const FollowItem& item = items[static_cast<std::size_t>(index)];
      float cx[kMaxSymmetryCopies];
      float cz[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(width, height, item.x, item.z, symmetry, turns, cx, cz);
      partners[s].assign(static_cast<std::size_t>(std::max(0, copies - 1)), -1);
      for (int c = 1; c < copies; ++c) {
        float best = tolerance;
        int found = -1;
        for (std::size_t j = 0; j < items.size(); ++j) {
          if (taken[j] || items[j].key != item.key) {
            continue;
          }
          const float d = std::hypot(items[j].x - cx[c], items[j].z - cz[c]);
          if (d <= best) {
            best = d;
            found = static_cast<int>(j);
          }
        }
        if (found >= 0) {
          taken[static_cast<std::size_t>(found)] = true;
          partners[s][static_cast<std::size_t>(c - 1)] = found;
        }
      }
    }
    return partners;
  }

  int SymmetricPlaces(
    const int width,
    const int height,
    const Symmetry symmetry,
    const int turns,
    const float x,
    const float z,
    const float heading,
    float (&outX)[kMaxSymmetryCopies],
    float (&outZ)[kMaxSymmetryCopies],
    float (&outHeading)[kMaxSymmetryCopies]
  )
  {
    // The heading carried through the symmetry: the copies of a point one unit ahead.
    float aheadX[kMaxSymmetryCopies];
    float aheadZ[kMaxSymmetryCopies];
    const int copies = HeightBrushCentres(width, height, x, z, symmetry, turns, outX, outZ);
    (void)HeightBrushCentres(
      width, height, x + std::sin(heading), z + std::cos(heading), symmetry, turns, aheadX, aheadZ
    );
    for (int c = 0; c < copies; ++c) {
      outHeading[c] = std::atan2(aheadX[c] - outX[c], aheadZ[c] - outZ[c]);
    }
    return copies;
  }
} // namespace faf::editor
