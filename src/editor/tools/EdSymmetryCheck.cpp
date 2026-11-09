#include "editor/tools/EdSymmetryCheck.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

namespace faf::editor
{

  SymmetryReport CheckSymmetry(const std::uint16_t* const heights, const int width, const int height, const Symmetry requested, const int turns,
                               const int turnTolerance)
  {
    SymmetryReport report;
    const Symmetry symmetry = EffectiveSymmetry(requested, width, height);
    if (heights == nullptr || width < 2 || height < 2 || symmetry == Symmetry::None) {
      return report;
    }
    const int blocksX = (width + kSymmetryBlock - 1) / kSymmetryBlock;
    const int blocksZ = (height + kSymmetryBlock - 1) / kSymmetryBlock;
    std::vector<std::uint8_t> marked(static_cast<std::size_t>(blocksX) * static_cast<std::size_t>(blocksZ), 0);
    const auto mark = [&](const int x, const int z) {
      ++report.differing;
      marked[static_cast<std::size_t>(z / kSymmetryBlock) * static_cast<std::size_t>(blocksX) + static_cast<std::size_t>(x / kSymmetryBlock)] = 1;
    };
    const auto at = [&](const int x, const int z) {
      return static_cast<int>(heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)]);
    };

    if (symmetry == Symmetry::NWay) {
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          double source = 0.0;
          if (TurnSector(width, height, turns, x, z) == 0 || !TurnedHeight(heights, width, height, turns, x, z, source)) {
            continue;
          }
          ++report.checked;
          const int difference = static_cast<int>(std::lround(std::fabs(source - at(x, z))));
          report.largest = std::max(report.largest, difference);
          if (difference > turnTolerance) {
            mark(x, z);
          }
        }
      }
    } else {
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          int copyX[kMaxSymmetryCopies];
          int copyZ[kMaxSymmetryCopies];
          const int copies = SymmetricSamples(symmetry, turns, width, height, x, z, copyX, copyZ);
          ++report.checked;
          int largest = 0;
          for (int c = 1; c < copies; ++c) {
            largest = std::max(largest, std::abs(at(copyX[c], copyZ[c]) - at(x, z)));
          }
          report.largest = std::max(report.largest, largest);
          if (largest > 0) {
            mark(x, z);
          }
        }
      }
    }

    for (int bz = 0; bz < blocksZ; ++bz) {
      for (int bx = 0; bx < blocksX; ++bx) {
        if (marked[static_cast<std::size_t>(bz) * static_cast<std::size_t>(blocksX) + static_cast<std::size_t>(bx)] != 0) {
          report.blocks.push_back({bx * kSymmetryBlock, bz * kSymmetryBlock, std::min(width - 1, (bx + 1) * kSymmetryBlock),
                                   std::min(height - 1, (bz + 1) * kSymmetryBlock)});
        }
      }
    }
    return report;
  }

  SampleRect MakeSymmetric(std::uint16_t* const heights, const int width, const int height, const Symmetry requested, const int turns)
  {
    const Symmetry symmetry = EffectiveSymmetry(requested, width, height);
    if (heights == nullptr || width < 2 || height < 2 || symmetry == Symmetry::None) {
      return {};
    }
    if (symmetry == Symmetry::NWay) {
      // TurnedHeight reads only the first sector, which this doesn't write.
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          double source = 0.0;
          if (TurnSector(width, height, turns, x, z) != 0 && TurnedHeight(heights, width, height, turns, x, z, source)) {
            heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)] =
              static_cast<std::uint16_t>(std::lround(std::clamp(source, 0.0, 65535.0)));
          }
        }
      }
    } else {
      // Row by row from the top: a group's first member comes first, so it still holds its own height
      // when its group is written.
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          int copyX[kMaxSymmetryCopies];
          int copyZ[kMaxSymmetryCopies];
          const int copies = SymmetricSamples(symmetry, turns, width, height, x, z, copyX, copyZ);
          bool first = true;
          for (int c = 1; c < copies && first; ++c) {
            first = copyZ[c] > z || (copyZ[c] == z && copyX[c] >= x);
          }
          if (!first) {
            continue;
          }
          const std::uint16_t word = heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
          for (int c = 1; c < copies; ++c) {
            heights[static_cast<std::size_t>(copyZ[c]) * static_cast<std::size_t>(width) + static_cast<std::size_t>(copyX[c])] = word;
          }
        }
      }
    }
    return {0, 0, width - 1, height - 1};
  }
} // namespace faf::editor
