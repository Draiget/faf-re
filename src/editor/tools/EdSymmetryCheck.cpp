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

  DetectedSymmetry DetectSymmetry(const std::uint16_t* heights, const int width, const int height)
  {
    DetectedSymmetry best;
    if (heights == nullptr || width < 8 || height < 8) {
      return best;
    }
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    const auto [low, high] = std::minmax_element(heights, heights + count);
    constexpr int kFlat = 2 * 128;      // 2 game units
    constexpr int kTolerance = 64;      // half a game unit
    constexpr float kNeeded = 0.97f;
    if (*high - *low < kFlat) {
      return best;
    }
    struct Candidate
    {
      Symmetry symmetry;
      int turns;
      int copies;
    };
    static constexpr Candidate kCandidates[] = {
      {Symmetry::LeftRight, 0, 2},    {Symmetry::TopBottom, 0, 2},  {Symmetry::DiagonalBack, 0, 2}, {Symmetry::DiagonalForward, 0, 2},
      {Symmetry::HalfTurn, 0, 2},     {Symmetry::BothAxes, 0, 4},   {Symmetry::BothDiagonals, 0, 4}, {Symmetry::QuarterTurns, 0, 4},
      {Symmetry::NWay, 3, 3},         {Symmetry::NWay, 5, 5},       {Symmetry::NWay, 6, 6},         {Symmetry::NWay, 8, 8},
    };
    // About 128 x 128 points.
    const int step = std::max(1, std::min(width, height) / 128);
    int bestCopies = 1;
    for (const Candidate& candidate : kCandidates) {
      if (EffectiveSymmetry(candidate.symmetry, width, height) != candidate.symmetry) {
        continue; // a mode for square maps on a map that isn't
      }
      int compared = 0;
      int matched = 0;
      for (int z = 0; z < height; z += step) {
        for (int x = 0; x < width; x += step) {
          float copyX[kMaxSymmetryCopies], copyZ[kMaxSymmetryCopies];
          const int copies = HeightBrushCentres(width, height, static_cast<float>(x), static_cast<float>(z), candidate.symmetry,
                                                candidate.turns, copyX, copyZ);
          const int here = heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
          bool any = false;
          bool same = true;
          for (int c = 1; c < copies; ++c) {
            const int cx = static_cast<int>(std::lround(copyX[c]));
            const int cz = static_cast<int>(std::lround(copyZ[c]));
            if (cx < 0 || cz < 0 || cx >= width || cz >= height) {
              continue; // a turned point off the map
            }
            any = true;
            const int there = heights[static_cast<std::size_t>(cz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(cx)];
            if (std::abs(there - here) > kTolerance) {
              same = false;
              break;
            }
          }
          if (any) {
            ++compared;
            matched += same ? 1 : 0;
          }
        }
      }
      if (compared == 0) {
        continue;
      }
      const float share = static_cast<float>(matched) / static_cast<float>(compared);
      if (share >= kNeeded && (candidate.copies > bestCopies || (candidate.copies == bestCopies && share > best.matched))) {
        best = {candidate.symmetry, candidate.turns, share};
        bestCopies = candidate.copies;
      }
    }
    return best;
  }
} // namespace faf::editor
