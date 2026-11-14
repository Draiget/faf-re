#include "editor/tools/EdSymmetryCheck.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

namespace faf::editor
{

  SymmetryReport CheckSymmetry(
    const std::uint16_t* const heights,
    const int width,
    const int height,
    const Symmetry requested,
    const int turns,
    const int turnTolerance
  )
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
      marked
        [static_cast<std::size_t>(z / kSymmetryBlock) * static_cast<std::size_t>(blocksX) +
         static_cast<std::size_t>(x / kSymmetryBlock)] = 1;
    };
    const auto at = [&](const int x, const int z) {
      return static_cast<int>(
        heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)]
      );
    };

    if (symmetry == Symmetry::NWay) {
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          double source = 0.0;
          if (
            TurnSector(width, height, turns, x, z) == 0 || !TurnedHeight(heights, width, height, turns, x, z, source)
          ) {
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
        if (
          marked[static_cast<std::size_t>(bz) * static_cast<std::size_t>(blocksX) + static_cast<std::size_t>(bx)] != 0
        ) {
          report.blocks.push_back(
            {bx * kSymmetryBlock,
             bz * kSymmetryBlock,
             std::min(width - 1, (bx + 1) * kSymmetryBlock),
             std::min(height - 1, (bz + 1) * kSymmetryBlock)}
          );
        }
      }
    }
    return report;
  }

  SampleRect MakeSymmetric(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const Symmetry requested,
    const int turns
  )
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
          if (
            TurnSector(width, height, turns, x, z) != 0 && TurnedHeight(heights, width, height, turns, x, z, source)
          ) {
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
          const std::uint16_t word =
            heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
          for (int c = 1; c < copies; ++c) {
            heights
              [static_cast<std::size_t>(copyZ[c]) * static_cast<std::size_t>(width) +
               static_cast<std::size_t>(copyX[c])] = word;
          }
        }
      }
    }
    return {0, 0, width - 1, height - 1};
  }

  int SymmetryImages(
    const Symmetry symmetry,
    const int turns,
    const float cx,
    const float cz,
    const float x,
    const float z,
    float (&outX)[kMaxSymmetryCopies],
    float (&outZ)[kMaxSymmetryCopies]
  )
  {
    int n = 0;
    const auto add = [&](const float px, const float pz) {
      outX[n] = px;
      outZ[n] = pz;
      ++n;
    };
    const float dx = x - cx;
    const float dz = z - cz;
    add(x, z);
    switch (symmetry) {
    case Symmetry::LeftRight:
      add(cx - dx, z);
      break;
    case Symmetry::TopBottom:
      add(x, cz - dz);
      break;
    case Symmetry::DiagonalBack:
      add(cx + dz, cz + dx);
      break;
    case Symmetry::DiagonalForward:
      add(cx - dz, cz - dx);
      break;
    case Symmetry::HalfTurn:
      add(cx - dx, cz - dz);
      break;
    case Symmetry::BothAxes:
      add(cx - dx, z);
      add(x, cz - dz);
      add(cx - dx, cz - dz);
      break;
    case Symmetry::BothDiagonals:
      add(cx + dz, cz + dx);
      add(cx - dz, cz - dx);
      add(cx - dx, cz - dz);
      break;
    case Symmetry::QuarterTurns:
      add(cx - dz, cz + dx);
      add(cx - dx, cz - dz);
      add(cx + dz, cz - dx);
      break;
    case Symmetry::NWay: {
      const int count = std::clamp(turns, 2, kMaxSymmetryCopies);
      for (int k = 1; k < count; ++k) {
        const double angle = 6.283185307179586 * k / count;
        add(
          static_cast<float>(cx + dx * std::cos(angle) - dz * std::sin(angle)),
          static_cast<float>(cz + dx * std::sin(angle) + dz * std::cos(angle))
        );
      }
      break;
    }
    default:
      break;
    }
    return n;
  }

  namespace
  {
    /** What one mode about one centre showed. */
    struct Evidence
    {
      int startTested = 0;
      int startMatched = 0;
      int startMissed = 0;
      int resourceTested = 0;
      int resourceMatched = 0;
      int resourceMissed = 0;
      // How far the partners lie from the exact copies, for a centre a little off the middle.
      double sumX = 0.0;
      int countX = 0;
      double sumZ = 0.0;
      int countZ = 0;
      // The heights: points compared and matched (none when flat).
      int compared = 0;
      int matched = 0;
    };

    Evidence Gather(
      const std::uint16_t* const heights,
      const int width,
      const int height,
      const bool flat,
      const std::vector<SymmetryMarker>& markers,
      const Symmetry symmetry,
      const int turns,
      const float cx,
      const float cz
    )
    {
      Evidence ev;
      const float tolerance = std::max(3.5f, static_cast<float>(std::max(width, height) - 1) * 0.012f);
      const float tolerance2 = tolerance * tolerance;
      for (std::size_t i = 0; i < markers.size(); ++i) {
        const SymmetryMarker& p = markers[i];
        float ix[kMaxSymmetryCopies];
        float iz[kMaxSymmetryCopies];
        const int images = SymmetryImages(symmetry, turns, cx, cz, p.x, p.z, ix, iz);
        const bool start = p.kind == SymmetryMarker::Kind::Start;
        for (int k = 1; k < images; ++k) {
          std::size_t best = markers.size();
          float bestD = tolerance2 + 1.0f;
          for (std::size_t j = 0; j < markers.size(); ++j) {
            if (markers[j].kind != p.kind) {
              continue;
            }
            const float ddx = markers[j].x - ix[k];
            const float ddz = markers[j].z - iz[k];
            const float d = ddx * ddx + ddz * ddz;
            if (d < bestD) {
              best = j;
              bestD = d;
            }
          }
          ++(start ? ev.startTested : ev.resourceTested);
          if (best == markers.size() || bestD > tolerance2) {
            ++(start ? ev.startMissed : ev.resourceMissed);
          } else if (best != i) {
            ++(start ? ev.startMatched : ev.resourceMatched);
            // A copy that moves the point in x (or z) says where the axis lies in x (or z).
            if (std::abs(ix[k] - p.x) > 0.5f) {
              ev.sumX += markers[best].x - ix[k];
              ++ev.countX;
            }
            if (std::abs(iz[k] - p.z) > 0.5f) {
              ev.sumZ += markers[best].z - iz[k];
              ++ev.countZ;
            }
          }
          // (best == i: a marker on the axis maps onto itself: no evidence either way)
        }
      }
      if (!flat && heights != nullptr) {
        constexpr int kTolerance = 64;                               // half a game unit
        const int step = std::max(1, std::min(width, height) / 128); // about 128 x 128 points
        for (int z = 0; z < height; z += step) {
          for (int x = 0; x < width; x += step) {
            float ix[kMaxSymmetryCopies];
            float iz[kMaxSymmetryCopies];
            const int images =
              SymmetryImages(symmetry, turns, cx, cz, static_cast<float>(x), static_cast<float>(z), ix, iz);
            const int here =
              heights[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
            bool any = false;
            bool same = true;
            for (int c = 1; c < images; ++c) {
              const int qx = static_cast<int>(std::lround(ix[c]));
              const int qz = static_cast<int>(std::lround(iz[c]));
              if (qx < 0 || qz < 0 || qx >= width || qz >= height) {
                continue; // a turned point off the map
              }
              any = true;
              const int there =
                heights[static_cast<std::size_t>(qz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(qx)];
              if (std::abs(there - here) > kTolerance) {
                same = false;
                break;
              }
            }
            if (any) {
              ++ev.compared;
              ev.matched += same ? 1 : 0;
            }
          }
        }
      }
      return ev;
    }
  } // namespace

  DetectedSymmetry DetectSymmetry(
    const std::uint16_t* heights,
    const int width,
    const int height,
    const std::vector<SymmetryMarker>& markers
  )
  {
    DetectedSymmetry best;
    best.centreX = 0.5f * static_cast<float>(width - 1);
    best.centreZ = 0.5f * static_cast<float>(height - 1);
    if (heights == nullptr || width < 8 || height < 8) {
      return best;
    }
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    const auto [low, high] = std::minmax_element(heights, heights + count);
    constexpr int kFlat = 2 * 128; // 2 game units
    const bool flat = *high - *low < kFlat;
    int starts = 0;
    for (const SymmetryMarker& m : markers) {
      starts += m.kind == SymmetryMarker::Kind::Start ? 1 : 0;
    }
    struct Candidate
    {
      Symmetry symmetry;
      int turns;
      int copies;
      bool movableCentre; // the mirrors and the half turn: an axis a little off the middle is looked for
    };
    static constexpr Candidate kCandidates[] = {
      {Symmetry::LeftRight, 0, 2, true},
      {Symmetry::TopBottom, 0, 2, true},
      {Symmetry::DiagonalBack, 0, 2, false},
      {Symmetry::DiagonalForward, 0, 2, false},
      {Symmetry::HalfTurn, 0, 2, true},
      {Symmetry::BothAxes, 0, 4, true},
      {Symmetry::BothDiagonals, 0, 4, false},
      {Symmetry::QuarterTurns, 0, 4, false},
      {Symmetry::NWay, 3, 3, false},
      {Symmetry::NWay, 5, 5, false},
      {Symmetry::NWay, 6, 6, false},
      {Symmetry::NWay, 8, 8, false},
    };
    const float middleX = best.centreX;
    const float middleZ = best.centreZ;
    const float tolerance = std::max(3.5f, static_cast<float>(std::max(width, height) - 1) * 0.012f);
    // Whether a mode fits, and how well: markers that rule it out, markers that prove it, or the heights alone.
    const auto judge = [&](const Evidence& ev, float& share) {
      share = ev.compared > 0 ? static_cast<float>(ev.matched) / static_cast<float>(ev.compared) : 0.0f;
      const float resourceMissing =
        ev.resourceTested > 0 ? static_cast<float>(ev.resourceMissed) / static_cast<float>(ev.resourceTested) : 0.0f;
      const bool ruledOut = (starts >= 2 && ev.startMissed > 0) || (resourceMissing > 0.5f && ev.resourceTested >= 4);
      if (ruledOut) {
        return false;
      }
      // Heights that match their copies closely settle it (GPG's own maps place resources only roughly: SCMP_009's
      // half turn pairs every start but leaves a third of its resource markers without a partner).
      if (ev.compared > 0 && share >= 0.97f) {
        return true;
      }
      // Else the markers must prove it: every start paired, most resources too, and the heights not against it.
      const bool proven = starts >= 2 && ev.startMissed == 0 && ev.startMatched >= 1;
      return proven && resourceMissing <= 0.25f && (ev.compared == 0 || share >= 0.90f);
    };
    bool found = false;
    int bestMatches = 0;
    int bestCopies = 1;
    for (const Candidate& candidate : kCandidates) {
      if (EffectiveSymmetry(candidate.symmetry, width, height) != candidate.symmetry) {
        continue; // a mode for square maps on a map that isn't
      }
      float cx = middleX;
      float cz = middleZ;
      Evidence ev = Gather(heights, width, height, flat, markers, candidate.symmetry, candidate.turns, cx, cz);
      float share = 0.0f;
      bool ok = judge(ev, share);
      // An axis a little off the middle: measured from the partners, and tried.
      if (candidate.movableCentre && ev.startMatched + ev.resourceMatched >= 2) {
        float offX = ev.countX > 0 ? static_cast<float>(ev.sumX / ev.countX) * 0.5f : 0.0f;
        float offZ = ev.countZ > 0 ? static_cast<float>(ev.sumZ / ev.countZ) * 0.5f : 0.0f;
        if (std::abs(offX) >= 0.3f || std::abs(offZ) >= 0.3f) {
          const float limit = tolerance * 3.0f;
          offX = std::clamp(offX, -limit, limit);
          offZ = std::clamp(offZ, -limit, limit);
          const Evidence moved = Gather(
            heights, width, height, flat, markers, candidate.symmetry, candidate.turns, middleX + offX, middleZ + offZ
          );
          float movedShare = 0.0f;
          if (
            judge(moved, movedShare) &&
            (!ok || moved.startMissed + moved.resourceMissed <= ev.startMissed + ev.resourceMissed)
          ) {
            ev = moved;
            share = movedShare;
            ok = true;
            cx = middleX + offX;
            cz = middleZ + offZ;
          }
        }
      }
      if (!ok) {
        continue;
      }
      const int matches = ev.startMatched + ev.resourceMatched;
      bool better = !found;
      if (found) {
        if (matches != bestMatches) {
          better = matches > bestMatches;
        } else if (candidate.copies != bestCopies) {
          // Flat ground can't confirm the extra copies of a larger group; heights that match them do.
          better = flat ? candidate.copies < bestCopies : candidate.copies > bestCopies;
        } else {
          better = share > best.matched;
        }
      }
      if (better) {
        found = true;
        bestMatches = matches;
        bestCopies = candidate.copies;
        best.symmetry = candidate.symmetry;
        best.turns = candidate.turns;
        best.matched = share;
        best.centreX = cx;
        best.centreZ = cz;
        best.startsMatched = ev.startMatched;
        best.resourcesMatched = ev.resourceMatched;
      }
    }
    return best;
  }
} // namespace faf::editor
