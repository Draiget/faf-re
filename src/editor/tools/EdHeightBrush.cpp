#include "editor/tools/EdHeightBrush.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    // Raise and Lower at full strength, in game units a second; Noise's amplitude likewise.
    constexpr float kRaiseUnitsPerSecond = 30.0f;
    constexpr float kNoiseUnitsPerSecond = 15.0f;
    // Smooth and Flatten at full strength close this share of the gap each second (capped at all of it).
    constexpr float kBlendPerSecond = 8.0f;
    constexpr float kWordsPerUnit = 128.0f;

    [[nodiscard]] bool NeedsSquare(const Symmetry symmetry)
    {
      return symmetry == Symmetry::DiagonalBack || symmetry == Symmetry::DiagonalForward ||
             symmetry == Symmetry::BothDiagonals || symmetry == Symmetry::QuarterTurns;
    }

    [[nodiscard]] Symmetry Effective(const Symmetry symmetry, const int width, const int height)
    {
      if (symmetry == Symmetry::NWay || (NeedsSquare(symmetry) && width != height)) {
        return Symmetry::None;
      }
      return symmetry;
    }

    /** The copies of a point under `symmetry`, for samples (T int) and for the brush's centre (T float). */
    template <typename T>
    int Copies(const Symmetry symmetry, const T w, const T h, const T x, const T z, T (&outX)[4], T (&outZ)[4])
    {
      int n = 0;
      const auto add = [&](const T cx, const T cz) {
        outX[n] = cx;
        outZ[n] = cz;
        ++n;
      };
      add(x, z);
      switch (symmetry) {
      case Symmetry::LeftRight:
        add(w - x, z);
        break;
      case Symmetry::TopBottom:
        add(x, h - z);
        break;
      case Symmetry::DiagonalBack:
        add(z, x);
        break;
      case Symmetry::DiagonalForward:
        add(w - z, w - x);
        break;
      case Symmetry::HalfTurn:
        add(w - x, h - z);
        break;
      case Symmetry::BothAxes:
        add(w - x, z);
        add(x, h - z);
        add(w - x, h - z);
        break;
      case Symmetry::BothDiagonals:
        add(z, x);
        add(w - z, w - x);
        add(w - x, w - z);
        break;
      case Symmetry::QuarterTurns:
        add(w - z, x);
        add(w - x, w - z);
        add(z, w - x);
        break;
      default:
        break;
      }
      return n;
    }

    [[nodiscard]] float Weight(const float distance, const HeightBrush& brush)
    {
      const float t = distance / brush.radius;
      if (t >= 1.0f) {
        return 0.0f;
      }
      const float inner = 1.0f - std::clamp(brush.falloff, 0.0f, 1.0f);
      if (t <= inner) {
        return 1.0f;
      }
      const float u = (t - inner) / (1.0f - inner);
      return 1.0f - u * u * (3.0f - 2.0f * u);
    }

    /** A fixed value in [-1, 1] per sample, so Noise gives every member of a group the same change. */
    [[nodiscard]] float SampleNoise(const int x, const int z)
    {
      std::uint32_t v = static_cast<std::uint32_t>(x) * 0x8DA6B343u ^ static_cast<std::uint32_t>(z) * 0xD8163841u;
      v ^= v >> 13;
      v *= 0x5BD1E995u;
      v ^= v >> 15;
      return static_cast<float>(v & 0xFFFFu) / 32767.5f - 1.0f;
    }

    [[nodiscard]] bool Contains(const SampleRect& rect, const int x, const int z)
    {
      return x >= rect.x0 && x <= rect.x1 && z >= rect.z0 && z <= rect.z1;
    }
  } // namespace

  int SymmetricSamples(const Symmetry symmetry, const int width, const int height, const int x, const int z, int (&outX)[4],
                       int (&outZ)[4])
  {
    return Copies<int>(Effective(symmetry, width, height), width - 1, height - 1, x, z, outX, outZ);
  }

  std::vector<SampleRect> ApplyHeightBrush(std::uint16_t* const heights, const int width, const int height, const float x,
                                           const float z, const HeightBrush& brush, const float seconds)
  {
    std::vector<SampleRect> rects;
    if (heights == nullptr || width < 2 || height < 2 || brush.radius <= 0.0f || seconds <= 0.0f) {
      return rects;
    }
    const Symmetry symmetry = Effective(brush.symmetry, width, height);

    // The brush's copies and the rectangle each one covers.
    float centreX[4];
    float centreZ[4];
    const int centres = Copies<float>(symmetry, static_cast<float>(width - 1), static_cast<float>(height - 1), x, z, centreX, centreZ);
    for (int i = 0; i < centres; ++i) {
      SampleRect rect{
        std::max(0, static_cast<int>(std::floor(centreX[i] - brush.radius))),
        std::max(0, static_cast<int>(std::floor(centreZ[i] - brush.radius))),
        std::min(width - 1, static_cast<int>(std::ceil(centreX[i] + brush.radius))),
        std::min(height - 1, static_cast<int>(std::ceil(centreZ[i] + brush.radius))),
      };
      if (rect.x0 <= rect.x1 && rect.z0 <= rect.z1) {
        rects.push_back(rect);
      }
    }

    // Smooth reads its neighbours as they were before this step, from a copy of each rectangle plus one sample.
    struct Snapshot
    {
      SampleRect area;
      std::vector<std::uint16_t> words;
      [[nodiscard]] float At(const int sx, const int sz) const
      {
        const int cx = std::clamp(sx, area.x0, area.x1);
        const int cz = std::clamp(sz, area.z0, area.z1);
        return words[static_cast<std::size_t>((cz - area.z0) * (area.x1 - area.x0 + 1) + (cx - area.x0))];
      }
    };
    std::vector<Snapshot> snapshots;
    snapshots.reserve(rects.size());
    for (const SampleRect& rect : rects) {
      Snapshot snapshot;
      snapshot.area = {std::max(0, rect.x0 - 1), std::max(0, rect.z0 - 1), std::min(width - 1, rect.x1 + 1), std::min(height - 1, rect.z1 + 1)};
      for (int sz = snapshot.area.z0; sz <= snapshot.area.z1; ++sz) {
        const std::uint16_t* const row = heights + static_cast<std::size_t>(sz) * static_cast<std::size_t>(width);
        snapshot.words.insert(snapshot.words.end(), row + snapshot.area.x0, row + snapshot.area.x1 + 1);
      }
      snapshots.push_back(std::move(snapshot));
    }

    const float strength = std::clamp(brush.strength, 0.0f, 1.0f);
    const float blend = std::min(1.0f, strength * kBlendPerSecond * seconds);
    for (std::size_t r = 0; r < rects.size(); ++r) {
      const SampleRect& rect = rects[r];
      const Snapshot& snapshot = snapshots[r];
      for (int sz = rect.z0; sz <= rect.z1; ++sz) {
        for (int sx = rect.x0; sx <= rect.x1; ++sx) {
          // Each group once: from its first member, and from the first rectangle that holds it.
          int memberX[4];
          int memberZ[4];
          const int members = Copies<int>(symmetry, width - 1, height - 1, sx, sz, memberX, memberZ);
          bool first = true;
          for (int m = 1; m < members && first; ++m) {
            first = memberZ[m] > sz || (memberZ[m] == sz && memberX[m] >= sx);
          }
          if (!first) {
            continue;
          }
          bool earlier = false;
          for (std::size_t e = 0; e < r && !earlier; ++e) {
            earlier = Contains(rects[e], sx, sz);
          }
          if (earlier) {
            continue;
          }

          float weight = 0.0f;
          for (int c = 0; c < centres; ++c) {
            weight = std::max(weight, Weight(std::hypot(static_cast<float>(sx) - centreX[c], static_cast<float>(sz) - centreZ[c]), brush));
          }
          if (weight <= 0.0f) {
            continue;
          }

          const float current = snapshot.At(sx, sz);
          float next = current;
          switch (brush.mode) {
          case HeightBrushMode::Raise:
            next = current + weight * strength * kRaiseUnitsPerSecond * kWordsPerUnit * seconds;
            break;
          case HeightBrushMode::Lower:
            next = current - weight * strength * kRaiseUnitsPerSecond * kWordsPerUnit * seconds;
            break;
          case HeightBrushMode::Smooth: {
            float sum = 0.0f;
            for (int dz = -1; dz <= 1; ++dz) {
              for (int dx = -1; dx <= 1; ++dx) {
                sum += snapshot.At(sx + dx, sz + dz);
              }
            }
            next = current + (sum / 9.0f - current) * blend * weight;
            break;
          }
          case HeightBrushMode::Flatten:
            next = current + (brush.flattenTo - current) * blend * weight;
            break;
          case HeightBrushMode::Noise:
            next = current + SampleNoise(sx, sz) * weight * strength * kNoiseUnitsPerSecond * kWordsPerUnit * seconds;
            break;
          }
          const auto word = static_cast<std::uint16_t>(std::lround(std::clamp(next, 0.0f, 65535.0f)));
          for (int m = 0; m < members; ++m) {
            heights[static_cast<std::size_t>(memberZ[m]) * static_cast<std::size_t>(width) + static_cast<std::size_t>(memberX[m])] = word;
          }
        }
      }
    }
    return rects;
  }
} // namespace faf::editor
