#include "editor/tools/EdHeightBrush.h"

#include <algorithm>
#include <cmath>
#include <type_traits>
#include <utility>

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
    constexpr double kTwoPi = 6.283185307179586;
    // N-way turns: copies are written this many samples past the brush's edge, since the heights a copy
    // reads between samples (and their own turned-back samples) reach that far.
    constexpr float kTurnRim = 2.0f;

    [[nodiscard]] bool NeedsSquare(const Symmetry symmetry)
    {
      return symmetry == Symmetry::DiagonalBack || symmetry == Symmetry::DiagonalForward || symmetry == Symmetry::BothDiagonals ||
             symmetry == Symmetry::QuarterTurns || symmetry == Symmetry::NWay;
    }

    [[nodiscard]] int Turns(const int turns)
    {
      return std::clamp(turns, 2, kMaxSymmetryCopies);
    }

    /** The copies of a point under `symmetry`, for samples (T int) and for the brush's centre (T float). */
    template <typename T>
    int Copies(const Symmetry symmetry, const int turns, const T w, const T h, const T x, const T z, T (&outX)[kMaxSymmetryCopies],
               T (&outZ)[kMaxSymmetryCopies])
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
      case Symmetry::NWay: {
        const double cx = static_cast<double>(w) * 0.5;
        const double cz = static_cast<double>(h) * 0.5;
        const double dx = static_cast<double>(x) - cx;
        const double dz = static_cast<double>(z) - cz;
        const int count = Turns(turns);
        for (int k = 1; k < count; ++k) {
          const double angle = kTwoPi * k / count;
          const double rx = cx + dx * std::cos(angle) - dz * std::sin(angle);
          const double rz = cz + dx * std::sin(angle) + dz * std::cos(angle);
          if constexpr (std::is_integral_v<T>) {
            add(static_cast<T>(std::lround(rx)), static_cast<T>(std::lround(rz)));
          } else {
            add(static_cast<T>(rx), static_cast<T>(rz));
          }
        }
        break;
      }
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

    /** The rectangle each centre's brush covers, clipped to the map; empty ones left out. */
    std::vector<SampleRect> RectsAround(const int width, const int height, const float (&centreX)[kMaxSymmetryCopies],
                                        const float (&centreZ)[kMaxSymmetryCopies], const int centres, const float radius)
    {
      std::vector<SampleRect> rects;
      for (int i = 0; i < centres; ++i) {
        SampleRect rect{
          std::max(0, static_cast<int>(std::floor(centreX[i] - radius))),
          std::max(0, static_cast<int>(std::floor(centreZ[i] - radius))),
          std::min(width - 1, static_cast<int>(std::ceil(centreX[i] + radius))),
          std::min(height - 1, static_cast<int>(std::ceil(centreZ[i] + radius))),
        };
        if (rect.x0 <= rect.x1 && rect.z0 <= rect.z1) {
          rects.push_back(rect);
        }
      }
      return rects;
    }

    /** A copy of a rectangle of heights plus one sample around it, read as they were before a step. */
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

    std::vector<Snapshot> TakeSnapshots(const std::uint16_t* const heights, const int width, const int height,
                                        const std::vector<SampleRect>& rects)
    {
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
      return snapshots;
    }

    /** The stamp's value (0..1) at offset (dx, dz) from the brush's centre, over the brush's square; 0 outside. */
    [[nodiscard]] float StampAt(const HeightStamp& stamp, const float dx, const float dz, const float radius)
    {
      if (stamp.width < 2 || stamp.height < 2 || radius <= 0.0f) {
        return 0.0f;
      }
      const float u = (dx / radius * 0.5f + 0.5f) * static_cast<float>(stamp.width - 1);
      const float v = (dz / radius * 0.5f + 0.5f) * static_cast<float>(stamp.height - 1);
      if (u < 0.0f || v < 0.0f || u > static_cast<float>(stamp.width - 1) || v > static_cast<float>(stamp.height - 1)) {
        return 0.0f;
      }
      const int x0 = std::min(stamp.width - 2, static_cast<int>(u));
      const int z0 = std::min(stamp.height - 2, static_cast<int>(v));
      const float fx = u - static_cast<float>(x0);
      const float fz = v - static_cast<float>(z0);
      const auto at = [&](const int x, const int z) {
        return static_cast<float>(stamp.words[static_cast<std::size_t>(z) * static_cast<std::size_t>(stamp.width) + static_cast<std::size_t>(x)]);
      };
      const float value = (at(x0, z0) * (1.0f - fx) + at(x0 + 1, z0) * fx) * (1.0f - fz) + (at(x0, z0 + 1) * (1.0f - fx) + at(x0 + 1, z0 + 1) * fx) * fz;
      return value / 65535.0f;
    }

    /** Whether the limits let the brush change this sample (read before the step). */
    [[nodiscard]] bool WithinLimits(const Snapshot& snapshot, const int sx, const int sz, const HeightBrush& brush)
    {
      const float current = snapshot.At(sx, sz);
      if (brush.limitHeight && (current < brush.limitLow || current > brush.limitHigh)) {
        return false;
      }
      if (brush.limitSlope) {
        // Rise over run in game units, from the neighbours on each side (one sample is one unit).
        const float dx = (snapshot.At(sx + 1, sz) - snapshot.At(sx - 1, sz)) * 0.5f / kWordsPerUnit;
        const float dz = (snapshot.At(sx, sz + 1) - snapshot.At(sx, sz - 1)) * 0.5f / kWordsPerUnit;
        if (std::hypot(dx, dz) > brush.limitMaxSlope) {
          return false;
        }
      }
      return true;
    }

    /** The brush's new height for one sample, from the heights before the step; (dx, dz) from its nearest copy's centre. */
    [[nodiscard]] float BrushedHeight(const Snapshot& snapshot, const int sx, const int sz, const float weight, const HeightBrush& brush,
                                      const float seconds, const float dx, const float dz)
    {
      const float strength = std::clamp(brush.strength, 0.0f, 1.0f);
      const float blend = std::min(1.0f, strength * kBlendPerSecond * seconds);
      const float current = snapshot.At(sx, sz);
      switch (brush.mode) {
      case HeightBrushMode::Raise:
        return current + weight * strength * kRaiseUnitsPerSecond * kWordsPerUnit * seconds;
      case HeightBrushMode::Lower:
        return current - weight * strength * kRaiseUnitsPerSecond * kWordsPerUnit * seconds;
      case HeightBrushMode::Smooth: {
        float sum = 0.0f;
        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            sum += snapshot.At(sx + dx, sz + dz);
          }
        }
        return current + (sum / 9.0f - current) * blend * weight;
      }
      case HeightBrushMode::Flatten:
        return current + (brush.flattenTo - current) * blend * weight;
      case HeightBrushMode::Noise:
        return current + SampleNoise(sx, sz) * weight * strength * kNoiseUnitsPerSecond * kWordsPerUnit * seconds;
      case HeightBrushMode::SetHeight:
        return current + (brush.setTo - current) * blend * weight;
      case HeightBrushMode::Terrace: {
        const float step = std::max(1.0f, brush.terraceStep);
        return current + (std::round(current / step) * step - current) * blend * weight;
      }
      case HeightBrushMode::Plane:
        if (!brush.planeSet) {
          return current;
        }
        return current + (static_cast<float>(brush.planeX * sx + brush.planeZ * sz + brush.planeC) - current) * blend * weight;
      case HeightBrushMode::Stamp:
        if (brush.stamp == nullptr) {
          return current;
        }
        return current + StampAt(*brush.stamp, dx, dz, brush.radius) * brush.stampHeight * strength * weight;
      }
      return current;
    }

    [[nodiscard]] std::uint16_t ToWord(const float value)
    {
      return static_cast<std::uint16_t>(std::lround(std::clamp(value, 0.0f, 65535.0f)));
    }

    [[nodiscard]] float StrongestWeight(const int sx, const int sz, const float (&centreX)[kMaxSymmetryCopies],
                                        const float (&centreZ)[kMaxSymmetryCopies], const int centres, const HeightBrush& brush,
                                        int* const strongest = nullptr)
    {
      float weight = 0.0f;
      float nearest = 0.0f;
      for (int c = 0; c < centres; ++c) {
        const float distance = std::hypot(static_cast<float>(sx) - centreX[c], static_cast<float>(sz) - centreZ[c]);
        const float w = Weight(distance, brush);
        if (strongest != nullptr && (c == 0 || distance < nearest)) {
          nearest = distance;
          *strongest = c;
        }
        weight = std::max(weight, w);
      }
      return weight;
    }

    /** True if the sample is within `reach` of a centre. */
    [[nodiscard]] bool NearACentre(const int sx, const int sz, const float (&centreX)[kMaxSymmetryCopies],
                                   const float (&centreZ)[kMaxSymmetryCopies], const int centres, const float reach)
    {
      for (int c = 0; c < centres; ++c) {
        if (std::hypot(static_cast<float>(sx) - centreX[c], static_cast<float>(sz) - centreZ[c]) < reach) {
          return true;
        }
      }
      return false;
    }

    /** True if no rectangle before `r` holds the sample (each sample is handled once). */
    [[nodiscard]] bool FirstRectHolding(const std::vector<SampleRect>& rects, const std::size_t r, const int sx, const int sz)
    {
      for (std::size_t e = 0; e < r; ++e) {
        if (Contains(rects[e], sx, sz)) {
          return false;
        }
      }
      return true;
    }

    /** N-way turns: see ApplyHeightBrush. */
    void ApplyTurned(std::uint16_t* const heights, const int width, const int height, const std::vector<SampleRect>& rects,
                     const float (&centreX)[kMaxSymmetryCopies], const float (&centreZ)[kMaxSymmetryCopies], const int centres,
                     const HeightBrush& brush, const float seconds)
    {
      // The first sector, painted with the brush from the heights before the step.
      const std::vector<Snapshot> snapshots = TakeSnapshots(heights, width, height, rects);
      for (std::size_t r = 0; r < rects.size(); ++r) {
        const SampleRect& rect = rects[r];
        for (int sz = rect.z0; sz <= rect.z1; ++sz) {
          for (int sx = rect.x0; sx <= rect.x1; ++sx) {
            if (TurnSector(width, height, brush.turns, sx, sz) != 0 || !FirstRectHolding(rects, r, sx, sz)) {
              continue;
            }
            int nearest = 0;
            const float weight = StrongestWeight(sx, sz, centreX, centreZ, centres, brush, &nearest);
            if (weight > 0.0f && WithinLimits(snapshots[r], sx, sz, brush)) {
              heights[static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx)] =
                ToWord(BrushedHeight(snapshots[r], sx, sz, weight, brush, seconds, static_cast<float>(sx) - centreX[nearest],
                                     static_cast<float>(sz) - centreZ[nearest]));
            }
          }
        }
      }

      // Every other sample the brush covers copies the first sector; TurnedHeight reads only the first
      // sector, which this pass doesn't write.
      for (std::size_t r = 0; r < rects.size(); ++r) {
        const SampleRect& rect = rects[r];
        for (int sz = rect.z0; sz <= rect.z1; ++sz) {
          for (int sx = rect.x0; sx <= rect.x1; ++sx) {
            double value = 0.0;
            if (TurnSector(width, height, brush.turns, sx, sz) == 0 || !FirstRectHolding(rects, r, sx, sz) ||
                !NearACentre(sx, sz, centreX, centreZ, centres, brush.radius + kTurnRim) ||
                !TurnedHeight(heights, width, height, brush.turns, sx, sz, value)) {
              continue;
            }
            heights[static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx)] =
              ToWord(static_cast<float>(value));
          }
        }
      }
    }
  } // namespace

  bool PlaneThrough(const double (&x)[3], const double (&h)[3], const double (&z)[3], double& planeX, double& planeZ, double& planeC)
  {
    // h = a x + b z + c through the three points: Cramer's rule on the two differences.
    const double x1 = x[1] - x[0];
    const double z1 = z[1] - z[0];
    const double h1 = h[1] - h[0];
    const double x2 = x[2] - x[0];
    const double z2 = z[2] - z[0];
    const double h2 = h[2] - h[0];
    const double determinant = x1 * z2 - x2 * z1;
    if (std::fabs(determinant) < 1e-6) {
      return false;
    }
    planeX = (h1 * z2 - h2 * z1) / determinant;
    planeZ = (x1 * h2 - x2 * h1) / determinant;
    planeC = h[0] - planeX * x[0] - planeZ * z[0];
    return true;
  }

  int TurnSector(const int width, const int height, const int turns, const int x, const int z)
  {
    const int count = Turns(turns);
    double angle = std::atan2(z - (height - 1) * 0.5, x - (width - 1) * 0.5);
    if (angle < 0.0) {
      angle += kTwoPi;
    }
    return std::min(count - 1, static_cast<int>(angle / (kTwoPi / count)));
  }

  bool TurnedHeight(const std::uint16_t* const heights, const int width, const int height, const int turns, const int x, const int z,
                    double& value)
  {
    const int count = Turns(turns);
    const double cx = (width - 1) * 0.5;
    const double cz = (height - 1) * 0.5;
    // A point turned back by the sector of sample (sx, sz).
    const auto turnBack = [&](const int sx, const int sz, const double px, const double pz, double& outX, double& outZ) {
      const double back = -kTwoPi * TurnSector(width, height, count, sx, sz) / count;
      outX = cx + (px - cx) * std::cos(back) - (pz - cz) * std::sin(back);
      outZ = cz + (px - cx) * std::sin(back) + (pz - cz) * std::cos(back);
    };
    double px = 0.0;
    double pz = 0.0;
    turnBack(x, z, x, z, px, pz);
    if (px < 0.0 || pz < 0.0 || px > width - 1 || pz > height - 1) {
      return false;
    }
    const int x0 = std::min(width - 2, static_cast<int>(px));
    const int z0 = std::min(height - 2, static_cast<int>(pz));
    const double fx = px - x0;
    const double fz = pz - z0;
    const auto at = [&](const int ax, const int az) {
      int sx = ax;
      int sz = az;
      if (TurnSector(width, height, count, ax, az) != 0) {
        // Outside the first sector: its own turned-back sample.
        double bx = 0.0;
        double bz = 0.0;
        turnBack(ax, az, ax, az, bx, bz);
        sx = std::clamp(static_cast<int>(std::lround(bx)), 0, width - 1);
        sz = std::clamp(static_cast<int>(std::lround(bz)), 0, height - 1);
      }
      return static_cast<double>(heights[static_cast<std::size_t>(sz) * static_cast<std::size_t>(width) + static_cast<std::size_t>(sx)]);
    };
    value = (at(x0, z0) * (1.0 - fx) + at(x0 + 1, z0) * fx) * (1.0 - fz) + (at(x0, z0 + 1) * (1.0 - fx) + at(x0 + 1, z0 + 1) * fx) * fz;
    return true;
  }

  Symmetry EffectiveSymmetry(const Symmetry symmetry, const int width, const int height)
  {
    return NeedsSquare(symmetry) && width != height ? Symmetry::None : symmetry;
  }

  int SymmetricSamples(const Symmetry symmetry, const int turns, const int width, const int height, const int x, const int z,
                       int (&outX)[kMaxSymmetryCopies], int (&outZ)[kMaxSymmetryCopies])
  {
    return Copies<int>(EffectiveSymmetry(symmetry, width, height), turns, width - 1, height - 1, x, z, outX, outZ);
  }

  int HeightBrushCentres(const int width, const int height, const float x, const float z, const Symmetry symmetry, const int turns,
                         float (&outX)[kMaxSymmetryCopies], float (&outZ)[kMaxSymmetryCopies])
  {
    return Copies<float>(EffectiveSymmetry(symmetry, width, height), turns, static_cast<float>(width - 1), static_cast<float>(height - 1), x,
                         z, outX, outZ);
  }

  std::vector<SampleRect> HeightBrushRects(const int width, const int height, const float x, const float z, const HeightBrush& brush)
  {
    if (width < 2 || height < 2 || brush.radius <= 0.0f) {
      return {};
    }
    float centreX[kMaxSymmetryCopies];
    float centreZ[kMaxSymmetryCopies];
    const int centres = HeightBrushCentres(width, height, x, z, brush.symmetry, brush.turns, centreX, centreZ);
    const bool turned = EffectiveSymmetry(brush.symmetry, width, height) == Symmetry::NWay;
    return RectsAround(width, height, centreX, centreZ, centres, brush.radius + (turned ? kTurnRim : 0.0f));
  }

  std::vector<SampleRect> ApplyHeightBrush(std::uint16_t* const heights, const int width, const int height, const float x,
                                           const float z, const HeightBrush& brush, const float seconds)
  {
    if (heights == nullptr || width < 2 || height < 2 || brush.radius <= 0.0f || seconds <= 0.0f) {
      return {};
    }
    const Symmetry symmetry = EffectiveSymmetry(brush.symmetry, width, height);

    // The brush's copies and the rectangle each one covers.
    float centreX[kMaxSymmetryCopies];
    float centreZ[kMaxSymmetryCopies];
    const int centres = HeightBrushCentres(width, height, x, z, symmetry, brush.turns, centreX, centreZ);
    const std::vector<SampleRect> rects =
      RectsAround(width, height, centreX, centreZ, centres, brush.radius + (symmetry == Symmetry::NWay ? kTurnRim : 0.0f));
    if (symmetry == Symmetry::NWay) {
      ApplyTurned(heights, width, height, rects, centreX, centreZ, centres, brush, seconds);
      return rects;
    }

    // Smooth reads its neighbours as they were before this step.
    const std::vector<Snapshot> snapshots = TakeSnapshots(heights, width, height, rects);
    for (std::size_t r = 0; r < rects.size(); ++r) {
      const SampleRect& rect = rects[r];
      for (int sz = rect.z0; sz <= rect.z1; ++sz) {
        for (int sx = rect.x0; sx <= rect.x1; ++sx) {
          // Each group once: from its first member, and from the first rectangle that holds it.
          int memberX[kMaxSymmetryCopies];
          int memberZ[kMaxSymmetryCopies];
          const int members = Copies<int>(symmetry, brush.turns, width - 1, height - 1, sx, sz, memberX, memberZ);
          bool first = true;
          for (int m = 1; m < members && first; ++m) {
            first = memberZ[m] > sz || (memberZ[m] == sz && memberX[m] >= sx);
          }
          if (!first || !FirstRectHolding(rects, r, sx, sz)) {
            continue;
          }
          int nearest = 0;
          const float weight = StrongestWeight(sx, sz, centreX, centreZ, centres, brush, &nearest);
          if (weight <= 0.0f || !WithinLimits(snapshots[r], sx, sz, brush)) {
            continue;
          }
          const std::uint16_t word = ToWord(BrushedHeight(snapshots[r], sx, sz, weight, brush, seconds, static_cast<float>(sx) - centreX[nearest],
                                                          static_cast<float>(sz) - centreZ[nearest]));
          for (int m = 0; m < members; ++m) {
            heights[static_cast<std::size_t>(memberZ[m]) * static_cast<std::size_t>(width) + static_cast<std::size_t>(memberX[m])] = word;
          }
        }
      }
    }
    return rects;
  }
} // namespace faf::editor
