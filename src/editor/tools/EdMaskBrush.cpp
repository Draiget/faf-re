#include "editor/tools/EdMaskBrush.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    // Paint and Erase at full strength move a weight this far a second; Smooth closes this share of the gap.
    constexpr float kWeightPerSecond = 3.0f * 255.0f;
    constexpr float kBlendPerSecond = 8.0f;
    constexpr double kTwoPi = 6.283185307179586;
    // N-way turns: copies are written this many texels past the brush's edge.
    constexpr float kTurnRim = 2.0f;

    /** Height samples per mask texel. */
    [[nodiscard]] float SamplesPerTexel(const int maskWidth, const MaskTerrain& terrain)
    {
      return maskWidth > 0 && terrain.width > 1 ? static_cast<float>(terrain.width - 1) / static_cast<float>(maskWidth) : 1.0f;
    }

    [[nodiscard]] float Falloff(const float distance, const float radius, const float falloff)
    {
      const float t = distance / radius;
      if (t >= 1.0f) {
        return 0.0f;
      }
      const float inner = 1.0f - std::clamp(falloff, 0.0f, 1.0f);
      if (t <= inner) {
        return 1.0f;
      }
      const float u = (t - inner) / (1.0f - inner);
      return 1.0f - u * u * (3.0f - 2.0f * u);
    }

    /** A value in [0, 1) per texel, layer and brush step. */
    [[nodiscard]] float Dither(const int x, const int z, const int layer, const std::uint32_t step)
    {
      std::uint32_t v = static_cast<std::uint32_t>(x) * 0x9E3779B1u ^ static_cast<std::uint32_t>(z) * 0x85EBCA77u ^ static_cast<std::uint32_t>(layer) * 0xC2B2AE3Du ^
                        step * 0x27D4EB2Fu;
      v ^= v >> 15;
      v *= 0x2C1B3C6Du;
      v ^= v >> 12;
      return static_cast<float>(v & 0xFFFFu) / 65536.0f;
    }

    /** Ground height (words) and slope (rise over run) under texel (x, z). */
    void GroundAt(const MaskTerrain& terrain, const float perTexel, const int x, const int z, float& height, float& slope)
    {
      height = 0.0f;
      slope = 0.0f;
      if (terrain.heights == nullptr || terrain.width < 2) {
        return;
      }
      const int sx = std::clamp(static_cast<int>((static_cast<float>(x) + 0.5f) * perTexel), 0, terrain.width - 1);
      const int sz = std::clamp(static_cast<int>((static_cast<float>(z) + 0.5f) * perTexel), 0, terrain.height - 1);
      const auto at = [&](const int ax, const int az) {
        return static_cast<float>(terrain.heights[static_cast<std::size_t>(std::clamp(az, 0, terrain.height - 1)) * static_cast<std::size_t>(terrain.width) +
                                                  static_cast<std::size_t>(std::clamp(ax, 0, terrain.width - 1))]);
      };
      height = at(sx, sz);
      const float dx = (at(sx + 1, sz) - at(sx - 1, sz)) * 0.5f / 128.0f;
      const float dz = (at(sx, sz + 1) - at(sx, sz - 1)) * 0.5f / 128.0f;
      slope = std::hypot(dx, dz);
    }

    struct Snapshot
    {
      SampleRect area;
      std::vector<std::uint64_t> texels;
      [[nodiscard]] std::uint64_t At(const int x, const int z) const
      {
        const int cx = std::clamp(x, area.x0, area.x1);
        const int cz = std::clamp(z, area.z0, area.z1);
        return texels[static_cast<std::size_t>((cz - area.z0) * (area.x1 - area.x0 + 1) + (cx - area.x0))];
      }
    };

    /** The brush's centres in texels and its radius in texels. */
    struct Shape
    {
      float centreX[kMaxSymmetryCopies];
      float centreZ[kMaxSymmetryCopies];
      int centres = 0;
      float radius = 0.0f;
      Symmetry symmetry = Symmetry::None;
      std::vector<SampleRect> rects;
    };

    Shape ShapeOf(const int maskWidth, const int maskHeight, const MaskTerrain& terrain, const float x, const float z, const MaskBrush& brush)
    {
      Shape shape;
      const float perTexel = SamplesPerTexel(maskWidth, terrain);
      shape.symmetry = EffectiveSymmetry(brush.shape.symmetry, maskWidth, maskHeight);
      shape.radius = brush.shape.radius / perTexel;
      shape.centres = HeightBrushCentres(maskWidth, maskHeight, x / perTexel - 0.5f, z / perTexel - 0.5f, shape.symmetry, brush.shape.turns,
                                         shape.centreX, shape.centreZ);
      const float reach = shape.radius + (shape.symmetry == Symmetry::NWay ? kTurnRim : 0.0f);
      for (int i = 0; i < shape.centres; ++i) {
        SampleRect rect{
          std::max(0, static_cast<int>(std::floor(shape.centreX[i] - reach))),
          std::max(0, static_cast<int>(std::floor(shape.centreZ[i] - reach))),
          std::min(maskWidth - 1, static_cast<int>(std::ceil(shape.centreX[i] + reach))),
          std::min(maskHeight - 1, static_cast<int>(std::ceil(shape.centreZ[i] + reach))),
        };
        if (rect.x0 <= rect.x1 && rect.z0 <= rect.z1) {
          shape.rects.push_back(rect);
        }
      }
      return shape;
    }

    [[nodiscard]] bool FirstRectHolding(const std::vector<SampleRect>& rects, const std::size_t r, const int x, const int z)
    {
      for (std::size_t e = 0; e < r; ++e) {
        if (x >= rects[e].x0 && x <= rects[e].x1 && z >= rects[e].z0 && z <= rects[e].z1) {
          return false;
        }
      }
      return true;
    }

    [[nodiscard]] float WeightAt(const Shape& shape, const int x, const int z, const MaskBrush& brush, const float extra = 0.0f)
    {
      float weight = 0.0f;
      for (int c = 0; c < shape.centres; ++c) {
        const float distance = std::hypot(static_cast<float>(x) - shape.centreX[c], static_cast<float>(z) - shape.centreZ[c]);
        if (extra > 0.0f) {
          weight = std::max(weight, distance < shape.radius + extra ? 1.0f : 0.0f);
        } else {
          weight = std::max(weight, Falloff(distance, shape.radius, brush.shape.falloff));
        }
      }
      return weight;
    }

    /** The brush's new texel for (x, z), from the texels before the step. */
    [[nodiscard]] std::uint64_t Brushed(const Snapshot& snapshot, const int x, const int z, const float weight, const MaskBrush& brush,
                                        const float seconds)
    {
      const std::uint64_t texel = snapshot.At(x, z);
      const float strength = std::clamp(brush.shape.strength, 0.0f, 1.0f);
      const int layer = std::clamp(brush.layer, 0, 7);
      const float current = MaskByte(texel, layer);
      const float step = weight * strength * kWeightPerSecond * seconds;
      std::uint64_t out = texel;
      const auto settle = [&](const float value, const int which) {
        return static_cast<std::uint8_t>(std::clamp(std::floor(value + Dither(x, z, which, brush.step)), 0.0f, 255.0f));
      };
      switch (brush.mode) {
      case MaskBrushMode::Paint:
        out = WithMaskByte(out, layer, std::max(MaskByte(texel, layer), settle(current + step, layer)));
        if (brush.lowerAbove) {
          for (int above = layer + 1; above < 8; ++above) {
            const float value = MaskByte(texel, above);
            if (value > 0.0f) {
              out = WithMaskByte(out, above, std::min(MaskByte(texel, above), settle(value - step, above)));
            }
          }
        }
        break;
      case MaskBrushMode::Erase:
        out = WithMaskByte(out, layer, std::min(MaskByte(texel, layer), settle(current - step, layer)));
        break;
      case MaskBrushMode::Smooth: {
        float sum = 0.0f;
        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            sum += MaskByte(snapshot.At(x + dx, z + dz), layer);
          }
        }
        const float blend = std::min(1.0f, strength * kBlendPerSecond * seconds);
        out = WithMaskByte(out, layer, settle(current + (sum / 9.0f - current) * blend * weight, layer));
        break;
      }
      }
      return out;
    }

    [[nodiscard]] bool WithinLimits(const MaskTerrain& terrain, const float perTexel, const int x, const int z, const HeightBrush& shape)
    {
      if (!shape.limitHeight && !shape.limitSlope) {
        return true;
      }
      float height = 0.0f;
      float slope = 0.0f;
      GroundAt(terrain, perTexel, x, z, height, slope);
      if (shape.limitHeight && (height < shape.limitLow || height > shape.limitHigh)) {
        return false;
      }
      return !shape.limitSlope || slope <= shape.limitMaxSlope;
    }
  } // namespace

  std::vector<SampleRect> MaskBrushRects(const int maskWidth, const int maskHeight, const MaskTerrain& terrain, const float x, const float z,
                                         const MaskBrush& brush)
  {
    if (maskWidth < 2 || maskHeight < 2 || brush.shape.radius <= 0.0f) {
      return {};
    }
    return ShapeOf(maskWidth, maskHeight, terrain, x, z, brush).rects;
  }

  std::vector<SampleRect> ApplyMaskBrush(std::uint64_t* const texels, const int maskWidth, const int maskHeight, const MaskTerrain& terrain,
                                         const float x, const float z, const MaskBrush& brush, const float seconds)
  {
    if (texels == nullptr || maskWidth < 2 || maskHeight < 2 || brush.shape.radius <= 0.0f || seconds <= 0.0f) {
      return {};
    }
    const float perTexel = SamplesPerTexel(maskWidth, terrain);
    const Shape shape = ShapeOf(maskWidth, maskHeight, terrain, x, z, brush);
    std::vector<Snapshot> snapshots;
    for (const SampleRect& rect : shape.rects) {
      Snapshot snapshot;
      snapshot.area = {std::max(0, rect.x0 - 1), std::max(0, rect.z0 - 1), std::min(maskWidth - 1, rect.x1 + 1), std::min(maskHeight - 1, rect.z1 + 1)};
      for (int row = snapshot.area.z0; row <= snapshot.area.z1; ++row) {
        const std::uint64_t* const line = texels + static_cast<std::size_t>(row) * static_cast<std::size_t>(maskWidth);
        snapshot.texels.insert(snapshot.texels.end(), line + snapshot.area.x0, line + snapshot.area.x1 + 1);
      }
      snapshots.push_back(std::move(snapshot));
    }
    const auto index = [maskWidth](const int tx, const int tz) {
      return static_cast<std::size_t>(tz) * static_cast<std::size_t>(maskWidth) + static_cast<std::size_t>(tx);
    };

    if (shape.symmetry == Symmetry::NWay) {
      const int turns = std::clamp(brush.shape.turns, 2, kMaxSymmetryCopies);
      // The first sector from the brush, then every other texel near a copy from its nearest turned-back texel.
      for (std::size_t r = 0; r < shape.rects.size(); ++r) {
        const SampleRect& rect = shape.rects[r];
        for (int tz = rect.z0; tz <= rect.z1; ++tz) {
          for (int tx = rect.x0; tx <= rect.x1; ++tx) {
            if (TurnSector(maskWidth, maskHeight, turns, tx, tz) != 0 || !FirstRectHolding(shape.rects, r, tx, tz)) {
              continue;
            }
            const float weight = WeightAt(shape, tx, tz, brush);
            if (weight > 0.0f && WithinLimits(terrain, perTexel, tx, tz, brush.shape)) {
              texels[index(tx, tz)] = Brushed(snapshots[r], tx, tz, weight, brush, seconds);
            }
          }
        }
      }
      const double cx = (maskWidth - 1) * 0.5;
      const double cz = (maskHeight - 1) * 0.5;
      for (std::size_t r = 0; r < shape.rects.size(); ++r) {
        const SampleRect& rect = shape.rects[r];
        for (int tz = rect.z0; tz <= rect.z1; ++tz) {
          for (int tx = rect.x0; tx <= rect.x1; ++tx) {
            const int k = TurnSector(maskWidth, maskHeight, turns, tx, tz);
            if (k == 0 || !FirstRectHolding(shape.rects, r, tx, tz) || WeightAt(shape, tx, tz, brush, kTurnRim) <= 0.0f) {
              continue;
            }
            const double back = -kTwoPi * k / turns;
            const int sx = static_cast<int>(std::lround(cx + (tx - cx) * std::cos(back) - (tz - cz) * std::sin(back)));
            const int sz = static_cast<int>(std::lround(cz + (tx - cx) * std::sin(back) + (tz - cz) * std::cos(back)));
            // Only from the first sector (a rounded turned-back texel next to its edge can fall outside it).
            if (sx >= 0 && sz >= 0 && sx < maskWidth && sz < maskHeight && TurnSector(maskWidth, maskHeight, turns, sx, sz) == 0) {
              texels[index(tx, tz)] = texels[index(sx, sz)];
            }
          }
        }
      }
      return shape.rects;
    }

    for (std::size_t r = 0; r < shape.rects.size(); ++r) {
      const SampleRect& rect = shape.rects[r];
      for (int tz = rect.z0; tz <= rect.z1; ++tz) {
        for (int tx = rect.x0; tx <= rect.x1; ++tx) {
          int memberX[kMaxSymmetryCopies];
          int memberZ[kMaxSymmetryCopies];
          const int members = SymmetricSamples(shape.symmetry, brush.shape.turns, maskWidth, maskHeight, tx, tz, memberX, memberZ);
          bool first = true;
          for (int m = 1; m < members && first; ++m) {
            first = memberZ[m] > tz || (memberZ[m] == tz && memberX[m] >= tx);
          }
          if (!first || !FirstRectHolding(shape.rects, r, tx, tz)) {
            continue;
          }
          const float weight = WeightAt(shape, tx, tz, brush);
          if (weight <= 0.0f || !WithinLimits(terrain, perTexel, tx, tz, brush.shape)) {
            continue;
          }
          const std::uint64_t texel = Brushed(snapshots[r], tx, tz, weight, brush, seconds);
          for (int m = 0; m < members; ++m) {
            texels[index(memberX[m], memberZ[m])] = texel;
          }
        }
      }
    }
    return shape.rects;
  }

  namespace
  {
    /** N-way turns: the nearest texel to (x, z) turned back into the first sector; false off the mask. */
    bool TurnedBackTexel(const int maskWidth, const int maskHeight, const int turns, const int x, const int z, int& outX, int& outZ)
    {
      const int k = TurnSector(maskWidth, maskHeight, turns, x, z);
      const double cx = (maskWidth - 1) * 0.5;
      const double cz = (maskHeight - 1) * 0.5;
      const double back = -kTwoPi * k / std::clamp(turns, 2, kMaxSymmetryCopies);
      outX = static_cast<int>(std::lround(cx + (x - cx) * std::cos(back) - (z - cz) * std::sin(back)));
      outZ = static_cast<int>(std::lround(cz + (x - cx) * std::sin(back) + (z - cz) * std::cos(back)));
      return outX >= 0 && outZ >= 0 && outX < maskWidth && outZ < maskHeight;
    }

    [[nodiscard]] int LargestByteDifference(const std::uint64_t a, const std::uint64_t b)
    {
      int largest = 0;
      for (int layer = 0; layer < 8; ++layer) {
        largest = std::max(largest, std::abs(static_cast<int>(MaskByte(a, layer)) - static_cast<int>(MaskByte(b, layer))));
      }
      return largest;
    }
  } // namespace

  MaskSymmetryReport CheckMaskSymmetry(const std::uint64_t* const texels, const int maskWidth, const int maskHeight, const Symmetry requested,
                                       const int turns)
  {
    MaskSymmetryReport report;
    const Symmetry symmetry = EffectiveSymmetry(requested, maskWidth, maskHeight);
    if (texels == nullptr || maskWidth < 2 || maskHeight < 2 || symmetry == Symmetry::None) {
      return report;
    }
    constexpr int kBlock = 4;
    const int blocksX = (maskWidth + kBlock - 1) / kBlock;
    const int blocksZ = (maskHeight + kBlock - 1) / kBlock;
    std::vector<std::uint8_t> marked(static_cast<std::size_t>(blocksX) * static_cast<std::size_t>(blocksZ), 0);
    const auto at = [&](const int x, const int z) {
      return texels[static_cast<std::size_t>(z) * static_cast<std::size_t>(maskWidth) + static_cast<std::size_t>(x)];
    };
    for (int z = 0; z < maskHeight; ++z) {
      for (int x = 0; x < maskWidth; ++x) {
        int largest = 0;
        if (symmetry == Symmetry::NWay) {
          int sx = 0;
          int sz = 0;
          if (TurnSector(maskWidth, maskHeight, turns, x, z) == 0 || !TurnedBackTexel(maskWidth, maskHeight, turns, x, z, sx, sz) ||
              TurnSector(maskWidth, maskHeight, turns, sx, sz) != 0) {
            continue;
          }
          largest = LargestByteDifference(at(x, z), at(sx, sz));
        } else {
          int copyX[kMaxSymmetryCopies];
          int copyZ[kMaxSymmetryCopies];
          const int copies = SymmetricSamples(symmetry, turns, maskWidth, maskHeight, x, z, copyX, copyZ);
          for (int c = 1; c < copies; ++c) {
            largest = std::max(largest, LargestByteDifference(at(x, z), at(copyX[c], copyZ[c])));
          }
        }
        ++report.checked;
        report.largest = std::max(report.largest, largest);
        if (largest > 0) {
          ++report.differing;
          marked[static_cast<std::size_t>(z / kBlock) * static_cast<std::size_t>(blocksX) + static_cast<std::size_t>(x / kBlock)] = 1;
        }
      }
    }
    for (int bz = 0; bz < blocksZ; ++bz) {
      for (int bx = 0; bx < blocksX; ++bx) {
        if (marked[static_cast<std::size_t>(bz) * static_cast<std::size_t>(blocksX) + static_cast<std::size_t>(bx)] != 0) {
          report.blocks.push_back(
            {bx * kBlock, bz * kBlock, std::min(maskWidth - 1, bx * kBlock + kBlock - 1), std::min(maskHeight - 1, bz * kBlock + kBlock - 1)});
        }
      }
    }
    return report;
  }

  SampleRect MakeMasksSymmetric(std::uint64_t* const texels, const int maskWidth, const int maskHeight, const Symmetry requested, const int turns)
  {
    const Symmetry symmetry = EffectiveSymmetry(requested, maskWidth, maskHeight);
    if (texels == nullptr || maskWidth < 2 || maskHeight < 2 || symmetry == Symmetry::None) {
      return {};
    }
    const auto index = [maskWidth](const int x, const int z) {
      return static_cast<std::size_t>(z) * static_cast<std::size_t>(maskWidth) + static_cast<std::size_t>(x);
    };
    if (symmetry == Symmetry::NWay) {
      // Only texels outside the first sector are written, from texels inside it.
      for (int z = 0; z < maskHeight; ++z) {
        for (int x = 0; x < maskWidth; ++x) {
          int sx = 0;
          int sz = 0;
          if (TurnSector(maskWidth, maskHeight, turns, x, z) != 0 && TurnedBackTexel(maskWidth, maskHeight, turns, x, z, sx, sz) &&
              TurnSector(maskWidth, maskHeight, turns, sx, sz) == 0) {
            texels[index(x, z)] = texels[index(sx, sz)];
          }
        }
      }
    } else {
      for (int z = 0; z < maskHeight; ++z) {
        for (int x = 0; x < maskWidth; ++x) {
          int copyX[kMaxSymmetryCopies];
          int copyZ[kMaxSymmetryCopies];
          const int copies = SymmetricSamples(symmetry, turns, maskWidth, maskHeight, x, z, copyX, copyZ);
          bool first = true;
          for (int c = 1; c < copies && first; ++c) {
            first = copyZ[c] > z || (copyZ[c] == z && copyX[c] >= x);
          }
          if (!first) {
            continue;
          }
          for (int c = 1; c < copies; ++c) {
            texels[index(copyX[c], copyZ[c])] = texels[index(x, z)];
          }
        }
      }
    }
    return {0, 0, maskWidth - 1, maskHeight - 1};
  }

  void MaskCoverage(const std::uint64_t* const texels, const std::size_t count, float (&coverage)[8])
  {
    std::uint64_t sums[8]{};
    for (std::size_t i = 0; i < count; ++i) {
      for (int layer = 0; layer < 8; ++layer) {
        sums[layer] += MaskByte(texels[i], layer);
      }
    }
    for (int layer = 0; layer < 8; ++layer) {
      coverage[layer] = count == 0 ? 0.0f : static_cast<float>(static_cast<double>(sums[layer]) / (255.0 * static_cast<double>(count)));
    }
  }

  SampleRect ApplyMaskRules(std::uint64_t* const texels, const int maskWidth, const int maskHeight, const MaskTerrain& terrain,
                            const std::vector<MaskRule>& rules)
  {
    if (texels == nullptr || maskWidth < 1 || maskHeight < 1) {
      return {};
    }
    const float perTexel = SamplesPerTexel(maskWidth, terrain);
    for (int tz = 0; tz < maskHeight; ++tz) {
      for (int tx = 0; tx < maskWidth; ++tx) {
        float height = 0.0f;
        float slope = 0.0f;
        GroundAt(terrain, perTexel, tx, tz, height, slope);
        std::uint64_t& texel = texels[static_cast<std::size_t>(tz) * static_cast<std::size_t>(maskWidth) + static_cast<std::size_t>(tx)];
        for (const MaskRule& rule : rules) {
          const float units = height / 128.0f;
          if ((rule.useHeight && (units < rule.low || units > rule.high)) || (rule.useSlope && (slope < rule.minSlope || slope > rule.maxSlope))) {
            continue;
          }
          texel = WithMaskByte(texel, std::clamp(rule.layer, 0, 7), 255);
        }
      }
    }
    return {0, 0, maskWidth - 1, maskHeight - 1};
  }
} // namespace faf::editor
