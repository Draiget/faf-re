#pragma once

#include <cstdint>
#include <vector>

#include "editor/tools/EdHeightBrush.h"

namespace faf::editor
{
  /** The Texture tool's modes. */
  enum class MaskBrushMode
  {
    /** The layer's weight up towards full. */
    Paint,
    /** The layer's weight down towards none. */
    Erase,
    /** The layer's weight towards its neighbours' average. */
    Smooth,
  };

  /**
   * One texture-layer brush: the height brush's shape (radius in height samples, strength, falloff,
   * symmetry, limits) acting on one stratum's mask.
   */
  struct MaskBrush
  {
    HeightBrush shape;
    MaskBrushMode mode = MaskBrushMode::Paint;
    /** The stratum painted, 0..7 (the panel's layers 1 to 8; the lower layer has no mask, the upper its alpha). */
    int layer = 0;
    /** Paint also lowers the strata above the painted one by as much, so it shows (they are blended over it). */
    bool lowerAbove = true;
    /** Counts the brush's steps: the dither that rounds weights to whole steps changes with it. */
    std::uint32_t step = 0;
  };

  /** The stratum masks as the editor keeps them: one texel's eight weights in one word, byte k for stratum k. */
  [[nodiscard]] inline std::uint8_t MaskByte(const std::uint64_t texel, const int layer)
  {
    return static_cast<std::uint8_t>(texel >> (8 * layer));
  }
  [[nodiscard]] inline std::uint64_t WithMaskByte(const std::uint64_t texel, const int layer, const std::uint8_t value)
  {
    const int shift = 8 * layer;
    return (texel & ~(std::uint64_t{0xFF} << shift)) | (std::uint64_t{value} << shift);
  }

  /** The height field under the masks, for the brush's limits (one mask texel spans `width - 1` / mask width samples). */
  struct MaskTerrain
  {
    const std::uint16_t* heights = nullptr;
    int width = 0;
    int height = 0;
  };

  /** The rectangles of texels `ApplyMaskBrush` would write, centred on (x, z) in height samples. */
  std::vector<SampleRect> MaskBrushRects(int maskWidth, int maskHeight, const MaskTerrain& terrain, float x, float z, const MaskBrush& brush);

  /**
   * One step of a mask brush on `maskWidth` x `maskHeight` texels at (x, z) in height samples, lasting
   * `seconds`. Symmetry is exact as for heights (one new texel per group of copies, from its first member,
   * written to all); N-way turns paint the first sector and copy the nearest turned-back texel elsewhere.
   * Weights move by whole steps with a fixed per-texel dither, so weak strokes still reach their target.
   */
  std::vector<SampleRect> ApplyMaskBrush(std::uint64_t* texels, int maskWidth, int maskHeight, const MaskTerrain& terrain, float x, float z,
                                         const MaskBrush& brush, float seconds);

  /** A rule for the whole map: the layer's weight full where the ground is in the height and slope range, else unchanged. */
  struct MaskRule
  {
    int layer = 0;
    bool useHeight = false;
    /** Heights in game units. */
    float low = 0.0f;
    float high = 512.0f;
    bool useSlope = false;
    /** Slopes as rise over run. */
    float minSlope = 0.0f;
    float maxSlope = 100.0f;
  };

  /** What the symmetry check found on the masks: texels whose copies differ, in blocks of texels. */
  struct MaskSymmetryReport
  {
    int checked = 0;
    int differing = 0;
    /** The largest difference of one layer's weight between copies (0-255). */
    int largest = 0;
    std::vector<SampleRect> blocks;
  };

  /**
   * Compares every texel (all eight layers) with its copies under `symmetry`; N-way turns compare a texel
   * outside the first sector with its nearest turned-back texel.
   */
  MaskSymmetryReport CheckMaskSymmetry(const std::uint64_t* texels, int maskWidth, int maskHeight, Symmetry symmetry, int turns);

  /** Copies the source part's texels to their copies (the first member of each group; for turns the first sector). */
  SampleRect MakeMasksSymmetric(std::uint64_t* texels, int maskWidth, int maskHeight, Symmetry symmetry, int turns);

  /** Each layer's share of full weight over the map, 0..1. */
  void MaskCoverage(const std::uint64_t* texels, std::size_t count, float (&coverage)[8]);

  /** Applies the rules in order over every texel; returns the whole mask's rectangle for undo and upload. */
  SampleRect ApplyMaskRules(std::uint64_t* texels, int maskWidth, int maskHeight, const MaskTerrain& terrain, const std::vector<MaskRule>& rules);
} // namespace faf::editor
