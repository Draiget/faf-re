#pragma once

#include <array>
#include <cstdint>
#include <string_view>
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
    /** The strata the map's shader reads through saturate(2m-1) (RemappedStrata): the brush works in the weight that
     * shows and stores the byte for it. */
    std::uint8_t remapped = 0;
    /** Paint stops at this share of full weight (FAF Studio's target %); ground already above it stays. */
    float target = 1.0f;
    /** 0..1: the share of a texel's weight a hash takes away, for a speckled edge (the same at every copy). */
    float scatter = 0.0f;
    /** The scatter's pattern (one per stroke). */
    std::uint32_t scatterSeed = 0;
    /** Paints only where the ground is at least this steep (rise over run; 0: anywhere). */
    float limitMinSlope = 0.0f;
    /**
     * Build up (the default): a still brush keeps adding. Off, with a MaskStroke: each texel's coverage is the
     * strongest weight times strength any step of the stroke gave it, and the texel is what it was before the stroke
     * blended towards the target (Paint) or nothing (Erase) by that coverage, so dabs don't pile up and the edge keeps
     * the brush's profile (FAF Studio's stroke model).
     */
    bool buildUp = true;
  };

  /** One stroke's texels as they were before it and their coverage so far (MaskBrush::buildUp off). */
  struct MaskStroke
  {
    std::vector<std::uint64_t> before;
    std::vector<float> coverage;
  };

  /**
   * Which strata (bit k: the stratum of byte k) a terrain shader reads through `saturate(m * 2 - 1)` rather than as
   * it is (FAF's effects/terrain.fx): every shader but TerrainPBR does, both masks; the Terrain1xx and Terrain2xx
   * shaders (Terrain100 to Terrain252, with or without B) only the second mask's colour, its alpha (stratum 8) as it
   * is. A shader the table doesn't know: all eight, as most do.
   */
  [[nodiscard]] std::uint8_t RemappedStrata(std::string_view shader);

  /** The weight a stored byte shows (0..255): itself, or saturate(2m-1) of it when its stratum is remapped. */
  [[nodiscard]] inline float MaskWeight(
    const std::uint8_t stored,
    const bool remapped
  )
  {
    return remapped ? (stored <= 127 ? 0.0f : static_cast<float>(stored) * 2.0f - 255.0f) : static_cast<float>(stored);
  }

  /**
   * The byte to store for a weight (0..255): itself, or (w + 255) / 2 when remapped. `before` stays when it already
   * shows that weight, so a texel a stroke didn't change keeps its byte (a remapped zero is any byte up to 127).
   */
  [[nodiscard]] inline std::uint8_t MaskStoredFor(
    const float weight,
    const bool remapped,
    const std::uint8_t before
  )
  {
    const float w = weight < 0.0f ? 0.0f : (weight > 255.0f ? 255.0f : weight);
    if (static_cast<int>(MaskWeight(before, remapped) + 0.5f) == static_cast<int>(w + 0.5f)) {
      return before;
    }
    if (!remapped) {
      return static_cast<std::uint8_t>(w + 0.5f);
    }
    return w <= 0.0f ? std::uint8_t{127} : static_cast<std::uint8_t>((w + 255.0f) * 0.5f + 0.5f);
  }

  /**
   * Per stratum, the texels whose weight a remapped shader hides (byte 1..127) and those it shows (128..255). Hidden
   * bytes alone mean nothing (GPG's own maps fade their edges through them); a remapped stratum with paint and none
   * that shows was painted for a shader that reads masks as they are (`PaintedForAnotherRange`).
   */
  struct MaskRangeReport
  {
    std::array<int, 8> hidden{};
    std::array<int, 8> shown{};
    [[nodiscard]] bool PaintedForAnotherRange(
      const int layer
    ) const noexcept
    {
      const auto i = static_cast<std::size_t>(layer);
      return hidden[i] > 0 && shown[i] == 0;
    }
    [[nodiscard]] int Total() const noexcept
    {
      int total = 0;
      for (int layer = 0; layer < 8; ++layer) {
        total += PaintedForAnotherRange(layer) ? hidden[static_cast<std::size_t>(layer)] : 0;
      }
      return total;
    }
  };
  [[nodiscard]] MaskRangeReport CheckMaskRange(const std::uint64_t* texels, std::size_t count, std::uint8_t remapped);

  /** The stratum masks as the editor keeps them: one texel's eight weights in one word, byte k for stratum k. */
  [[nodiscard]] inline std::uint8_t MaskByte(
    const std::uint64_t texel,
    const int layer
  )
  {
    return static_cast<std::uint8_t>(texel >> (8 * layer));
  }
  [[nodiscard]] inline std::uint64_t WithMaskByte(
    const std::uint64_t texel,
    const int layer,
    const std::uint8_t value
  )
  {
    const int shift = 8 * layer;
    return (texel & ~(std::uint64_t{0xFF} << shift)) | (std::uint64_t{value} << shift);
  }

  /** The height field under the masks, for the brush's limits (one mask texel spans `width - 1` / mask width samples).
   */
  struct MaskTerrain
  {
    const std::uint16_t* heights = nullptr;
    int width = 0;
    int height = 0;
  };

  /** The rectangles of texels `ApplyMaskBrush` would write, centred on (x, z) in height samples. */
  std::vector<SampleRect>
  MaskBrushRects(int maskWidth, int maskHeight, const MaskTerrain& terrain, float x, float z, const MaskBrush& brush);

  /**
   * One step of a mask brush on `maskWidth` x `maskHeight` texels at (x, z) in height samples, lasting
   * `seconds`. Symmetry is exact as for heights (one new texel per group of copies, from its first member,
   * written to all); N-way turns paint the first sector and copy the nearest turned-back texel elsewhere.
   * Weights move by whole steps with a fixed per-texel dither, so weak strokes still reach their target.
   */
  std::vector<SampleRect> ApplyMaskBrush(
    std::uint64_t* texels,
    int maskWidth,
    int maskHeight,
    const MaskTerrain& terrain,
    float x,
    float z,
    const MaskBrush& brush,
    float seconds,
    MaskStroke* stroke = nullptr
  );

  /** A rule for the whole map: the layer's weight full where the ground is in the height and slope range, else
   * unchanged. */
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
  MaskSymmetryReport
  CheckMaskSymmetry(const std::uint64_t* texels, int maskWidth, int maskHeight, Symmetry symmetry, int turns);

  /** Copies the source part's texels to their copies (the first member of each group; for turns the first sector). */
  SampleRect MakeMasksSymmetric(std::uint64_t* texels, int maskWidth, int maskHeight, Symmetry symmetry, int turns);

  /** Each layer's share of full weight over the map, 0..1. */
  void MaskCoverage(const std::uint64_t* texels, std::size_t count, float (&coverage)[8], std::uint8_t remapped = 0);

  /** Applies the rules in order over every texel; returns the whole mask's rectangle for undo and upload. */
  SampleRect ApplyMaskRules(
    std::uint64_t* texels,
    int maskWidth,
    int maskHeight,
    const MaskTerrain& terrain,
    const std::vector<MaskRule>& rules
  );
} // namespace faf::editor
