#pragma once

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /** The Tools panel's terrain brush modes, in its order. */
  enum class HeightBrushMode
  {
    Raise,
    Lower,
    Smooth,
    Flatten,
    Noise,
  };

  /** The Tools panel's symmetry modes, in its order. The diagonal and turn modes need a square map. */
  enum class Symmetry
  {
    None,
    LeftRight,
    TopBottom,
    DiagonalBack,    // the "\" diagonal: (x, z) and (z, x)
    DiagonalForward, // the "/" diagonal: (x, z) and (W - z, W - x)
    HalfTurn,
    BothAxes,
    BothDiagonals,
    QuarterTurns,
    NWay,
  };

  /** The most copies a symmetry makes (N-way turns go up to this many). */
  constexpr int kMaxSymmetryCopies = 16;

  struct HeightBrush
  {
    HeightBrushMode mode = HeightBrushMode::Raise;
    Symmetry symmetry = Symmetry::None;
    /** Radius in height samples (one sample per game unit). */
    float radius = 14.0f;
    /** 0..1: how fast the brush works. */
    float strength = 0.5f;
    /** 0..1: the share of the radius over which the brush fades out (0 a hard edge, 1 fading from the middle). */
    float falloff = 0.6f;
    /** Flatten's height, in height words (1/128 of a game unit). */
    float flattenTo = 0.0f;
    /** N-way turns: the number of copies, 2 to kMaxSymmetryCopies. */
    int turns = 3;
  };

  /** A rectangle of samples, both ends included. */
  struct SampleRect
  {
    int x0 = 0;
    int z0 = 0;
    int x1 = -1;
    int z1 = -1;
  };

  /**
   * One step of a height brush on a grid of 16-bit height words (`width` x `height` samples, row by row),
   * centred on (`x`, `z`) in samples and lasting `seconds`. Returns the rectangles it wrote, one per copy
   * of the brush that symmetry makes.
   *
   * Symmetry is exact: every sample belongs to the group of samples the symmetry maps it onto. The group's
   * brush weight is the strongest of the brush's copies at any of its members (so a stroke across a mirror
   * line doesn't apply twice), its new height is computed once from its first member (lowest z, then x),
   * and that height is written to every member. A map whose copies were equal stays so, bit for bit.
   * N-way turns can't be exact (their copies fall between samples): the first sector, from the turn
   * centre towards +x and turning towards +z, is painted with the brush, and every other sample the brush
   * covers takes TurnedHeight. A turn of 4 copies lands on samples and is exact. The diagonal and turn modes on a map that isn't square fall back to
   * no symmetry.
   */
  std::vector<SampleRect>
  ApplyHeightBrush(std::uint16_t* heights, int width, int height, float x, float z, const HeightBrush& brush, float seconds);

  /** The rectangles `ApplyHeightBrush` would write for the same arguments, without writing (undo saves them first). */
  std::vector<SampleRect> HeightBrushRects(int width, int height, float x, float z, const HeightBrush& brush);

  /** The brush's centre and its symmetric copies (the cursor's first), as the brush paints them. */
  int HeightBrushCentres(int width, int height, float x, float z, Symmetry symmetry, int turns, float (&outX)[kMaxSymmetryCopies],
                         float (&outZ)[kMaxSymmetryCopies]);

  /**
   * The symmetric copies of sample (x, z), itself first (the group, with repeats where copies coincide).
   * N-way turns give the nearest samples to the turned points.
   */
  int SymmetricSamples(Symmetry symmetry, int turns, int width, int height, int x, int z, int (&outX)[kMaxSymmetryCopies],
                       int (&outZ)[kMaxSymmetryCopies]);

  /** N-way turns: the sector of sample (x, z), 0 the first (from the map's centre towards +x, turning towards +z). */
  int TurnSector(int width, int height, int turns, int x, int z);

  /**
   * N-way turns: the height a sample copies, at its point turned back into the first sector, read between
   * samples. A neighbour of that point outside the first sector is read at its own turned-back sample, so
   * every read lands in the first sector and the brush and the symmetry check read the same heights.
   * False when the point is off the map.
   */
  bool TurnedHeight(const std::uint16_t* heights, int width, int height, int turns, int x, int z, double& value);

  /** The symmetry the brush really uses on a map of this size (the square-only modes fall back to None). */
  Symmetry EffectiveSymmetry(Symmetry symmetry, int width, int height);
} // namespace faf::editor
