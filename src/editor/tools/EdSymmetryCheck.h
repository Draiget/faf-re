#pragma once

#include "editor/tools/EdHeightBrush.h"

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /** What the symmetry check found on a height field. */
  struct SymmetryReport
  {
    /** Samples compared with their copies (for N-way turns, those outside the first sector that have a turned point on the map). */
    int checked = 0;
    /** Samples that differ from a copy by more than the tolerance. */
    int differing = 0;
    /** The largest difference seen, in height words (1/128 of a game unit). */
    int largest = 0;
    /** Blocks of kSymmetryBlock x kSymmetryBlock samples holding a differing sample, for the overlay. */
    std::vector<SampleRect> blocks;
  };

  /** The overlay's block size, in samples. */
  constexpr int kSymmetryBlock = 4;

  /**
   * Compares every sample with its copies under `symmetry`. The exact modes count any difference; N-way
   * turns compare a sample outside the first sector with the height at its point turned back into the
   * first sector, read between samples, and count differences above `turnTolerance` words.
   */
  SymmetryReport CheckSymmetry(const std::uint16_t* heights, int width, int height, Symmetry symmetry, int turns, int turnTolerance = 32);

  /**
   * Makes the field symmetric from its source part: every group of copies takes its first member's height
   * (lowest z, then lowest x: the top or left part); for N-way turns every sample outside the first sector
   * takes the height at its point turned back into it. Returns the rectangle it may have written (the
   * whole map) for undo, or an empty one when there is no symmetry.
   */
  SampleRect MakeSymmetric(std::uint16_t* heights, int width, int height, Symmetry symmetry, int turns);
} // namespace faf::editor
