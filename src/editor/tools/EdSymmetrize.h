#pragma once

// Make symmetric with options (FAF Studio's `symmetrize` op, src/editor/terrain/EdFieldSc.cpp): the part copied, a
// seam that cross-fades the part's borders, copies combined (average, highest, lowest) instead of copied, and a
// centre off the map's middle; for the heights, the texture masks and the terrain types. No engine types: tested on
// its own (tests/editor/SymmetrizeTests.cpp).

#include "editor/tools/EdHeightBrush.h"

#include <cstdint>
#include <string>

namespace faf::editor
{
  /** How a group of copies gets its value. */
  enum class SymmetryCombine
  {
    /** The source part's (the others are copies of it). */
    Copy,
    /** The average of every copy. */
    Average,
    /** The highest of them. */
    Max,
    /** The lowest of them. */
    Min,
  };

  struct SymmetrizeOptions
  {
    Symmetry symmetry = Symmetry::None;
    /** N-way turns: how many. */
    int turns = 3;
    /** Copy: the part copied, 0 to SymmetryParts - 1 (0 is the left or top one, the others follow round the centre). */
    int part = 0;
    SymmetryCombine combine = SymmetryCombine::Copy;
    /** Copy: the width (height samples) over which the part's borders cross-fade into its neighbours; 0 a hard edge. */
    float seam = 0.0f;
    /** The centre in height samples; below 0, the map's middle. */
    float centreX = -1.0f;
    float centreZ = -1.0f;
  };

  /** How many parts a symmetry splits a map into (1 for none). */
  [[nodiscard]] int SymmetryParts(Symmetry symmetry, int turns);

  /** The heights (`width` x `height` words) made symmetric; false with `error` when the op refuses. */
  bool SymmetrizeHeights(
    std::uint16_t* heights,
    int width,
    int height,
    const SymmetrizeOptions& options,
    std::string& error
  );

  /**
   * The eight strata masks (a 64-bit texel each, byte k stratum k + 1) made symmetric, each on its own. The masks
   * cover the map of `fieldWidth` x `fieldHeight` height samples; a texel's middle is where it lies.
   */
  bool SymmetrizeMasks(
    std::uint64_t* texels,
    int maskWidth,
    int maskHeight,
    int fieldWidth,
    int fieldHeight,
    const SymmetrizeOptions& options,
    std::string& error
  );

  /** A grid of codes over the map (terrain types: a byte a cell) made symmetric: each takes a copy's code, never a
   * blend. */
  bool SymmetrizeCells(
    std::uint8_t* cells,
    int cellWidth,
    int cellHeight,
    int fieldWidth,
    int fieldHeight,
    const SymmetrizeOptions& options,
    std::string& error
  );
} // namespace faf::editor
