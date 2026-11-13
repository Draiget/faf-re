#pragma once

#include "editor/tools/EdHeightBrush.h"

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /** What the symmetry check found on a height field. */
  struct SymmetryReport
  {
    /** Samples compared with their copies (for N-way turns, those outside the first sector that have a turned point on
     * the map). */
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
  SymmetryReport CheckSymmetry(
    const std::uint16_t* heights,
    int width,
    int height,
    Symmetry symmetry,
    int turns,
    int turnTolerance = 32
  );

  /**
   * Makes the field symmetric from its source part: every group of copies takes its first member's height
   * (lowest z, then lowest x: the top or left part); for N-way turns every sample outside the first sector
   * takes the height at its point turned back into it. Returns the rectangle it may have written (the
   * whole map) for undo, or an empty one when there is no symmetry.
   */
  SampleRect MakeSymmetric(std::uint16_t* heights, int width, int height, Symmetry symmetry, int turns);

  /** The symmetry a map was made with, as DetectSymmetry finds it. */
  struct DetectedSymmetry
  {
    Symmetry symmetry = Symmetry::None;
    /** For N-way turns, how many. */
    int turns = 0;
    /** The share of sampled points whose copies are within the tolerance (0 to 1); 0 when the heights are flat. */
    float matched = 0.0f;
    /** The centre in height samples: the map's middle, or a little off it as the markers' partners show. */
    float centreX = 0.0f;
    float centreZ = 0.0f;
    /** Start positions and resource markers whose copy lands on another marker of their kind. */
    int startsMatched = 0;
    int resourcesMatched = 0;
  };

  /** A marker the detection reads (height samples, as the map's markers are in game units). */
  struct SymmetryMarker
  {
    enum class Kind
    {
      Start,
      Mass,
      Hydrocarbon,
    };
    float x = 0.0f;
    float z = 0.0f;
    Kind kind = Kind::Start;
  };

  /**
   * The images of (x, z) under `symmetry` about the centre (cx, cz), the point itself first; about the map's middle
   * they are the brush's copies (HeightBrushCentres). Returns how many.
   */
  int SymmetryImages(
    Symmetry symmetry,
    int turns,
    float cx,
    float cz,
    float x,
    float z,
    float (&outX)[kMaxSymmetryCopies],
    float (&outZ)[kMaxSymmetryCopies]
  );

  /**
   * Finds the symmetry a map was made with (FAF Studio's symmetry detection on the editor's height check):
   *  - the markers: every start position and resource marker is mapped by each copy of a mode, and the copy must
   *    land on another marker of its kind (within about a percent of the map); one on the axis maps onto itself and
   *    counts neither way. Every start must find its partner, a quarter of the resource markers may be missing;
   *  - the heights: points on a grid are compared with their copies (within half a game unit); a map with less than
   *    2 units between its lowest and highest point says nothing.
   * A mode the markers rule out (a start without its partner, or more than half the resource markers) is out. Else 97%
   * of the points matching settles it; with fewer, the markers must prove it: every start paired, three quarters of
   * the resources, and 90% of the points (or flat ground). For the mirrors and the half turn, a centre a little off the
   * middle is measured from the partners and tried. The mode with the most matched markers wins, then (on flat ground)
   * the fewer copies or (else) the more, then the closer match.
   */
  DetectedSymmetry
  DetectSymmetry(const std::uint16_t* heights, int width, int height, const std::vector<SymmetryMarker>& markers = {});
} // namespace faf::editor
