#pragma once

#include <cstdint>
#include <memory>
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
    /** Towards the panel's height. */
    SetHeight,
    /** Towards the nearest step of the panel's step height. */
    Terrace,
    /** Towards the plane through three picked points. */
    Plane,
    /** Adds a height image over the brush's circle, once per click. */
    Stamp,
    /**
     * Thermal erosion: where the ground between two neighbours is steeper than the talus slope, height moves from the
     * higher to the lower until it isn't; gentler ground stays. Each pair's exchange is equal and opposite, so ground
     * is moved downhill, not made.
     */
    Erode,
    /**
     * Hydraulic erosion: water droplets dropped in the brush run downhill, carry ground away where they speed up and
     * leave it where they slow, carving channels and fans. What a droplet still carries when it stops is left there, so
     * ground is moved, not made.
     */
    WaterErode,
    /**
     * Like Water erode, but the water runs on past the brush and keeps digging downhill, up to 0.8 of the radius
     * beyond it (FAF Studio's Rain brush).
     */
    Rain,
    /**
     * Sediment laid under the brush as an even heap that the water then carries a little downhill, so it settles
     * like washed-in ground (FAF Studio's Deposit brush). Ground is made. Right-dragging Water erode does this.
     */
    Deposit,
    /**
     * Towards the stroke's level (the ground under its first point) in one go where the brush is full, the falloff
     * shaping the shoulder (FAF Studio's Plateau): a flat top with a soft edge.
     */
    Plateau,
    /** Away from the blurred ground, the opposite of Smooth: edges and ridges stand out. Right-dragging Smooth does it.
     */
    Sharpen,
    /** A drag from a start to an end: a straight slope as wide as the brush between the ground's heights there. */
    Ramp,
    /** Clicked points make a curve that shapes the ground along it (EdTerrainPath), applied in one go. */
    Path,
  };
  /**
   * The mode that does the opposite (a negative strength, a right-drag): Raise and Lower swap, Smooth sharpens and
   * Sharpen smooths, Water erode deposits and Deposit erodes; the others have no opposite and stay.
   */
  [[nodiscard]] constexpr HeightBrushMode InvertedHeightMode(
    const HeightBrushMode mode
  ) noexcept
  {
    switch (mode) {
    case HeightBrushMode::Raise:
      return HeightBrushMode::Lower;
    case HeightBrushMode::Lower:
      return HeightBrushMode::Raise;
    case HeightBrushMode::Smooth:
      return HeightBrushMode::Sharpen;
    case HeightBrushMode::Sharpen:
      return HeightBrushMode::Smooth;
    case HeightBrushMode::WaterErode:
      return HeightBrushMode::Deposit;
    case HeightBrushMode::Deposit:
      return HeightBrushMode::WaterErode;
    default:
      return mode;
    }
  }

  /**
   * The brush's shape (FAF Studio's brushes.lua): Round follows the falloff; the others are masks over the brush's
   * square, read at (u, v) in -1..1 and turned by the brush's angle.
   */
  enum class BrushShape
  {
    Round,
    Square,
    Diamond,
    Cone,
    Plateau,
    Ring,
    Ridge,
    Mountain,
    Rocks,
    Bump,
    /** A greyscale image of the brush library, on the brush's `shapeImage` grid. */
    Image,
  };
  /** Round and the procedural shapes (Image comes from the brush library). */
  inline constexpr int kBrushShapeCount = 10;

  /** A shape on an n x n grid over its square (-1..1 on both axes, corners on the samples), row by row. */
  struct ShapeGrid
  {
    int n = 0;
    std::vector<float> values;
    /** Read between samples at (u, v); 0 outside the square. */
    [[nodiscard]] float Sample(
      const float u,
      const float v
    ) const noexcept
    {
      if (n < 2 || u < -1.0f || v < -1.0f || u > 1.0f || v > 1.0f) {
        return 0.0f;
      }
      const float top = static_cast<float>(n - 1);
      const float fx = (u + 1.0f) * 0.5f * top;
      const float fz = (v + 1.0f) * 0.5f * top;
      const int x0 = fx >= top ? n - 2 : static_cast<int>(fx);
      const int z0 = fz >= top ? n - 2 : static_cast<int>(fz);
      const float tx = fx - static_cast<float>(x0);
      const float tz = fz - static_cast<float>(z0);
      const auto at = [&](const int x, const int z) {
        return values[static_cast<std::size_t>(z) * static_cast<std::size_t>(n) + static_cast<std::size_t>(x)];
      };
      return (at(x0, z0) * (1.0f - tx) + at(x0 + 1, z0) * tx) * (1.0f - tz) +
        (at(x0, z0 + 1) * (1.0f - tx) + at(x0 + 1, z0 + 1) * tx) * tz;
    }
  };

  /** How a stamp meets the ground (FAF Studio's stamp.lua). Max, Min and Replace measure from the brush's `stampBase`.
   */
  enum class StampMode
  {
    /** The stamp is added to the ground. */
    Add,
    Subtract,
    /** The ground rises to the stamp where the stamp is higher. */
    Max,
    /** The ground sinks to the stamp turned upside down where that is lower. */
    Min,
    /** Inside its circle the ground becomes the stamp: a mountain set into the landscape. */
    Replace,
  };

  /**
   * The brush's weight (0..1) at offset (dx, dz) from its centre, in its own frame: the falloff for Round, else its
   * shape turned by its angle, cut at the radius (the mask brush reads its shape through this too).
   */
  struct HeightBrush;
  [[nodiscard]] float BrushWeightAt(const HeightBrush& brush, float dx, float dz);

  /** A shape's name for the panel. */
  [[nodiscard]] const char* BrushShapeName(BrushShape shape);

  /** A shape's weight (0..1) at (u, v) of its square (-1..1 on both axes); Round: 1 inside the unit circle. */
  [[nodiscard]] float BrushShapeAt(BrushShape shape, float u, float v);

  /**
   * Rain and Deposit: droplets on FAF Studio's erosion session (src/editor/terrain/EdErosion.h). Water erode keeps the
   * editor's own droplets: Studio's carries part of what runs out of the brush away, and Water erode moves ground
   * without losing any.
   */
  [[nodiscard]] constexpr bool IsErosionMode(
    const HeightBrushMode mode
  ) noexcept
  {
    return mode == HeightBrushMode::Rain || mode == HeightBrushMode::Deposit;
  }

  /**
   * The erosion brushes' state for one stroke: the map's heights as floats, so ground a droplet moves keeps its
   * fractions from step to step, and the stroke's droplet seed. The caller makes one when a stroke starts and drops it
   * when the stroke ends; without one, each step starts afresh from the map's words.
   */
  class ErosionStroke;
  struct ErosionStrokeDelete
  {
    void operator()(ErosionStroke* stroke) const noexcept;
  };
  using ErosionStrokePtr = std::unique_ptr<ErosionStroke, ErosionStrokeDelete>;
  [[nodiscard]] ErosionStrokePtr MakeErosionStroke();

  /** A height image for stamps: `width` x `height` words, read between samples over the brush's square. */
  struct HeightStamp
  {
    int width = 0;
    int height = 0;
    std::vector<std::uint16_t> words;
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
    /** Set height's height, in height words. */
    float setTo = 0.0f;
    /** Terrace's step, in height words (at least 1). */
    float terraceStep = 640.0f;
    /** Plane: height words = planeX * x + planeZ * z + planeC, at sample (x, z); used when `planeSet`. */
    bool planeSet = false;
    double planeX = 0.0;
    double planeZ = 0.0;
    double planeC = 0.0;
    /** Stamp: the image (null: none) and the height its brightest value adds, in height words, times strength. */
    const HeightStamp* stamp = nullptr;
    float stampHeight = 2560.0f;
    /** Erode: the steepest slope (rise over run, game units) the ground keeps. */
    float erodeTalus = 0.6f;
    /** The brush's shape and how far it is turned (degrees, towards +z); Round uses `falloff`. */
    BrushShape shape = BrushShape::Round;
    float shapeAngle = 0.0f;
    /** Image: the library image's grid (null: the brush is round). */
    const ShapeGrid* shapeImage = nullptr;
    /** Stamp: how it meets the ground, the height Max, Min and Replace measure from (words), its turn (degrees). */
    StampMode stampMode = StampMode::Add;
    float stampBase = 0.0f;
    float stampTurn = 0.0f;
    /**
     * Noise: smooth value noise with a lattice cell of `noiseScale` samples and `noiseOctaves` (1 to 4) layers, each
     * half the cell and `noiseRoughness` as strong as the one before; `noiseSeed` picks the pattern (one per stroke).
     */
    float noiseScale = 8.0f;
    int noiseOctaves = 2;
    float noiseRoughness = 0.5f;
    std::uint32_t noiseSeed = 0;
    /** Water erode: where this step's droplets start and how it rounds (the caller changes it every step). */
    std::uint32_t seed = 1;
    /** Limits: only samples between these heights (height words), and only where the slope (rise over run) is at most
     * this. */
    bool limitHeight = false;
    float limitLow = 0.0f;
    float limitHigh = 65535.0f;
    bool limitSlope = false;
    float limitMaxSlope = 1.0f;
  };

  /** The plane through three points (x, height words, z); false when they are on one line (seen from above). */
  bool PlaneThrough(
    const double (&x)[3],
    const double (&h)[3],
    const double (&z)[3],
    double& planeX,
    double& planeZ,
    double& planeC
  );

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
   * covers takes TurnedHeight. A turn of 4 copies lands on samples and is exact. The diagonal and turn modes on a map
   * that isn't square fall back to no symmetry.
   */
  std::vector<SampleRect> ApplyHeightBrush(
    std::uint16_t* heights,
    int width,
    int height,
    float x,
    float z,
    const HeightBrush& brush,
    float seconds,
    ErosionStroke* stroke = nullptr
  );

  /** The rectangles `ApplyHeightBrush` would write for the same arguments, without writing (undo saves them first). */
  std::vector<SampleRect> HeightBrushRects(int width, int height, float x, float z, const HeightBrush& brush);

  /** The brush's centre and its symmetric copies (the cursor's first), as the brush paints them. */
  int HeightBrushCentres(
    int width,
    int height,
    float x,
    float z,
    Symmetry symmetry,
    int turns,
    float (&outX)[kMaxSymmetryCopies],
    float (&outZ)[kMaxSymmetryCopies]
  );

  /**
   * The symmetric copies of sample (x, z), itself first (the group, with repeats where copies coincide).
   * N-way turns give the nearest samples to the turned points.
   */
  int SymmetricSamples(
    Symmetry symmetry,
    int turns,
    int width,
    int height,
    int x,
    int z,
    int (&outX)[kMaxSymmetryCopies],
    int (&outZ)[kMaxSymmetryCopies]
  );

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
