#pragma once

#include "editor/tools/EdHeightBrush.h"

#include <cstdint>
#include <vector>

namespace faf::editor
{
  /**
   * Terrain paths (FAF Studio's paths.lua): a Catmull-Rom curve through picked points shapes the ground along it, as
   * wide as asked, its edge fading over the falloff. The Ramp tool is a path of two points.
   */
  enum class PathMode
  {
    /** Down by the depth from the path's own level (the ground under its points), never up: a trench. */
    Carve,
    /** Up by the depth from the path's level, never down: a dyke. */
    Raise,
    /** To the first point's height all along: a flat road. */
    Level,
    /** To the path's level, which runs from point to point: a road that climbs. */
    Ramp,
    /** A rounded bed the depth deep in the middle, never up: a river. */
    River,
  };
  inline constexpr int kPathModeCount = 5;
  [[nodiscard]] const char* PathModeName(PathMode mode);

  struct TerrainPathPoint
  {
    float x = 0.0f;
    float z = 0.0f;
    /** The ground's height there in game units (the path's level runs through these). */
    float height = 0.0f;
  };

  struct PathOptions
  {
    PathMode mode = PathMode::Ramp;
    /** The full width in game units (the brush's diameter). */
    float width = 16.0f;
    /** The share of the half width that fades out at each side (0: a hard edge). */
    float falloff = 0.5f;
    /** Carve, Raise and River: how deep or high, in game units. */
    float depth = 4.0f;
    /** Back from the last point to the first. */
    bool closed = false;
  };

  /** Points along the curve, about `step` game units apart (the given points among them); heights in between. */
  [[nodiscard]] std::vector<TerrainPathPoint>
  SamplePath(const std::vector<TerrainPathPoint>& points, bool closed, float step);

  /** The samples the path can change (its points' box grown by half its width), clipped to the field. */
  [[nodiscard]] SampleRect
  PathRect(int width, int height, const std::vector<TerrainPathPoint>& points, const PathOptions& o);

  /**
   * Shapes `heights` (the field's words, `width` x `height`, 1/128 of a game unit) along the path. Returns the
   * rectangle it wrote (empty: x1 < x0 when nothing changed).
   */
  SampleRect ApplyTerrainPath(
    std::uint16_t* heights,
    int width,
    int height,
    const std::vector<TerrainPathPoint>& points,
    const PathOptions& options
  );

  /** What a stroke did to the ground, in game units: from a stroke's before and after words. */
  struct HeightChange
  {
    std::size_t samples = 0;
    /** Ground taken away and put down, each in cubic game units (a sample is one square unit). */
    double removed = 0.0;
    double added = 0.0;
    float deepest = 0.0f;
    float highest = 0.0f;
  };
  void AddHeightChange(HeightChange& change, std::uint16_t before, std::uint16_t after);
} // namespace faf::editor
