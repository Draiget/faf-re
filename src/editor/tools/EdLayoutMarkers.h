#pragma once

#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The start and resource generator (FAF Studio's layoutmarkers.lua): start positions from the map's start markers,
   * from the bases drawn in the layout or from a pattern, and Mass and Hydrocarbon markers around each start by shape
   * and distance:
   *   ring     evenly around the start, the distances alternating between the nearest and the farthest
   *   arc      a fan of the given width, facing the middle of the map (or away from it)
   *   cluster  a sunflower of points at the middle of the distance range in the facing direction
   *   line     a row across the facing direction
   *   pairs    ring positions with two markers side by side
   * Every start gets the same shape turned to face the middle, so symmetric starts get symmetric resources. A spot is
   * checked against the ground (inside the playable area, above the water, a slope the limit allows) and the other
   * markers (the spacing); one that fails is searched around and skipped when nothing fits.
   */
  enum class LayoutStartMode
  {
    Existing,
    Bases,
    Pattern,
  };
  enum class LayoutPattern
  {
    Ring,
    Corners,
    Sides,
    Line,
  };
  enum class LayoutShape
  {
    Ring,
    Arc,
    Cluster,
    Line,
    Pairs,
  };

  [[nodiscard]] const char* LayoutShapeName(LayoutShape shape);
  [[nodiscard]] const char* LayoutPatternName(LayoutPattern pattern);

  struct LayoutMarkerSettings
  {
    LayoutStartMode starts = LayoutStartMode::Pattern;
    LayoutPattern pattern = LayoutPattern::Ring;
    int count = 4;
    float radius = 0.68f;  // share of the half area
    float rotation = 0.0f; // degrees
    bool replaceStarts = true;
    int mass = 6;
    float massMin = 16.0f;
    float massMax = 30.0f;
    LayoutShape massShape = LayoutShape::Ring;
    float arc = 160.0f; // degrees
    bool facingAway = false;
    int hydro = 1;
    float hydroMin = 36.0f;
    float hydroMax = 48.0f;
    int extra = 4;
    float extraMin = 70.0f;
    float extraMax = 110.0f;
    LayoutShape extraShape = LayoutShape::Arc;
    int middle = 4;
    float middleRadius = 40.0f;
    float spacing = 7.0f;
    float maxSlope = 30.0f; // degrees
    int seed = 1;
    bool clear = true; // the markers made the last time are replaced
  };

  struct LayoutPoint
  {
    float x = 0.0f;
    float z = 0.0f;
    std::string name;
  };

  /** What the checks read: the playable area, the ground height at a point, the water level (below the ground for
   * none). */
  struct LayoutGround
  {
    float x0 = 0.0f;
    float z0 = 0.0f;
    float x1 = 256.0f;
    float z1 = 256.0f;
    std::function<float(float x, float z)> height;
    float water = -1000.0f;
  };

  struct LayoutMarkerItem
  {
    bool hydro = false;
    float x = 0.0f;
    float z = 0.0f;
    int start = 0;     // 1-based; 0 for the middle
    std::string group; // hydro, mass, extra, middle
  };

  struct LayoutMarkerPlan
  {
    std::vector<LayoutPoint> starts;
    std::vector<LayoutMarkerItem> items;
    int failed = 0;
    int masses = 0;
    int hydros = 0;
    std::string text;
  };

  /** The start positions the settings give (`existing`: the map's start markers; `bases`: the layout's base
   * centres). */
  [[nodiscard]] std::vector<LayoutPoint> LayoutStarts(
    const LayoutMarkerSettings& settings,
    const LayoutGround& ground,
    const std::vector<LayoutPoint>& existing,
    const std::vector<LayoutPoint>& bases
  );

  /** The ideal positions of `count` markers around (sx, sz) facing `facing` (radians). */
  [[nodiscard]] std::vector<LayoutPoint> LayoutShapePoints(
    LayoutShape shape,
    float sx,
    float sz,
    float facing,
    int count,
    float dmin,
    float dmax,
    float arc,
    float spacing
  );

  /**
   * The plan: `starts` (from LayoutStarts) and the resources around them; `occupied` are the resource markers that
   * stay (each keeps the spacing free around it). Nothing is placed.
   */
  [[nodiscard]] LayoutMarkerPlan PlanLayoutMarkers(
    const LayoutMarkerSettings& settings,
    const LayoutGround& ground,
    const std::vector<LayoutPoint>& starts,
    const std::vector<LayoutPoint>& occupied
  );
} // namespace faf::editor
