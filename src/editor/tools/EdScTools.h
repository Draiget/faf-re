#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * SC tools (the consolidated design's Terrain > SC tools; FAF Studio's sctools.lua over the field library's
   * terrain/EdFieldSc.cpp): flat base pads and resource rings under the markers, re-applied as markers move; the
   * pathable slope limit with each unit class's blocked share; and the grade along a route.
   */
  struct PadSettings
  {
    bool startPads = true;
    float startHalf = 8.0f;
    float startSkirt = 10.0f;
    bool massPads = true;
    float massHalf = 2.0f;
    float massSkirt = 4.0f;
    bool hydroPads = true;
    float hydroHalf = 4.0f;
    float hydroSkirt = 5.0f;
    bool ring = true; // mass and hydro within ringRadius of a start share its pad's height (a resource ring)
    float ringRadius = 30.0f;
    bool cluster = true; // other resources closer than clusterDist share one height
    float clusterDist = 16.0f;
    int level = 0; // a pad's height: 0 the mean of its core, 1 the lowest, 2 the highest
    float strength = 1.0f;
    bool autoApply = false; // re-apply when a marker moved
  };

  /** A marker a pad can belong to: a start (`ARMY_n`), a mass or a hydrocarbon point. */
  struct PadMarker
  {
    std::string name;
    std::string type; // the marker's type ("Mass", "Hydrocarbon", "Blank Marker")
    float x = 0.0f;
    float z = 0.0f;
  };

  struct Pad
  {
    std::string name;
    enum class Kind
    {
      Start,
      Mass,
      Hydro,
    } kind = Kind::Start;
    float x = 0.0f;
    float z = 0.0f;
    float half = 0.0f;
    float skirt = 0.0f;
    int group = 0; // 0: its own height; k >= 1: the height shared with the others of group k
  };

  /**
   * The pads the markers ask for, by name order: starts first, then hydrocarbons, then mass. Each resource within the
   * ring radius of a start joins that start's group; the rest of a kind closer than the cluster distance to each other
   * share a group of their own (two or more); the others keep their own height.
   */
  [[nodiscard]] std::vector<Pad> CollectPads(const std::vector<PadMarker>& markers, const PadSettings& settings);

  /** What the pads were made from: changes when a marker moves or a setting changes (not when the ground does). */
  [[nodiscard]] std::string PadSignature(const std::vector<Pad>& pads, const PadSettings& settings);

  /** The last Apply's change: its rect of samples (inclusive) and the height it added there (map units). */
  struct PadResult
  {
    int x0 = 0, z0 = 0, x1 = -1, z1 = -1;
    std::vector<float> delta;
    std::string signature;
    [[nodiscard]] bool Empty() const noexcept
    {
      return x1 < x0 || z1 < z0;
    }
  };

  /**
   * The pads flattened into the height words (pad_flatten, quantised to a word), the previous result taken off first
   * so the call replaces it. `result` is the new change; returns the samples changed, -1 with `error`.
   */
  int ApplyPads(
    std::uint16_t* heights,
    int width,
    int height,
    float scale,
    const std::vector<Pad>& pads,
    const PadSettings& settings,
    const PadResult& previous,
    PadResult& result,
    std::string& error
  );
  /** A result taken off again; returns the samples changed. */
  int RemovePads(std::uint16_t* heights, int width, int height, float scale, const PadResult& result);

  /** The unit classes the slope report counts for: their footprint (window) in cells. */
  struct SlopeClass
  {
    const char* name;
    int window;
  };
  [[nodiscard]] const std::vector<SlopeClass>& SlopeClasses();

  /** The share (0..1) of the ground each unit class can't cross: its slope rating over `limit` (0.75 for land). */
  [[nodiscard]] std::vector<float>
  BlockedShares(const std::uint16_t* heights, int width, int height, float scale, float limit);

  struct SlopeLimitSettings
  {
    float limit = 0.75f;
    std::string mode = "both"; // "lower", "raise" or "both"
    float balance = 0.5f;
    float margin = 0.03f;
    float strength = 1.0f;
  };
  /** The steepest neighbour difference clamped to the limit (slope_limit, quantised); returns the samples changed. */
  int LimitSlopes(
    std::uint16_t* heights,
    int width,
    int height,
    float scale,
    const SlopeLimitSettings& settings,
    std::string& error
  );

  /** The grade along a route: its length, steepest and mean grade, the share over the limit and where. */
  struct RampReport
  {
    float length = 0.0f;
    float maxGrade = 0.0f;
    float meanGrade = 0.0f;
    float over = 0.0f; // share of the length steeper than the limit
    float minHeight = 0.0f;
    float maxHeight = 0.0f;
    struct Run
    {
      float from = 0.0f; // distance along the route
      float to = 0.0f;
      float x = 0.0f; // the steepest point of the stretch
      float z = 0.0f;
      float grade = 0.0f;
    };
    std::vector<Run> runs; // the stretches over the limit
  };
  /** Sampled every `step` units, the grade (rise over `run` units, centred) along the polyline. */
  [[nodiscard]] RampReport RampProfile(
    const std::uint16_t* heights,
    int width,
    int height,
    float scale,
    const std::vector<std::pair<float, float>>& points,
    float step = 1.0f,
    float run = 3.0f,
    float limit = 0.75f
  );
} // namespace faf::editor
