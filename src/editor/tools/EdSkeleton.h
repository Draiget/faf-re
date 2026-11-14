#pragma once

// The map skeleton generator (FAF Studio's skeleton.lua, TERRAIN_GEN_DESIGN.md stage T6): from the start positions and
// a lane style it lays down kept paths (EdKeptPaths) and base pads (EdScTools' pad_flatten). Everything it makes is an
// ordinary path the mapper edits and applies again afterwards; Generate replaces an earlier skeleton (paths tagged
// `skeleton`), Apply all puts the pads and the paths on the map as one undo step.
//
//   styles    open     wide level lanes (ramp paths pinned to the base heights, grade limited) between the bases
//             ridge    the same lanes with a raised wall along both sides
//             ramps    every base on a plateau (a pad at an absolute height) with ramps down to the lane level; the
//             lane
//                      between two bases narrows to a choke in the middle
//             islands  every base on an island inside a carved moat; narrow causeways join the islands
//   topology  ring (each base to its neighbours around the middle), hub (every base to a plaza in the middle), both
//
// Engine independent (tests/editor/SkeletonTests.cpp).

#include "editor/tools/EdKeptPaths.h"
#include "editor/tools/EdScTools.h"

#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  enum class SkeletonStyle : std::uint8_t
  {
    Open,
    Ridge,
    Ramps,
    Islands,
  };
  [[nodiscard]] const char* SkeletonStyleName(SkeletonStyle style) noexcept;
  [[nodiscard]] const char* SkeletonStyleId(SkeletonStyle style) noexcept;

  enum class SkeletonTopology : std::uint8_t
  {
    Ring,
    Hub,
    Both,
  };
  [[nodiscard]] const char* SkeletonTopologyName(SkeletonTopology topology) noexcept;

  struct SkeletonSettings
  {
    SkeletonStyle style = SkeletonStyle::Open;
    SkeletonTopology topology = SkeletonTopology::Ring;
    int lanes = 1;          // parallel lanes per connection
    float laneWidth = 9.0f; // half width of a lane
    float laneFalloff = 7.0f;
    float laneGrade = 0.5f; // maximum grade of a lane (rise per run)
    float bend = 14.0f;     // how far a lane bows away from the straight line
    float ridgeHeight = 9.0f;
    float ridgeWidth = 5.0f;
    float ridgeGap = 3.0f;
    float plateau = 7.0f;
    float plateauHalf = 14.0f;
    float rampWidth = 6.0f;
    float chokeWidth = 4.0f;
    float islandRadius = 26.0f;
    float moatWidth = 16.0f;
    float moatDepth = 5.0f;
    float bridgeWidth = 4.0f;
    float hubHalf = 8.0f;
    bool pads = true;   // the base pads (and plateaus, plaza) go down first
    bool smooth = true; // Apply all: the pathable slope limit over the lane corridors at the end
  };

  struct SkeletonStart
  {
    std::string name; // ARMY_n
    float x = 0.0f;
    float z = 0.0f;
  };

  /** The start positions among the markers (`ARMY_<n>`), by their number. */
  [[nodiscard]] std::vector<SkeletonStart> SkeletonStarts(const std::vector<PadMarker>& markers);

  /** A connection between two bases (or a base and the hub). */
  struct SkeletonNode
  {
    std::string name;
    float x = 0.0f;
    float z = 0.0f;
    bool hub = false;
  };
  struct SkeletonConnection
  {
    SkeletonNode a;
    SkeletonNode b;
  };
  /** The connections of the topology (bases sorted by their angle round the middle) and the hub (their middle). */
  [[nodiscard]] std::vector<SkeletonConnection>
  SkeletonConnections(const std::vector<SkeletonStart>& starts, SkeletonTopology topology, SkeletonNode& hub);

  /** The pads the skeleton puts down: the start pads (plateaus in the ramps style) and the hub's plaza. */
  [[nodiscard]] std::vector<Pad> SkeletonPads(
    const std::vector<SkeletonStart>& starts,
    const SkeletonSettings& settings,
    const PadSettings& padSettings,
    const std::function<float(float, float)>& ground
  );

  /**
   * The skeleton's paths, in the order they are applied, with fresh ids from `ids`. `ground` is the ground after the
   * pads (the base heights the lanes are pinned to); `water` the sea level (moats).
   */
  [[nodiscard]] std::vector<KeptPath> SkeletonPaths(
    const std::vector<SkeletonStart>& starts,
    const SkeletonSettings& settings,
    const PadSettings& padSettings,
    const std::vector<Pad>& pads,
    const std::function<float(float, float)>& ground,
    float water,
    KeptPathSet& ids
  );
} // namespace faf::editor
