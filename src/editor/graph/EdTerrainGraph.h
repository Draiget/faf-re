#pragma once

#include "editor/graph/EdNodeGraph.h"
#include "editor/terrain/EdFieldCore.h"

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The terrain graph (the consolidated design's Generate workspace; FAF Studio's graphnodes.lua and graphrun.lua):
   * node types whose evaluations run the field library's ops, a run that evaluates a graph at full resolution or on
   * every step-th sample (the preview) and keeps each node's result while its parameters and inputs stay the same, the
   * heights the outputs make, and Studio's graph files (a Lua table) read into a NodeGraph with their ids.
   */

  /** The registry of the terrain node types (built once). */
  [[nodiscard]] const NodeTypeRegistry& TerrainNodeTypes();

  /** A palette group's title by the category id the node types carry ("gen" -> "Generators"), in palette order. */
  [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& TerrainCategories();

  /** A path made by the Path nodes: control points in map units with their width, falloff and height. */
  struct TerrainPath
  {
    struct Point
    {
      float x = 0.0f;
      float z = 0.0f;
      float width = 6.0f;
      float falloff = 4.0f;
      float height = 0.0f;
    };
    std::vector<Point> points;
    bool closed = false;
    std::string mode = "carve";
    std::string profile = "u";
  };

  /** What flows along a link: a field (height or mask), a number or a path. */
  struct TerrainValue
  {
    field::GridPtr grid;
    double number = 0.0;
    bool isNumber = false;
    std::shared_ptr<const TerrainPath> path;
  };

  /** The map a run works on: its heights (map units, (width) x (height) samples a unit apart) and what nodes read. */
  struct TerrainGround
  {
    int width = 0; // samples (the map's size in units + 1)
    int height = 0;
    std::shared_ptr<const std::vector<float>> heights;
    /** Changes whenever the heights do (a node reading the map caches against it). */
    std::uint64_t revision = 0;
    float water = 0.0f;
    /** The markers' pads (x, z, half, skirt, height, group per pad), as the SC tools collect them. */
    std::vector<double> pads;
    std::string padSignature;
  };

  struct TerrainReport
  {
    int evaluated = 0;
    int cached = 0;
    double ms = 0.0;
    std::map<int, std::string> errors; // by node id: the node's own error (not one passed on from upstream)
  };

  /**
   * A run of a graph on one grid: step 1 is the map's own samples, a larger step every step-th one. Each node's result
   * is kept with a key of its parameters, the versions of its inputs and the grid, so evaluating again after a change
   * re-runs only the nodes it reaches.
   */
  class TerrainRun
  {
  public:
    explicit TerrainRun(
      const int step = 1
    )
      : mStep(step < 1 ? 1 : step)
    {}
    [[nodiscard]] int Step() const noexcept
    {
      return mStep;
    }
    void SetStep(int step);

    /** Every node (or the ones `only` names) in order; `seed` is the graph's. */
    TerrainReport
    Evaluate(const NodeGraph& graph, int seed, const TerrainGround& ground, const std::set<int>* only = nullptr);

    /** A node's output by its pin name (nullptr: none, or the node failed). */
    [[nodiscard]] const TerrainValue* Value(int node, const std::string& pin) const;
    /** A node's error (its own or one upstream), empty when it ran. */
    [[nodiscard]] std::string Error(int node) const;
    /** How long a node took the last time it ran (ms). */
    [[nodiscard]] double NodeMs(int node) const;
    /** The value an input of a node gets now (through its link), nullptr when nothing is linked or it has no value. */
    [[nodiscard]] const TerrainValue* Input(const NodeGraph& graph, int node, const std::string& pin) const;

    /**
     * The heights the graph's height outputs make on this run's grid: the map's heights with every enabled output
     * folded in, in node order (replace, add with a gain, or blend; a strength and an optional mask). False when the
     * graph has no height output with a value. `plain` says the result is a plain replace (else a coarse preview is
     * applied as a change, not as the new ground).
     */
    bool FinalHeight(const NodeGraph& graph, const TerrainGround& ground, field::Grid& out, bool* plain = nullptr);

    void Clear();

  private:
    struct Entry
    {
      std::string key;
      std::uint64_t version = 0;
      std::map<std::string, TerrainValue> outs;
      std::string error;
      bool upstream = false;
      double ms = 0.0;
    };
    field::GridPtr Like(const TerrainGround& ground);
    field::GridPtr BaseHere(const TerrainGround& ground);

    int mStep = 1;
    std::map<int, Entry> mCache;
    std::uint64_t mVersion = 0;
    field::GridPtr mLike;
    std::string mLikeKey;
    field::GridPtr mBase;
    std::uint64_t mBaseRevision = ~0ULL;
  };

  /** A graph file of FAF Studio (`graphpresets/*.lua`, `Graph = { ... }`) read into `graph` with its node ids. */
  struct StudioGraphFacts
  {
    std::string name;
    int seed = 1;
    std::vector<std::string> unknownTypes; // node types this editor doesn't have (those nodes are left out)
    int droppedLinks = 0;                  // links to or from left-out nodes or unknown pins
  };
  bool ReadStudioGraph(const std::string& text, NodeGraph& graph, StudioGraphFacts& facts, std::string& error);

  /** A node's parameter by name as the evaluations read it (numbers, a choice's id, text). */
  [[nodiscard]] double TerrainParamNumber(const GraphNode& node, const std::string& name, double fallback);
  [[nodiscard]] std::string TerrainParamText(const GraphNode& node, const std::string& name);
} // namespace faf::editor
