#pragma once

#include "editor/tools/EdAlphaGen.h"
#include "editor/tools/EdMapLayout.h"
#include "editor/graph/EdNodeGraph.h"
#include "editor/terrain/EdFieldCore.h"
#include "editor/tools/EdRecipes.h"

#include <array>
#include <cstdint>
#include <functional>
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
    /** A colour: four 0..1 fields, red, green, blue and alpha (the colour ramp's rgba). */
    std::shared_ptr<const std::array<field::GridPtr, 4>> color;
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
    bool waterOn = false;
    /** The map's paint: which layer holds which kind of ground (the stratum recipes' plan), the layers with a texture.
     */
    RecipePlan plan;
    std::array<bool, 9> textured{};
    bool hasPaint = false; // the masks can be written (a map is open)
    /** The terrain shader: the layers it paints, PBR, height splatting, side-mapped layers 3 and 4, the map-wide
     * pictures it reads, a roughness multiplier in layer 8. */
    int painted = 8;
    bool pbr = false;
    bool splat = false;
    bool biplanar = false;
    bool macro = false;
    bool specular = false;
    bool roughness = false;
    /** The map's sun (degrees towards it: azimuth 0 = +x, 90 = +z; altitude above the horizon), its brightness, the
     * sun, ambient and shadow fill colours. */
    float sunAzimuth = 315.0f;
    float sunAltitude = 40.0f;
    float lightMultiplier = 1.0f;
    std::array<float, 3> sunColour{1.0f, 1.0f, 1.0f};
    std::array<float, 3> ambient{0.0f, 0.0f, 0.0f};
    std::array<float, 3> shadowFill{0.0f, 0.0f, 0.0f};
    /**
     * Heights from another tool over the whole map, in map units (`file` empty: the Import / Export window's file),
     * mapped as that window says; false with `error` when there is none or it can't be read. `externalKey` changes when
     * the window's file, its stamp or the mapping does.
     */
    std::function<bool(const std::string& file, field::Grid& out, std::string& error)> loadExternal;
    std::string externalKey;
    /**
     * The Layout workspace's drawing (null: none) for the Map layout nodes, a key that changes with it and the editor's
     * symmetry, and that symmetry as the symmetrize op's mode ("" none) about the map's middle.
     */
    const MapLayout* layout = nullptr;
    std::string layoutKey;
    std::string layoutSymmetry;
    int layoutTurns = 3;
    /**
     * The symmetry of what the graph writes (GraphSymmetryChoices: "map" follows the editor's, `layoutSymmetry`; "off"
     * none): the height outputs, the paint and the terrain types are made symmetric where the graph writes them, so
     * nodes after a Symmetrize node (erosion, noise) can't break it.
     */
    std::string graphSymmetry = "off";
  };

  /** FAF Studio's gensym choices: the setting's id and its label. */
  struct GraphSymmetryChoice
  {
    const char* id;
    const char* label;
  };
  [[nodiscard]] const std::vector<GraphSymmetryChoice>& GraphSymmetryChoices();
  /** The symmetrize op's mode and turns a setting gives on `ground` (false: none). */
  bool ResolveGraphSymmetry(const std::string& setting, const TerrainGround& ground, std::string& mode, int& turns);

  /** The eight kinds of ground by the names graph files use, bottom to top, with their roughness (0 shiny .. 1 rough).
   */
  struct TerrainKind
  {
    const char* id;
    GroundKind kind;
    float roughness;
  };
  [[nodiscard]] const std::vector<TerrainKind>& TerrainKinds();
  /** The bands that split a kind between its layers (`rock2` is rock's second layer). */
  struct TerrainKindVariant
  {
    const char* id;
    GroundKind kind;
    int layer; // 1: the kind's second layer
  };
  [[nodiscard]] const std::vector<TerrainKindVariant>& TerrainKindVariants();

  struct TerrainReport
  {
    int evaluated = 0;
    int cached = 0;
    double ms = 0.0;
    std::map<int, std::string> errors; // by node id: the node's own error (not one passed on from upstream)
  };

  struct TerrainBuildWrites;

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
    /**
     * What the graph's Output: ground kinds node paints, as the recipes resolve it: the visible weight of every layer
     * (layer -> field on this run's grid, `heights` its shape), overlaps settled by the kinds' priority, the base layer
     * what is left, the layers of a kind with no link cleared. False (and `error` empty) when the graph has none.
     */
    /** Everything a Build writes besides the heights (`heights`: the run's grid, for the kinds' resolution). False with
     * `error` when the ground kinds can't be resolved. */
    bool BuildWrites(
      const NodeGraph& graph,
      const TerrainGround& ground,
      const field::Grid& heights,
      TerrainBuildWrites& writes,
      std::string& error
    ) const;
    bool KindsPaint(
      const NodeGraph& graph,
      const TerrainGround& ground,
      const field::Grid& heights,
      std::map<int, field::Grid>& target,
      std::string& error
    ) const;

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
    int mSeed = 1; // the graph's seed of the last Evaluate
    std::map<int, Entry> mCache;
    std::uint64_t mVersion = 0;
    field::GridPtr mLike;
    std::string mLikeKey;
    field::GridPtr mBase;
    std::uint64_t mBaseRevision = ~0ULL;
  };

  /** What a Build writes besides the heights, from the graph's paint and terrain type outputs. */
  struct TerrainBuildWrites
  {
    /** Output: ground kinds as the recipes resolve it (layer -> visible weight on the run's grid). */
    std::map<int, field::Grid> kinds;
    /** Output: ground kinds' "Set the terrain types too": the types follow what the paint shows most. */
    bool kindsTypes = false;
    std::array<bool, 9> textured{};
    int cap = 8;
    /** Output: texture layer and Output: ground kind, in node order: a mask into one layer (1..8). */
    struct Layer
    {
      field::Grid mask;
      int layer = 1;
      MaskWriteMode mode = MaskWriteMode::Replace;
      float strength = 1.0f;
      bool takeAway = false;
    };
    std::vector<Layer> layers;
    /** Output: terrain type: the code where the mask is above the threshold. */
    struct Types
    {
      field::Grid mask;
      int code = 0;
      float threshold = 0.5f;
    };
    std::vector<Types> types;
    /** Output: scatter props: points no nearer than the spacing where the density mask (none: everywhere) allows. */
    struct Scatter
    {
      field::Grid density;                              // no samples: 1 everywhere
      std::vector<std::pair<std::string, int>> entries; // blueprint and weight; empty: the Props tool's list or prop
      int count = 800;
      float minDist = 6.0f;
      float fill = 1.0f;
      float slopeMax = 35.0f; // degrees
      float scaleMin = 0.8f;
      float scaleMax = 1.2f;
      float margin = 4.0f;
      bool underWater = false;
      std::uint32_t seed = 1;
      /** Decals instead of props: `entries` are decal textures (none: the Decals tool's), the scale a share of the
       * Decals tool's size. */
      bool decals = false;
    };
    std::vector<Scatter> scatters;
    /** The map-wide textures to make from the built map: 0 normals, 1 lighting, 2 specular, 3 macro (MapTextureKind).
     */
    std::vector<int> mapTextures;
    /** Output: roughness / height atlas: made from the layers' textures and kinds into the Upper layer (Terrain1xx /
     * 2xx), with the Terrain2xx splat softness / contrast (0: leave the map's). */
    bool atlas = false;
    AtlasSettings atlasSettings;
    int atlasSize = 1024;
    float splatSoft = 0.0f;
    float splatContrast = 0.0f;
    /** Outputs left out, with why ("Output: ground kind (snow): no layer holds snow"). */
    std::vector<std::string> notes;
    [[nodiscard]] bool Empty() const noexcept
    {
      return kinds.empty() && layers.empty() && types.empty() && scatters.empty() && mapTextures.empty() && !atlas;
    }
  };

  /** A graph file of FAF Studio (`graphpresets/*.lua`, `Graph = { ... }`) read into `graph` with its node ids. */
  struct StudioGraphFacts
  {
    std::string name;
    int seed = 1;
    std::string symmetry = "map";          // the graph's symmetry setting (GraphSymmetryChoices' ids)
    std::vector<std::string> unknownTypes; // node types this editor doesn't have (those nodes are left out)
    int droppedLinks = 0;                  // links to or from left-out nodes or unknown pins
  };
  bool ReadStudioGraph(const std::string& text, NodeGraph& graph, StudioGraphFacts& facts, std::string& error);

  /** The graphs the editor ships (Studio's graphpresets with their index): id, title, what it makes, the file. */
  struct ShippedGraph
  {
    std::string id;
    std::string name;
    std::string note;
    bool library = false; // a competitive layout (Studio's library graphs)
    std::string text;     // the graph file
  };
  [[nodiscard]] const std::vector<ShippedGraph>& ShippedTerrainGraphs();
  /** The files built into the editor (a generated source): file name and text. */
  [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& EmbeddedTerrainGraphFiles();

  /** The editor's own graph file (`.fafgraph.json`): the node graph with the graph's seed and name. */
  [[nodiscard]] std::string
  SaveTerrainGraph(const NodeGraph& graph, int seed, const std::string& name, const std::string& symmetry = "map");
  /** `symmetry` (when given) gets the saved setting, "map" for a file without one. */
  bool LoadTerrainGraph(
    const std::string& text,
    NodeGraph& graph,
    int& seed,
    std::string& name,
    std::string& error,
    std::string* symmetry = nullptr
  );

  /** A node's parameter by name as the evaluations read it (numbers, a choice's id, text). */
  [[nodiscard]] double TerrainParamNumber(const GraphNode& node, const std::string& name, double fallback);
  [[nodiscard]] std::string TerrainParamText(const GraphNode& node, const std::string& name);
} // namespace faf::editor
