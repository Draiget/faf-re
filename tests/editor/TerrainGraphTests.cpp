// The terrain graph (src/editor/graph/EdTerrainGraph.cpp, EdTerrainNodes.cpp): the node catalogue, a FAF Studio graph
// file read with its ids, a run on a small map at full and preview resolution, the cache re-running only what a
// change reaches, number pins driving parameters, and the errors a node shows.

#include "editor/graph/EdTerrainGraph.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <string>

namespace
{
  using faf::editor::LinkResult;
  using faf::editor::NodeGraph;
  using faf::editor::ParamValue;
  using faf::editor::ReadStudioGraph;
  using faf::editor::StudioGraphFacts;
  using faf::editor::TerrainGround;
  using faf::editor::TerrainNodeTypes;
  using faf::editor::TerrainRun;
  namespace field = faf::editor::field;

  std::string ReadFile(
    const char* path
  )
  {
    std::ifstream in(path, std::ios::binary);
    std::stringstream text;
    text << in.rdbuf();
    return text.str();
  }

  /** A 129 x 129 map: a gentle slope from 20 to 30 units. */
  TerrainGround Ground(
    const std::uint64_t revision = 1
  )
  {
    TerrainGround ground;
    ground.width = 129;
    ground.height = 129;
    auto heights = std::make_shared<std::vector<float>>(129 * 129);
    for (int z = 0; z < 129; ++z) {
      for (int x = 0; x < 129; ++x) {
        (*heights)[static_cast<std::size_t>(z * 129 + x)] = 20.0f + 10.0f * static_cast<float>(x) / 128.0f;
      }
    }
    ground.heights = heights;
    ground.revision = revision;
    ground.water = 17.5f;
    return ground;
  }

  int PinOf(
    const std::vector<faf::editor::PinDef>& pins,
    const char* name
  )
  {
    for (std::size_t i = 0; i < pins.size(); ++i) {
      if (pins[i].name == name) {
        return static_cast<int>(i);
      }
    }
    return -1;
  }

  std::size_t ParamOf(
    const faf::editor::NodeType& type,
    const char* name
  )
  {
    for (std::size_t i = 0; i < type.params.size(); ++i) {
      if (type.params[i].name == name) {
        return i;
      }
    }
    return type.params.size();
  }

  TEST(
    TerrainGraph,
    CatalogueHasTheNodesAndTheirNumberPins
  )
  {
    const auto& registry = TerrainNodeTypes();
    EXPECT_GE(registry.All().size(), 70U) << "the core nodes and a generic node per other field op";
    for (const char* name :
         {"terrain",
          "perlin",
          "ridged",
          "range",
          "blend",
          "erode_hydraulic",
          "erode_droplet",
          "erode_stream",
          "flatten",
          "landform",
          "pad_flatten",
          "symmetrize",
          "slope_limit",
          "out_height",
          "number",
          "math"}) {
      EXPECT_NE(registry.Find(name), nullptr) << name;
    }
    // A number that can be driven has an input pin of its name.
    const auto* range = registry.Find("range");
    ASSERT_NE(range, nullptr);
    EXPECT_GE(PinOf(range->inputs, "hi"), 0);
    EXPECT_EQ(range->inputs[static_cast<std::size_t>(PinOf(range->inputs, "hi"))].type, faf::editor::PinType::Number);
    // Heights and masks link freely; a number doesn't link into a field.
    EXPECT_TRUE(faf::editor::PinsCompatible(faf::editor::PinType::Mask, faf::editor::PinType::Height));
    EXPECT_FALSE(faf::editor::PinsCompatible(faf::editor::PinType::Number, faf::editor::PinType::Height));
  }

  TEST(
    TerrainGraph,
    ReadsAStudioGraphWithItsIds
  )
  {
    NodeGraph graph(TerrainNodeTypes());
    StudioGraphFacts facts;
    std::string error;
    ASSERT_TRUE(ReadStudioGraph(ReadFile(FAF_TERRAIN_GRAPHS "/hills.lua"), graph, facts, error)) << error;
    EXPECT_EQ(facts.name, "Rolling hills (two noises, hydraulic erosion)");
    EXPECT_EQ(facts.seed, 4);
    // Every node, with Studio's ids: the height chain and the texturing (ground kinds into their output).
    EXPECT_EQ(graph.Nodes().size(), 9U);
    EXPECT_TRUE(facts.unknownTypes.empty());
    ASSERT_NE(graph.Find(11), nullptr);
    EXPECT_EQ(graph.Find(11)->type->name, "flatten");
    EXPECT_FLOAT_EQ(graph.Find(4)->params[ParamOf(*graph.Find(4)->type, "hi")].value[0], 62.0f);
    EXPECT_EQ(faf::editor::TerrainParamText(*graph.Find(3), "mode"), "normal") << "a choice by its id";
    EXPECT_EQ(graph.Links().size(), 18U) << "the height chain's 6, the texturing's 12";
    EXPECT_EQ(facts.droppedLinks, 0);
    EXPECT_FALSE(ReadStudioGraph("Graph = { nodes = { { id = 1, ", graph, facts, error));
    EXPECT_NE(error.find("line"), std::string::npos) << error;
  }

  TEST(
    TerrainGraph,
    RunsTheHillsGraphAndCachesWhatDidNotChange
  )
  {
    NodeGraph graph(TerrainNodeTypes());
    StudioGraphFacts facts;
    std::string error;
    ASSERT_TRUE(ReadStudioGraph(ReadFile(FAF_TERRAIN_GRAPHS "/hills.lua"), graph, facts, error)) << error;
    const TerrainGround ground = Ground();
    TerrainRun run(1);
    const auto report = run.Evaluate(graph, facts.seed, ground);
    EXPECT_TRUE(report.errors.empty()) << report.errors.begin()->second;
    EXPECT_EQ(report.evaluated, 9);
    field::Grid heights;
    bool plain = false;
    ASSERT_TRUE(run.FinalHeight(graph, ground, heights, &plain));
    EXPECT_TRUE(plain) << "one output replacing the heights";
    ASSERT_EQ(heights.w, 129);
    const field::Stats stats = field::Measure(heights);
    EXPECT_GT(stats.min, 20.0f) << "the range starts at 28; erosion and flattening take a little";
    EXPECT_LT(stats.max, 66.0f);
    EXPECT_GT(stats.max - stats.min, 5.0f) << "hills, not a plain";
    const std::uint64_t sum = field::Checksum(heights);

    // The same graph in a new run: the same heights.
    TerrainRun again(1);
    (void)again.Evaluate(graph, facts.seed, ground);
    field::Grid second;
    ASSERT_TRUE(again.FinalHeight(graph, ground, second));
    EXPECT_EQ(field::Checksum(second), sum);

    // Nothing changed: everything comes from the cache.
    const auto cached = run.Evaluate(graph, facts.seed, ground);
    EXPECT_EQ(cached.evaluated, 0);
    EXPECT_EQ(cached.cached, 9);

    // The range's top changed: the range and what it feeds run again (range, erosion, flatten, the height output, the
    // ground kinds and their output), the noises and the blend don't.
    ParamValue hi;
    hi.value[0] = 80.0f;
    graph.SetParam(4, ParamOf(*graph.Find(4)->type, "hi"), hi);
    const auto changed = run.Evaluate(graph, facts.seed, ground);
    EXPECT_EQ(changed.evaluated, 6);
    EXPECT_EQ(changed.cached, 3);
    field::Grid higher;
    ASSERT_TRUE(run.FinalHeight(graph, ground, higher));
    EXPECT_GT(field::Measure(higher).max, stats.max);

    // Another graph seed: other noise.
    (void)run.Evaluate(graph, facts.seed + 1, ground);
    field::Grid reseeded;
    ASSERT_TRUE(run.FinalHeight(graph, ground, reseeded));
    EXPECT_NE(field::Checksum(reseeded), field::Checksum(higher));
  }

  TEST(
    TerrainGraph,
    PreviewRunsOnACoarseGrid
  )
  {
    NodeGraph graph(TerrainNodeTypes());
    StudioGraphFacts facts;
    std::string error;
    ASSERT_TRUE(ReadStudioGraph(ReadFile(FAF_TERRAIN_GRAPHS "/hills.lua"), graph, facts, error)) << error;
    const TerrainGround ground = Ground();
    TerrainRun preview(4);
    const auto report = preview.Evaluate(graph, facts.seed, ground);
    EXPECT_TRUE(report.errors.empty());
    field::Grid heights;
    ASSERT_TRUE(preview.FinalHeight(graph, ground, heights));
    EXPECT_EQ(heights.w, 33) << "every fourth sample of 129";
    EXPECT_FLOAT_EQ(heights.cell, 4.0f);
    const field::Stats stats = field::Measure(heights);
    EXPECT_GT(stats.min, 20.0f);
    EXPECT_LT(stats.max, 66.0f);
  }

  TEST(
    TerrainGraph,
    EveryShippedGraphReads
  )
  {
    const auto& shipped = faf::editor::ShippedTerrainGraphs();
    EXPECT_EQ(shipped.size(), 40U) << "Studio's 40 graphs, by its index";
    std::set<std::string> missing;
    int complete = 0;
    for (const auto& entry : shipped) {
      EXPECT_FALSE(entry.name.empty()) << entry.id;
      NodeGraph graph(TerrainNodeTypes());
      StudioGraphFacts facts;
      std::string error;
      ASSERT_TRUE(ReadStudioGraph(entry.text, graph, facts, error)) << entry.id << ": " << error;
      EXPECT_FALSE(graph.Nodes().empty()) << entry.id;
      complete += facts.unknownTypes.empty() ? 1 : 0;
      missing.insert(facts.unknownTypes.begin(), facts.unknownTypes.end());
    }
    std::string list;
    for (const std::string& type : missing) {
      list += " " + type;
    }
    std::printf(
      "[ shipped  ] %d of %zu graphs read whole; node types still to come:%s\n", complete, shipped.size(), list.c_str()
    );
  }

  TEST(
    TerrainGraph,
    EveryNodeTypeRunsOnASmallMap
  )
  {
    // Every node of the palette (not the generic op nodes) fed with hills where it has an `a` pin: none fails. The ones
    // that need more than that are left out: the markers' pads, both slopes of Height from slopes.
    const std::set<std::string> skip = {"pad_flatten", "height_from_gradient", "frame", "path_drawn"};
    const TerrainGround ground = [] {
      TerrainGround g;
      g.width = 65;
      g.height = 65;
      g.heights = std::make_shared<std::vector<float>>(65 * 65, 30.0f);
      g.revision = 1;
      g.water = 20.0f;
      return g;
    }();
    int ran = 0;
    for (const auto& type : TerrainNodeTypes().All()) {
      if (type->category == "raw" || skip.count(type->name) != 0) {
        continue;
      }
      NodeGraph graph(TerrainNodeTypes());
      const int noise = graph.AddNode("perlin", 0, 0);
      const int range = graph.AddNode("range", 200, 0);
      ASSERT_EQ(graph.Link(noise, 0, range, 0), LinkResult::Ok);
      const int node = graph.AddNode(type->name, 400, 0);
      ASSERT_NE(node, 0) << type->name;
      const int a = PinOf(type->inputs, "a");
      if (a >= 0 && type->inputs[static_cast<std::size_t>(a)].type != faf::editor::PinType::Number) {
        ASSERT_EQ(graph.Link(range, 0, node, a), LinkResult::Ok) << type->name;
      }
      // A path into the path nodes.
      if (const int pts = PinOf(type->inputs, "pts"); pts >= 0) {
        const int line = graph.AddNode("path_line", 200, 200);
        ASSERT_EQ(graph.Link(line, 0, node, pts), LinkResult::Ok) << type->name;
      }
      if (type->name == "blend") {
        ASSERT_EQ(graph.Link(noise, 0, node, PinOf(type->inputs, "b")), LinkResult::Ok) << "blend needs b";
      }
      TerrainRun run(1);
      const auto report = run.Evaluate(graph, 3, ground);
      EXPECT_TRUE(report.errors.empty()) << type->name << ": "
                                         << (report.errors.empty() ? "" : report.errors.begin()->second);
      ++ran;
    }
    EXPECT_GE(ran, 80) << "the palette's node types";
  }

  TEST(
    TerrainGraph,
    GroundKindsPaintTheLayersThatHoldThem
  )
  {
    // A map with grass as the base, rock on layer 1, sand on layer 2, snow on layer 3; rolling ground with a cliff.
    TerrainGround ground;
    ground.width = 129;
    ground.height = 129;
    auto heights = std::make_shared<std::vector<float>>(129 * 129);
    for (int z = 0; z < 129; ++z) {
      for (int x = 0; x < 129; ++x) {
        const float cliff = x < 60 ? 0.0f : (x < 66 ? static_cast<float>(x - 60) * 8.0f : 48.0f);
        (*heights)[static_cast<std::size_t>(z * 129 + x)] =
          20.0f + cliff + 2.0f * std::sin(static_cast<float>(z) * 0.1f);
      }
    }
    ground.heights = heights;
    ground.revision = 7;
    std::array<faf::editor::GroundKind, 9> kinds{};
    kinds[0] = faf::editor::GroundKind::Grass;
    kinds[1] = faf::editor::GroundKind::Rock;
    kinds[2] = faf::editor::GroundKind::Sand;
    kinds[3] = faf::editor::GroundKind::Snow;
    for (int l = 0; l <= 3; ++l) {
      ground.textured[static_cast<std::size_t>(l)] = true;
    }
    ground.plan = faf::editor::PlanRecipe(kinds, ground.textured, 8, false);
    ground.hasPaint = true;

    NodeGraph graph(TerrainNodeTypes());
    const int terrain = graph.AddNode("terrain", 0, 0);
    const int detect = graph.AddNode("ground_kinds", 200, 0);
    const int out = graph.AddNode("out_kinds", 400, 0);
    const auto& kindsType = *graph.Find(detect)->type;
    const auto& outType = *graph.Find(out)->type;
    ASSERT_EQ(graph.Link(terrain, 0, detect, PinOf(kindsType.inputs, "a")), LinkResult::Ok);
    ASSERT_EQ(graph.Link(detect, PinOf(kindsType.outputs, "rock"), out, PinOf(outType.inputs, "rock")), LinkResult::Ok);
    ASSERT_EQ(graph.Link(detect, PinOf(kindsType.outputs, "snow"), out, PinOf(outType.inputs, "snow")), LinkResult::Ok);
    TerrainRun run(1);
    const auto report = run.Evaluate(graph, 1, ground);
    ASSERT_TRUE(report.errors.empty()) << report.errors.begin()->second;
    const faf::editor::TerrainValue* rock = run.Value(detect, "rock");
    ASSERT_NE(rock, nullptr);
    ASSERT_NE(rock->grid, nullptr);
    EXPECT_GT(*std::max_element(rock->grid->v.begin(), rock->grid->v.end()), 0.5f) << "rock on the cliff";
    const faf::editor::TerrainValue* grass = run.Value(detect, "grass");
    ASSERT_NE(grass, nullptr);
    EXPECT_FLOAT_EQ(grass->grid->v[0], 1.0f) << "the base kind: everything the others leave";

    field::Grid shape(129, 129, 1.0f, 0.0f, 0.0f);
    std::map<int, field::Grid> target;
    std::string error;
    ASSERT_TRUE(run.KindsPaint(graph, ground, shape, target, error)) << error;
    ASSERT_EQ(target.count(1), 1U) << "rock's layer";
    ASSERT_EQ(target.count(2), 1U) << "sand has a layer and no link: cleared";
    EXPECT_FLOAT_EQ(*std::max_element(target[2].v.begin(), target[2].v.end()), 0.0f);
    EXPECT_GT(*std::max_element(target[1].v.begin(), target[1].v.end()), 0.5f);
    // The visible weights never add up to more than the whole.
    for (std::size_t k = 0; k < shape.v.size(); ++k) {
      float sum = 0.0f;
      for (const auto& [layer, weight] : target) {
        sum += weight.v[k];
      }
      ASSERT_LE(sum, 1.0001f) << "sample " << k;
    }
    // On a PBR shader with a roughness multiplier in layer 8 the build writes it too: rock rough, the rest neutral.
    ground.roughness = true;
    faf::editor::TerrainBuildWrites writes;
    ASSERT_TRUE(run.BuildWrites(graph, ground, shape, writes, error)) << error;
    EXPECT_TRUE(writes.kindsTypes) << "the node's \"Set the terrain types too\" is on by default";
    ASSERT_EQ(writes.layers.size(), 1U);
    EXPECT_EQ(writes.layers[0].layer, 8);
    const auto [lowest, highest] = std::minmax_element(writes.layers[0].mask.v.begin(), writes.layers[0].mask.v.end());
    EXPECT_GT(*highest, 0.65f) << "rock (0.88) at the default amount 0.6: 0.5 + 0.38 x 0.6";
    EXPECT_LT(*lowest, 0.45f) << "snow (0.2) is linked too: shiny on the top";
    EXPECT_GE(*lowest, 0.31f) << "no shinier than snow at the amount: 0.5 - 0.3 x 0.6";
    ground.roughness = false;
    ASSERT_TRUE(run.BuildWrites(graph, ground, shape, writes, error)) << error;
    EXPECT_TRUE(writes.layers.empty()) << "no roughness layer on other shaders";

    // A graph without Output: ground kinds paints nothing.
    NodeGraph none(TerrainNodeTypes());
    (void)none.AddNode("perlin", 0, 0);
    TerrainRun other(1);
    (void)other.Evaluate(none, 1, ground);
    EXPECT_FALSE(other.KindsPaint(none, ground, shape, target, error));
    EXPECT_TRUE(error.empty());
  }

  TEST(
    TerrainGraph,
    BuildWritesCollectLayersKindsAndTypes
  )
  {
    // Rock on layer 1, sand on 2; a 4-layer shader.
    TerrainGround ground;
    ground.width = 65;
    ground.height = 65;
    ground.heights = std::make_shared<std::vector<float>>(65 * 65, 30.0f);
    ground.revision = 3;
    std::array<faf::editor::GroundKind, 9> kinds{};
    kinds[0] = faf::editor::GroundKind::Grass;
    kinds[1] = faf::editor::GroundKind::Rock;
    kinds[2] = faf::editor::GroundKind::Sand;
    for (int l = 0; l <= 2; ++l) {
      ground.textured[static_cast<std::size_t>(l)] = true;
    }
    ground.painted = 4;
    ground.plan = faf::editor::PlanRecipe(kinds, ground.textured, 4, false);
    ground.hasPaint = true;

    NodeGraph graph(TerrainNodeTypes());
    const int noise = graph.AddNode("perlin", 0, 0);
    const int layer = graph.AddNode("out_layer", 300, 0);
    const int rock = graph.AddNode("out_role", 300, 100);
    const int snow = graph.AddNode("out_role", 300, 200);
    const int high = graph.AddNode("out_layer", 300, 300);
    const int types = graph.AddNode("out_types", 300, 400);
    const int lonely = graph.AddNode("out_types", 300, 500);
    for (const int out : {layer, rock, snow, high, types}) {
      ASSERT_EQ(graph.Link(noise, 0, out, 0), LinkResult::Ok);
    }
    const auto set = [&](const int id, const char* name, const float value) {
      ParamValue v;
      v.value[0] = value;
      graph.SetParam(id, ParamOf(*graph.Find(id)->type, name), v);
    };
    set(layer, "layer", 3);
    set(layer, "mode", 1); // add
    set(layer, "strength", 0.5f);
    set(rock, "role", 4);  // rock (grass, dirt, wet, sand, rock, ...)
    set(snow, "role", 7);  // snow: no layer holds it
    set(high, "layer", 6); // beyond the 4-layer shader
    set(types, "code", 33);
    TerrainRun run(1);
    const auto report = run.Evaluate(graph, 1, ground);
    EXPECT_EQ(report.errors.count(lonely), 1U) << "an output with nothing linked shows an error";
    faf::editor::TerrainBuildWrites writes;
    std::string error;
    ASSERT_TRUE(run.BuildWrites(graph, ground, field::Grid(65, 65, 1.0f, 0.0f, 0.0f), writes, error)) << error;
    ASSERT_EQ(writes.layers.size(), 2U) << "layer 3 and rock's layer";
    EXPECT_EQ(writes.layers[0].layer, 3);
    EXPECT_EQ(writes.layers[0].mode, faf::editor::MaskWriteMode::AddTo);
    EXPECT_FLOAT_EQ(writes.layers[0].strength, 0.5f);
    EXPECT_EQ(writes.layers[1].layer, 1) << "rock is on layer 1";
    ASSERT_EQ(writes.types.size(), 1U);
    EXPECT_EQ(writes.types[0].code, 33);
    EXPECT_TRUE(writes.kinds.empty()) << "no Output: ground kinds";
    EXPECT_EQ(writes.notes.size(), 3U) << "snow has no layer, layer 6 isn't painted, one output has nothing linked";
    EXPECT_FALSE(writes.Empty());

    // A scatter with no density mask (everywhere) and two blueprints, one weighted.
    const int scatter = graph.AddNode("out_scatter", 300, 600);
    ParamValue entries;
    entries.text = "/env/common/props/rocks/rock01_prop.bp:3; /env/common/props/trees/tree01_prop.bp";
    graph.SetParam(scatter, ParamOf(*graph.Find(scatter)->type, "entries"), entries);
    set(scatter, "count", 50);
    const auto again = run.Evaluate(graph, 1, ground);
    EXPECT_EQ(again.errors.count(scatter), 0U) << "its density mask is optional";
    ASSERT_TRUE(run.BuildWrites(graph, ground, field::Grid(65, 65, 1.0f, 0.0f, 0.0f), writes, error)) << error;
    ASSERT_EQ(writes.scatters.size(), 1U);
    const auto& s = writes.scatters[0];
    EXPECT_EQ(s.density.w, 0) << "everywhere";
    ASSERT_EQ(s.entries.size(), 2U);
    EXPECT_EQ(s.entries[0].first, "/env/common/props/rocks/rock01_prop.bp");
    EXPECT_EQ(s.entries[0].second, 3);
    EXPECT_EQ(s.entries[1].second, 100) << "no weight: 100";
    EXPECT_EQ(s.count, 50);
    EXPECT_FLOAT_EQ(s.scaleMin, 0.8f) << "the node's 80 %";
    EXPECT_EQ(s.seed, static_cast<std::uint32_t>((1 * 1009 + scatter * 101 + 1) % 1000003))
      << "the graph's seed mixed in";

    // The map-wide textures to make from the built map, the atlas not written yet, the roughness mask into layer 8.
    (void)graph.AddNode("out_normalmap", 300, 700);
    (void)graph.AddNode("out_macro", 300, 800);
    (void)graph.AddNode("out_atlas", 300, 900);
    const int rough = graph.AddNode("out_roughness", 300, 1000);
    ASSERT_EQ(graph.Link(noise, 0, rough, 0), LinkResult::Ok);
    ground.roughness = true;
    (void)run.Evaluate(graph, 1, ground);
    ASSERT_TRUE(run.BuildWrites(graph, ground, field::Grid(65, 65, 1.0f, 0.0f, 0.0f), writes, error)) << error;
    EXPECT_EQ(std::count(writes.mapTextures.begin(), writes.mapTextures.end(), 0), 1) << "the normal map";
    EXPECT_EQ(std::count(writes.mapTextures.begin(), writes.mapTextures.end(), 3), 1) << "the macrotexture";
    EXPECT_EQ(
      std::count_if(
        writes.notes.begin(),
        writes.notes.end(),
        [](const std::string& note) {
      return note.find("atlas") != std::string::npos;
    }
      ),
      1
    );
    EXPECT_EQ(
      std::count_if(
        writes.layers.begin(),
        writes.layers.end(),
        [](const auto& layer) {
      return layer.layer == 8;
    }
      ),
      1
    ) << "the roughness mask";
  }

  TEST(
    TerrainGraph,
    APathMasksAndCarvesAlongItsLine
  )
  {
    // A straight line (no wobble) across the middle of a flat 129 x 129 map at 30 units, 8 units wide.
    TerrainGround ground = Ground();
    std::fill(
      std::const_pointer_cast<std::vector<float>>(ground.heights)->begin(),
      std::const_pointer_cast<std::vector<float>>(ground.heights)->end(),
      30.0f
    );
    NodeGraph graph(TerrainNodeTypes());
    const int terrain = graph.AddNode("terrain", 0, 0);
    const int line = graph.AddNode("path_line", 0, 200);
    const int mask = graph.AddNode("path_mask", 200, 200);
    const int shape = graph.AddNode("path_shape", 200, 0);
    const auto set = [&](const int id, const char* name, const float value) {
      ParamValue v;
      v.value[0] = value;
      graph.SetParam(id, ParamOf(*graph.Find(id)->type, name), v);
    };
    set(line, "x0", 0.0f);
    set(line, "z0", 0.5f);
    set(line, "x1", 1.0f);
    set(line, "z1", 0.5f);
    set(line, "wobble", 0.0f);
    set(line, "height", -6.0f);
    ASSERT_EQ(graph.Link(line, 0, mask, 0), LinkResult::Ok);
    const auto& shapeType = *graph.Find(shape)->type;
    ASSERT_EQ(graph.Link(terrain, 0, shape, PinOf(shapeType.inputs, "a")), LinkResult::Ok);
    ASSERT_EQ(graph.Link(line, 0, shape, PinOf(shapeType.inputs, "pts")), LinkResult::Ok);
    TerrainRun run(1);
    const auto report = run.Evaluate(graph, 1, ground);
    ASSERT_TRUE(report.errors.empty()) << report.errors.begin()->second;
    const faf::editor::TerrainValue* path = run.Value(line, "out");
    ASSERT_NE(path, nullptr);
    ASSERT_NE(path->path, nullptr);
    EXPECT_EQ(path->path->points.size(), 7U) << "7 control points";
    const field::Grid& m = *run.Value(mask, "out")->grid;
    EXPECT_GT(m.At(64, 64), 0.9f) << "on the line";
    EXPECT_FLOAT_EQ(m.At(64, 10), 0.0f) << "far from it";
    const field::Grid& h = *run.Value(shape, "out")->grid;
    EXPECT_LT(h.At(64, 64), 26.0f) << "carved about 6 units into the 30";
    EXPECT_FLOAT_EQ(h.At(64, 10), 30.0f) << "untouched away from it";
    // A path node without a path is an error, not a crash.
    NodeGraph lonely(TerrainNodeTypes());
    const int alone = lonely.AddNode("path_mask", 0, 0);
    TerrainRun other(1);
    EXPECT_EQ(other.Evaluate(lonely, 1, ground).errors.count(alone), 1U);
  }

  TEST(
    TerrainGraph,
    SavedGraphReadsBack
  )
  {
    NodeGraph graph(TerrainNodeTypes());
    StudioGraphFacts facts;
    std::string error;
    ASSERT_TRUE(ReadStudioGraph(ReadFile(FAF_TERRAIN_GRAPHS "/hills.lua"), graph, facts, error)) << error;
    const std::string text = faf::editor::SaveTerrainGraph(graph, 77, "My hills");
    NodeGraph back(TerrainNodeTypes());
    int seed = 0;
    std::string name;
    ASSERT_TRUE(faf::editor::LoadTerrainGraph(text, back, seed, name, error)) << error;
    EXPECT_EQ(seed, 77);
    EXPECT_EQ(name, "My hills");
    EXPECT_EQ(back.Nodes().size(), graph.Nodes().size());
    EXPECT_EQ(back.Links().size(), graph.Links().size());
    ASSERT_NE(back.Find(4), nullptr);
    EXPECT_FLOAT_EQ(back.Find(4)->params[ParamOf(*back.Find(4)->type, "hi")].value[0], 62.0f);
    EXPECT_EQ(faf::editor::TerrainParamText(*back.Find(3), "mode"), "normal");
  }

  TEST(
    TerrainGraph,
    NumbersDriveParametersAndMissingInputsAreErrors
  )
  {
    NodeGraph graph(TerrainNodeTypes());
    const int noise = graph.AddNode("perlin", 0, 0);
    const int range = graph.AddNode("range", 200, 0);
    const int out = graph.AddNode("out_height", 400, 0);
    const int number = graph.AddNode("number", 0, 200);
    const int lonely = graph.AddNode("out_height", 400, 200);
    const auto& rangeType = *graph.Find(range)->type;
    ASSERT_EQ(graph.Link(noise, 0, range, PinOf(rangeType.inputs, "a")), LinkResult::Ok);
    ASSERT_EQ(graph.Link(range, 0, out, 0), LinkResult::Ok);
    ParamValue value;
    value.value[0] = 200.0f;
    graph.SetParam(number, 0, value);
    ASSERT_EQ(graph.Link(number, 0, range, PinOf(rangeType.inputs, "hi")), LinkResult::Ok);
    EXPECT_EQ(graph.Link(number, 0, out, 0), LinkResult::WrongType) << "a number isn't a field";
    const TerrainGround ground = Ground();
    TerrainRun run(2);
    const auto report = run.Evaluate(graph, 1, ground);
    ASSERT_EQ(report.errors.size(), 1U);
    EXPECT_EQ(report.errors.begin()->first, lonely);
    EXPECT_EQ(run.Error(lonely), "input a is not linked");
    field::Grid heights;
    ASSERT_TRUE(run.FinalHeight(graph, ground, heights));
    EXPECT_GT(field::Measure(heights).max, 100.0f) << "the number pin set the range's top to 200";
  }
} // namespace
