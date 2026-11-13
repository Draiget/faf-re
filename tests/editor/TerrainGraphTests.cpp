// The terrain graph (src/editor/graph/EdTerrainGraph.cpp, EdTerrainNodes.cpp): the node catalogue, a FAF Studio graph
// file read with its ids, a run on a small map at full and preview resolution, the cache re-running only what a
// change reaches, number pins driving parameters, and the errors a node shows.

#include "editor/graph/EdTerrainGraph.h"

#include <gtest/gtest.h>

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
    // The texturing nodes come later: the height chain is all there, with Studio's ids.
    EXPECT_EQ(graph.Nodes().size(), 7U);
    ASSERT_NE(graph.Find(11), nullptr);
    EXPECT_EQ(graph.Find(11)->type->name, "flatten");
    EXPECT_FLOAT_EQ(graph.Find(4)->params[ParamOf(*graph.Find(4)->type, "hi")].value[0], 62.0f);
    EXPECT_EQ(faf::editor::TerrainParamText(*graph.Find(3), "mode"), "normal") << "a choice by its id";
    EXPECT_EQ(
      graph.Links().size(), 6U
    ) << "simplex and billow into blend, then blend > range > erosion > flatten > output";
    EXPECT_EQ(facts.droppedLinks, 12) << "the links to and from the two texturing nodes";
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
    EXPECT_EQ(report.evaluated, 7);
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
    EXPECT_EQ(cached.cached, 7);

    // The range's top changed: the range and what it feeds run again (range, erosion, flatten, output), the noises
    // don't.
    ParamValue hi;
    hi.value[0] = 80.0f;
    graph.SetParam(4, ParamOf(*graph.Find(4)->type, "hi"), hi);
    const auto changed = run.Evaluate(graph, facts.seed, ground);
    EXPECT_EQ(changed.evaluated, 4);
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
