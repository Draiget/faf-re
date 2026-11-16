// The sixth comparison with FAF Studio (field target): the terrain graph's editing (names, bypass, copy and paste,
// the history's restore).

#include "editor/graph/EdNodeGraph.h"
#include "editor/graph/EdTerrainGraph.h"

#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace
{
  using namespace faf::editor;

  std::size_t ParamAt(
    const NodeType& type,
    const char* name
  )
  {
    for (std::size_t p = 0; p < type.params.size(); ++p) {
      if (type.params[p].name == name) {
        return p;
      }
    }
    return type.params.size();
  }

  TerrainGround Ground()
  {
    TerrainGround ground;
    ground.width = 65;
    ground.height = 65;
    auto heights = std::make_shared<std::vector<float>>(65 * 65, 30.0f);
    ground.heights = heights;
    ground.revision = 1;
    return ground;
  }

  struct Chain
  {
    NodeGraph graph{TerrainNodeTypes()};
    int noise = 0;
    int range = 0;
    int out = 0;
    Chain()
    {
      noise = graph.AddNode("perlin", 0.0f, 0.0f);
      range = graph.AddNode("range", 240.0f, 0.0f);
      out = graph.AddNode("out_height", 480.0f, 0.0f);
      EXPECT_EQ(graph.Link(noise, 0, range, 0), LinkResult::Ok);
      EXPECT_EQ(graph.Link(range, 0, out, 0), LinkResult::Ok);
    }
  };

  TEST(
    RoundEightField,
    NodesKeepTheirNameAndBypassInTheFile
  )
  {
    Chain c;
    const std::uint64_t before = c.graph.Changes();
    c.graph.SetName(c.range, "Hill \"heights\"");
    EXPECT_GT(c.graph.Changes(), before) << "a name is a change the editor saves";
    const std::uint64_t revision = c.graph.Find(c.out)->revision;
    c.graph.SetBypass(c.range, true);
    EXPECT_GT(c.graph.Find(c.out)->revision, revision) << "bypass runs what is downstream again";
    NodeGraph loaded(TerrainNodeTypes());
    const auto read = loaded.Load(c.graph.Save());
    ASSERT_TRUE(read) << read.error();
    ASSERT_NE(loaded.Find(c.range), nullptr);
    EXPECT_EQ(loaded.Find(c.range)->name, "Hill \"heights\"");
    EXPECT_TRUE(loaded.Find(c.range)->bypass);
    EXPECT_FALSE(loaded.Find(c.noise)->bypass);
    EXPECT_TRUE(loaded.Find(c.noise)->name.empty());
    EXPECT_EQ(loaded.Links().size(), 2U) << "a name with quotes doesn't break the parameters after it";
  }

  TEST(
    RoundEightField,
    CopyAndPasteTakeTheLinksAmongTheNodes
  )
  {
    Chain c;
    c.graph.SetName(c.noise, "Base");
    const std::size_t lo = ParamAt(*c.graph.Find(c.range)->type, "lo");
    ASSERT_LT(lo, c.graph.Find(c.range)->params.size());
    ParamValue value = c.graph.Find(c.range)->params[lo];
    value.value[0] = 77.0f;
    c.graph.SetParam(c.range, lo, value);
    const std::string copied = c.graph.SaveSome({c.noise, c.range});
    EXPECT_EQ(copied.find("out_height"), std::string::npos) << "only the nodes copied";
    const auto pastedOk = c.graph.Paste(copied, 1000.0f, 500.0f);
    ASSERT_TRUE(pastedOk) << pastedOk.error();
    const std::vector<int>& pasted = *pastedOk;
    ASSERT_EQ(pasted.size(), 2U);
    EXPECT_EQ(c.graph.Nodes().size(), 5U);
    const GraphNode* noise = c.graph.Find(pasted[0]);
    const GraphNode* range = c.graph.Find(pasted[1]);
    ASSERT_NE(noise, nullptr);
    ASSERT_NE(range, nullptr);
    EXPECT_NE(noise->id, c.noise) << "new ids";
    EXPECT_EQ(noise->name, "Base");
    EXPECT_FLOAT_EQ(noise->x, 1000.0f) << "the group's top left corner at the place";
    EXPECT_FLOAT_EQ(noise->y, 500.0f);
    EXPECT_FLOAT_EQ(range->x, 1240.0f);
    EXPECT_FLOAT_EQ(range->params[lo].value[0], 77.0f);
    ASSERT_NE(c.graph.InputLink(range->id, 0), nullptr) << "the link between them";
    EXPECT_EQ(c.graph.InputLink(range->id, 0)->fromNode, noise->id);
    EXPECT_EQ(c.graph.Links().size(), 3U) << "nothing linked to the old nodes";
    // The whole graph pasted again: every node (height outputs too: a graph folds several together).
    const auto again = c.graph.Paste(c.graph.Save(), 0.0f, 2000.0f);
    ASSERT_TRUE(again) << again.error();
    EXPECT_EQ(again->size(), 5U);
    EXPECT_EQ(c.graph.Links().size(), 6U) << "the three links again";
    EXPECT_FALSE(c.graph.Paste("not a graph", 0.0f, 0.0f));
  }

  TEST(
    RoundEightField,
    RestoreGoesBackAndCountsOn
  )
  {
    Chain c;
    const std::string before = c.graph.Save();
    (void)c.graph.RemoveNode(c.noise);
    ASSERT_EQ(c.graph.Nodes().size(), 2U);
    const std::uint64_t changes = c.graph.Changes();
    const auto restored = c.graph.Restore(before);
    ASSERT_TRUE(restored) << restored.error();
    EXPECT_EQ(c.graph.Nodes().size(), 3U);
    EXPECT_EQ(c.graph.Save(), before) << "the same graph";
    EXPECT_GT(c.graph.Changes(), changes) << "a restore is a change (the preview runs again)";
  }

  TEST(
    RoundEightField,
    ABypassedNodePassesItsInputThrough
  )
  {
    Chain c;
    const std::size_t lo = ParamAt(*c.graph.Find(c.range)->type, "lo");
    const std::size_t hi = ParamAt(*c.graph.Find(c.range)->type, "hi");
    ParamValue value = c.graph.Find(c.range)->params[lo];
    value.value[0] = 300.0f;
    c.graph.SetParam(c.range, lo, value);
    value.value[0] = 400.0f;
    c.graph.SetParam(c.range, hi, value);
    const TerrainGround ground = Ground();
    TerrainRun run(1);
    auto report = run.Evaluate(c.graph, 3, ground);
    ASSERT_TRUE(report.errors.empty()) << report.errors.begin()->second;
    const std::string noiseOut = c.graph.Find(c.noise)->type->outputs[0].name;
    const std::string rangeOut = c.graph.Find(c.range)->type->outputs[0].name;
    const TerrainValue* ranged = run.Value(c.range, rangeOut);
    ASSERT_TRUE(ranged != nullptr && ranged->grid != nullptr);
    EXPECT_GE(ranged->grid->v[0], 299.0f) << "the range's 300..400";
    c.graph.SetBypass(c.range, true);
    report = run.Evaluate(c.graph, 3, ground);
    ASSERT_TRUE(report.errors.empty()) << report.errors.begin()->second;
    const TerrainValue* noise = run.Value(c.noise, noiseOut);
    const TerrainValue* through = run.Value(c.range, rangeOut);
    ASSERT_TRUE(noise != nullptr && through != nullptr && through->grid != nullptr);
    EXPECT_EQ(through->grid->v, noise->grid->v) << "bypassed: the noise unchanged";
    EXPECT_LT(through->grid->v[0], 299.0f);
    c.graph.SetBypass(c.range, false);
    report = run.Evaluate(c.graph, 3, ground);
    EXPECT_GE(run.Value(c.range, rangeOut)->grid->v[0], 299.0f) << "on again";
  }
} // namespace
