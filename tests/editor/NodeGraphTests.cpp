// The node graph's model (src/editor/graph/EdNodeGraph.cpp): links, loops, order, revisions and the graph file.

#include "editor/graph/EdNodeGraph.h"

#include <gtest/gtest.h>

#include <algorithm>

namespace
{
  using namespace faf::editor;

  NodeTypeRegistry MakeRegistry()
  {
    NodeTypeRegistry registry;
    NodeType constant;
    constant.name = "Constant";
    constant.outputs = {{"Out", PinType::Grey, {}}};
    ParamDef value;
    value.name = "Value";
    value.initial = {0.5f, 0.0f, 0.0f, 0.0f};
    constant.params = {value};
    registry.Add(constant);

    NodeType multiply;
    multiply.name = "Multiply";
    multiply.inputs = {{"A", PinType::Color, {}}, {"B", PinType::Color, {}}};
    multiply.outputs = {{"Out", PinType::Color, {}}};
    registry.Add(multiply);

    NodeType sample;
    sample.name = "TextureSample";
    sample.outputs = {{"RGBA", PinType::Color, {}}};
    ParamDef path;
    path.name = "Texture";
    path.kind = ParamKind::Text;
    path.initialText = "/env/evergreen/layers/eg_grass001_albedo.dds";
    ParamDef tint;
    tint.name = "Tint";
    tint.kind = ParamKind::Color;
    tint.initial = {1.0f, 1.0f, 1.0f, 1.0f};
    sample.params = {path, tint};
    registry.Add(sample);

    NodeType output;
    output.name = "Output";
    output.isOutput = true;
    output.inputs = {{"Albedo", PinType::Color, {}}, {"Normal", PinType::Color, {}}};
    registry.Add(output);
    return registry;
  }

  TEST(NodeGraph, LinksReplaceTheInputsLinkAndRefuseLoops)
  {
    const NodeTypeRegistry registry = MakeRegistry();
    NodeGraph graph(registry);
    const int out = graph.AddNode("Output", 400.0f, 0.0f);
    const int a = graph.AddNode("Multiply", 0.0f, 0.0f);
    const int b = graph.AddNode("Multiply", 200.0f, 0.0f);
    const int c = graph.AddNode("Constant", -200.0f, 0.0f);
    EXPECT_EQ(graph.AddNode("Output", 0.0f, 0.0f), 0); // one output per graph
    EXPECT_EQ(graph.AddNode("Nope", 0.0f, 0.0f), 0);

    EXPECT_EQ(graph.Link(a, 0, b, 0), LinkResult::Ok);
    EXPECT_EQ(graph.Link(b, 0, out, 0), LinkResult::Ok);
    EXPECT_EQ(graph.Link(b, 0, a, 1), LinkResult::Cycle);
    EXPECT_EQ(graph.Link(a, 0, a, 1), LinkResult::SameNode);
    EXPECT_EQ(graph.Link(a, 3, b, 1), LinkResult::BadPin);
    // A second link into b.A replaces the first.
    EXPECT_EQ(graph.Link(c, 0, b, 0), LinkResult::Ok);
    ASSERT_NE(graph.InputLink(b, 0), nullptr);
    EXPECT_EQ(graph.InputLink(b, 0)->fromNode, c);
    EXPECT_EQ(graph.Links().size(), 2U);

    // Order: c before b before out; a stands alone, the output's evaluation leaves it out.
    std::vector<int> order;
    ASSERT_TRUE(graph.Order(order));
    const auto at = [&](const int id) { return std::find(order.begin(), order.end(), id) - order.begin(); };
    EXPECT_LT(at(c), at(b));
    EXPECT_LT(at(b), at(out));
    EXPECT_EQ(graph.OrderFor(out), (std::vector<int>{c, b, out}));

    // The output can't be removed; removing c drops its link.
    EXPECT_FALSE(graph.RemoveNode(out));
    EXPECT_TRUE(graph.RemoveNode(c));
    EXPECT_EQ(graph.InputLink(b, 0), nullptr);
  }

  TEST(NodeGraph, AChangeBumpsTheNodeAndWhatItFeeds)
  {
    const NodeTypeRegistry registry = MakeRegistry();
    NodeGraph graph(registry);
    const int out = graph.AddNode("Output", 0.0f, 0.0f);
    const int m = graph.AddNode("Multiply", 0.0f, 0.0f);
    const int c = graph.AddNode("Constant", 0.0f, 0.0f);
    const int lone = graph.AddNode("Constant", 0.0f, 0.0f);
    ASSERT_EQ(graph.Link(c, 0, m, 0), LinkResult::Ok);
    ASSERT_EQ(graph.Link(m, 0, out, 0), LinkResult::Ok);
    const auto revision = [&](const int id) { return graph.Find(id)->revision; };
    const auto outBefore = revision(out);
    const auto loneBefore = revision(lone);
    ParamValue value;
    value.value = {0.25f, 0.0f, 0.0f, 0.0f};
    graph.SetParam(c, 0, value);
    EXPECT_GT(revision(out), outBefore);
    EXPECT_EQ(revision(lone), loneBefore);
    // The same value again changes nothing.
    const auto again = revision(out);
    graph.SetParam(c, 0, value);
    EXPECT_EQ(revision(out), again);
  }

  TEST(NodeGraph, TheFileReadsBackTheSameGraph)
  {
    const NodeTypeRegistry registry = MakeRegistry();
    NodeGraph graph(registry);
    const int out = graph.AddNode("Output", 400.0f, 10.0f);
    const int s = graph.AddNode("TextureSample", -120.5f, 30.0f);
    const int m = graph.AddNode("Multiply", 100.0f, -40.0f);
    ParamValue tint;
    tint.value = {0.5f, 0.25f, 1.0f, 0.75f};
    graph.SetParam(s, 1, tint);
    ParamValue path;
    path.text = "/maps/my map/env/rock \"02\".dds";
    graph.SetParam(s, 0, path);
    ASSERT_EQ(graph.Link(s, 0, m, 1), LinkResult::Ok);
    ASSERT_EQ(graph.Link(m, 0, out, 0), LinkResult::Ok);
    const std::string text = graph.Save();

    NodeGraph read(registry);
    std::string error;
    ASSERT_TRUE(read.Load(text, error)) << error;
    EXPECT_EQ(read.Save(), text);
    EXPECT_EQ(read.Find(s)->params[0].text, path.text);
    EXPECT_FLOAT_EQ(read.Find(s)->params[1].value[1], 0.25f);
    EXPECT_FLOAT_EQ(read.Find(s)->x, -120.5f);
    ASSERT_NE(read.InputLink(m, 1), nullptr);
    EXPECT_EQ(read.InputLink(m, 1)->fromNode, s);
    // New nodes don't reuse a read id.
    EXPECT_GT(read.AddNode("Constant", 0.0f, 0.0f), std::max({out, s, m}));
  }

  TEST(NodeGraph, AFileWithUnknownNodesAndMissingParametersStillReads)
  {
    const NodeTypeRegistry registry = MakeRegistry();
    const std::string text = R"({
  "graph": "fafgraph",
  "version": 1,
  "nodes": [
    {"id": 1, "type": "Output", "x": 0, "y": 0, "params": {}},
    {"id": 2, "type": "FromTheFuture", "x": 0, "y": 0, "params": {"Q": [1]}},
    {"id": 3, "type": "Constant", "x": 5, "y": 6, "params": {}}
  ],
  "links": [
    {"from": 2, "out": "Out", "to": 1, "in": "Albedo"},
    {"from": 3, "out": "Out", "to": 1, "in": "Normal"}
  ]
})";
    NodeGraph graph(registry);
    std::string error;
    ASSERT_TRUE(graph.Load(text, error)) << error;
    EXPECT_EQ(graph.Nodes().size(), 2U);
    EXPECT_FLOAT_EQ(graph.Find(3)->params[0].value[0], 0.5f); // the initial value
    EXPECT_EQ(graph.Links().size(), 1U);
    EXPECT_FALSE(graph.Load("{}", error));
  }
} // namespace
