// The material editor's texture graph (src/editor/graph/EdTextureGraph.cpp): tiling, caching, sizes and the output.

#include "editor/graph/EdTextureGraph.h"

#include <gtest/gtest.h>

#include <cmath>

namespace
{
  using namespace faf::editor;

  /** The largest step between neighbouring pixels across the image's left/right seam, and inside it. */
  void Steps(const TexImage& image, float& seam, float& inside)
  {
    seam = 0.0f;
    inside = 0.0f;
    for (int y = 0; y < image.size; ++y) {
      seam = std::max(seam, std::fabs(image.Pixel(0, y)[0] - image.Pixel(image.size - 1, y)[0]));
      for (int x = 1; x < image.size; ++x) {
        inside = std::max(inside, std::fabs(image.Pixel(x, y)[0] - image.Pixel(x - 1, y)[0]));
      }
    }
  }

  TEST(TextureGraph, NoiseAndCellsTileAcrossTheSeam)
  {
    NodeGraph graph(TextureNodeTypes());
    const int noise = graph.AddNode("Noise", 0.0f, 0.0f);
    const int cells = graph.AddNode("Cells", 0.0f, 0.0f);
    TextureGraphEvaluator eval(graph);
    eval.SetSize(128);
    eval.EvaluateAll();
    for (const auto& [id, pin] : {std::pair{noise, 0}, std::pair{cells, 0}}) {
      const TexImagePtr image = eval.Output(id, pin);
      ASSERT_NE(image, nullptr);
      ASSERT_EQ(image->size, 128);
      float seam = 0.0f;
      float inside = 0.0f;
      Steps(*image, seam, inside);
      EXPECT_LE(seam, inside * 1.01f + 1e-4f) << graph.Find(id)->type->name;
    }
  }

  TEST(TextureGraph, OnlyWhatChangedIsComputedAgain)
  {
    NodeGraph graph(TextureNodeTypes());
    StartTextureGraph(graph);
    TextureGraphEvaluator eval(graph);
    eval.SetSize(32);
    EXPECT_EQ(eval.EvaluateAll(), 4);
    EXPECT_EQ(eval.EvaluateAll(), 0);
    // The gradient map's colour: it and the output, not the noise or the normal.
    int colours = 0;
    for (const GraphNode& node : graph.Nodes()) {
      if (node.type->name == "GradientMap") {
        colours = node.id;
      }
    }
    ParamValue red;
    red.value = {1.0f, 0.0f, 0.0f, 1.0f};
    graph.SetParam(colours, 0, red);
    EXPECT_EQ(eval.EvaluateAll(), 2);
    // A new size computes everything.
    eval.SetSize(16);
    EXPECT_EQ(eval.EvaluateAll(), 4);
  }

  TEST(TextureGraph, TheResultIsAtTheGraphsSizeInThePinsType)
  {
    NodeGraph graph(TextureNodeTypes());
    StartTextureGraph(graph);
    TextureGraphEvaluator eval(graph);
    eval.SetSize(64);
    const TexImagePtr albedo = eval.Result("Albedo");
    ASSERT_NE(albedo, nullptr);
    EXPECT_EQ(albedo->size, 64);
    EXPECT_EQ(albedo->channels, 4);
    EXPECT_EQ(eval.Result("Mask"), nullptr); // nothing linked
    // A constant into the mask is spread over the whole image.
    const int constant = graph.AddNode("Constant", 0.0f, 0.0f);
    ASSERT_EQ(graph.Link(constant, 0, graph.OutputNode(), 2), LinkResult::Ok);
    const TexImagePtr mask = eval.Result("Mask");
    ASSERT_NE(mask, nullptr);
    EXPECT_EQ(mask->size, 64);
    EXPECT_EQ(mask->channels, 1);
    EXPECT_FLOAT_EQ(mask->Pixel(63, 63)[0], 0.5f);
  }

  TEST(TextureGraph, APreviewAndABakeLookTheSame)
  {
    NodeGraph graph(TextureNodeTypes());
    const int noise = graph.AddNode("Noise", 0.0f, 0.0f);
    const int blur = graph.AddNode("Blur", 0.0f, 0.0f);
    ASSERT_EQ(graph.Link(noise, 0, blur, 0), LinkResult::Ok);
    TextureGraphEvaluator small(graph);
    small.SetSize(64);
    small.Evaluate(blur);
    TextureGraphEvaluator large(graph);
    large.SetSize(256);
    large.Evaluate(blur);
    const TexImagePtr a = small.Output(blur, 0);
    const TexImagePtr b = large.Output(blur, 0);
    float worst = 0.0f;
    for (int y = 0; y < 64; ++y) {
      for (int x = 0; x < 64; ++x) {
        float c[4];
        b->Sample((static_cast<float>(x) + 0.5f) / 64.0f, (static_cast<float>(y) + 0.5f) / 64.0f, c);
        worst = std::max(worst, std::fabs(c[0] - a->Pixel(x, y)[0]));
      }
    }
    EXPECT_LT(worst, 0.12f);
  }

  TEST(TextureGraph, AFlatHeightGivesAFlatNormal)
  {
    NodeGraph graph(TextureNodeTypes());
    const int normal = graph.AddNode("HeightToNormal", 0.0f, 0.0f);
    TextureGraphEvaluator eval(graph);
    eval.SetSize(16);
    eval.Evaluate(normal);
    const float* p = eval.Output(normal, 0)->Pixel(5, 7);
    EXPECT_NEAR(p[0], 0.5f, 1e-5f);
    EXPECT_NEAR(p[1], 0.5f, 1e-5f);
    EXPECT_NEAR(p[2], 1.0f, 1e-5f);
  }

  TEST(TextureGraph, TexturesComeFromTheLoaderAndAMissingOneWarns)
  {
    NodeGraph graph(TextureNodeTypes());
    const int texture = graph.AddNode("Texture", 0.0f, 0.0f);
    TextureGraphEvaluator eval(graph);
    eval.SetSize(8);
    int loads = 0;
    eval.SetTextureLoader([&](const std::string& path, TexImage& out) {
      ++loads;
      if (path.find("missing") != std::string::npos) {
        return false;
      }
      out.Reset(2, 4, 0.25f);
      return true;
    });
    eval.Evaluate(texture);
    EXPECT_TRUE(eval.Warning(texture).empty());
    EXPECT_FLOAT_EQ(eval.Output(texture, 0)->Pixel(3, 3)[0], 0.25f);
    ParamValue missing;
    missing.text = "/env/missing.dds";
    graph.SetParam(texture, 0, missing);
    eval.Evaluate(texture);
    EXPECT_NE(eval.Warning(texture).find("missing.dds"), std::string::npos);
    EXPECT_EQ(loads, 2);
  }

  TEST(TextureGraph, MapHeightAndSlopeReadTheTerrain)
  {
    NodeGraph graph(TextureNodeTypes());
    const int height = graph.AddNode("TerrainHeight", 0.0f, 0.0f);
    const int slope = graph.AddNode("TerrainSlope", 0.0f, 0.0f);
    TextureGraphEvaluator eval(graph);
    eval.SetSize(16);
    eval.EvaluateAll();
    EXPECT_EQ(eval.Warning(height), "No map open");
    // A ramp rising one unit per sample along x: 45 degrees everywhere.
    auto terrain = std::make_shared<TerrainSource>();
    terrain->width = 33;
    terrain->height = 33;
    for (int y = 0; y < 33; ++y) {
      for (int x = 0; x < 33; ++x) {
        terrain->heights.push_back(static_cast<float>(x));
      }
    }
    eval.SetTerrain(terrain);
    eval.EvaluateAll();
    EXPECT_TRUE(eval.Warning(height).empty());
    EXPECT_LT(eval.Output(height, 0)->Pixel(0, 8)[0], 0.1f);
    EXPECT_GT(eval.Output(height, 0)->Pixel(15, 8)[0], 0.9f);
    EXPECT_NEAR(eval.Output(slope, 0)->Pixel(8, 8)[0], 1.0f, 1e-3f);
  }

  TEST(TextureGraph, EveryNodeTypeComputes)
  {
    NodeGraph graph(TextureNodeTypes());
    for (const auto& type : TextureNodeTypes().All()) {
      EXPECT_NE(graph.AddNode(type->name, 0.0f, 0.0f), 0) << type->name;
    }
    TextureGraphEvaluator eval(graph);
    eval.SetSize(16);
    EXPECT_EQ(eval.EvaluateAll(), static_cast<int>(graph.Nodes().size()));
    for (const GraphNode& node : graph.Nodes()) {
      for (std::size_t pin = 0; pin < node.type->outputs.size(); ++pin) {
        const TexImagePtr image = eval.Output(node.id, static_cast<int>(pin));
        ASSERT_NE(image, nullptr) << node.type->name;
        for (const float v : image->data) {
          ASSERT_TRUE(std::isfinite(v)) << node.type->name;
        }
      }
    }
  }
} // namespace
