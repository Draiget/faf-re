// The particle editor's node graph (src/editor/graph/EdEffectGraph.cpp): emitters into graphs and back, the curve
// nodes, the pins' kinds, FAF's effect templates.

#include "editor/graph/EdEffectGraph.h"
#include "TestEnv.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>

namespace
{
  using namespace faf::editor;

  bool SameEmitter(const EmitterBlueprint& a, const EmitterBlueprint& b)
  {
    const auto near = [](const float x, const float y) { return std::fabs(x - y) <= 1e-4f * std::max(1.0f, std::fabs(x)); };
    if (a.blueprintId != b.blueprintId || a.texture != b.texture || a.rampTexture != b.rampTexture || a.flags != b.flags ||
        a.lowFidelity != b.lowFidelity || a.medFidelity != b.medFidelity || a.highFidelity != b.highFidelity || !near(a.lifetime, b.lifetime) ||
        !near(a.repeatTime, b.repeatTime) || !near(a.blendMode, b.blendMode) || !near(a.textureFrameCount, b.textureFrameCount) ||
        !near(a.textureStripCount, b.textureStripCount) || !near(a.lodCutoff, b.lodCutoff) || !near(a.sortOrder, b.sortOrder)) {
      return false;
    }
    for (int c = 0; c < kEmitterCurveCount; ++c) {
      const EmitterCurve& x = a.curves[static_cast<std::size_t>(c)];
      const EmitterCurve& y = b.curves[static_cast<std::size_t>(c)];
      if (x.keys.size() != y.keys.size() || (!x.keys.empty() && !near(x.xRange, y.xRange))) {
        return false;
      }
      for (std::size_t k = 0; k < x.keys.size(); ++k) {
        if (!near(x.keys[k].x, y.keys[k].x) || !near(x.keys[k].y, y.keys[k].y) || !near(x.keys[k].z, y.keys[k].z)) {
          return false;
        }
      }
    }
    return true;
  }

  TEST(EffectGraph, AnEmitterBecomesAGraphAndBack)
  {
    EmitterBlueprint e = NewEmitter();
    e.curves[kSize].keys = {{0.0f, 1.0f, 0.5f}, {5.0f, 3.0f, 0.0f}, {10.0f, 0.5f, 0.25f}};
    e.texture = "/textures/particles/a.dds";
    e.flags[kGravity] = true;
    NodeGraph graph(EffectNodeTypes());
    BuildEffectGraph(graph, "test", {{"my_emit", e}});
    std::vector<std::pair<std::string, EmitterBlueprint>> out;
    std::string error;
    ASSERT_TRUE(GraphEmitters(graph, out, error)) << error;
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].first, "my_emit");
    EXPECT_TRUE(SameEmitter(out[0].second, e));
    // Through the graph file too.
    NodeGraph read(EffectNodeTypes());
    ASSERT_TRUE(read.Load(graph.Save(), error)) << error;
    ASSERT_TRUE(GraphEmitters(read, out, error)) << error;
    EXPECT_TRUE(SameEmitter(out[0].second, e));
  }

  TEST(EffectGraph, CurveNodesMakeKeysAndPinsKeepToTheirKind)
  {
    NodeGraph graph(EffectNodeTypes());
    const int output = graph.AddNode(kEffectOutput, 0.0f, 0.0f);
    const int emitter = graph.AddNode(kEmitterNode, 0.0f, 0.0f);
    ASSERT_EQ(graph.Link(emitter, 0, output, 0), LinkResult::Ok);
    const int ramp = graph.AddNode("CurveOverLife", 0.0f, 0.0f);   // 0 to 1
    const int scale = graph.AddNode("CurveScale", 0.0f, 0.0f);     // x 2
    const int random = graph.AddNode("CurveRandom", 0.0f, 0.0f);   // 0 to 1
    const int texture = graph.AddNode(kTextureNode, 0.0f, 0.0f);
    ASSERT_EQ(graph.Link(ramp, 0, scale, 0), LinkResult::Ok);
    ASSERT_EQ(graph.Link(scale, 0, emitter, kStartSize), LinkResult::Ok);
    ASSERT_EQ(graph.Link(random, 0, emitter, kVelocity), LinkResult::Ok);
    // A texture into a curve pin, an emitter into a curve pin: refused.
    EXPECT_EQ(graph.Link(texture, 0, emitter, kLifetime), LinkResult::WrongType);
    EXPECT_EQ(graph.Link(emitter, 0, emitter, kLifetime), LinkResult::SameNode);
    std::vector<std::pair<std::string, EmitterBlueprint>> out;
    std::string error;
    ASSERT_TRUE(GraphEmitters(graph, out, error)) << error;
    const EmitterCurve& size = out[0].second.curves[kStartSize];
    ASSERT_EQ(size.keys.size(), 2U);
    EXPECT_FLOAT_EQ(size.keys[1].x, out[0].second.repeatTime);
    EXPECT_FLOAT_EQ(size.keys[1].y, 2.0f);
    const EmitterCurve& velocity = out[0].second.curves[kVelocity];
    ASSERT_EQ(velocity.keys.size(), 1U);
    EXPECT_FLOAT_EQ(velocity.keys[0].y, 0.5f);
    EXPECT_FLOAT_EQ(velocity.keys[0].z, 1.0f);
    // An unlinked curve: its starting key (the emit rate's 1).
    EXPECT_FLOAT_EQ(out[0].second.curves[kEmitRate].keys.at(0).y, 1.0f);
    EXPECT_EQ(CurveKeysFromText(CurveKeysText({{1.5f, -2.0f, 0.25f}, {3.0f, 4.0f, 0.0f}})).size(), 2U);
  }

  TEST(EffectGraph, PlainTemplatesAreRead)
  {
    const std::string lua = "EmtBpPath = '/effects/emitters/'\n"
                            "-- a comment { }\n"
                            "ExplosionLarge = {\n    EmtBpPath .. 'Large_test_smoke.bp',\n    '/effects/emitters/x.bp',\n}\n"
                            "Nested = {\n    { EmtBpPath .. 'a.bp' },\n}\n"
                            "Called = table.cat(A, B)\n"
                            "  Indented = {\n    EmtBpPath .. 'b.bp',\n  }\n";
    const std::vector<EffectTemplate> templates = ParseEffectTemplates(lua);
    ASSERT_EQ(templates.size(), 1U);
    EXPECT_EQ(templates[0].name, "ExplosionLarge");
    EXPECT_EQ(templates[0].paths, (std::vector<std::string>{"/effects/emitters/Large_test_smoke.bp", "/effects/emitters/x.bp"}));
  }

  TEST(EffectGraph, TheGamesEmittersAndTemplates)
  {
    const std::string folder = faf::editor::test::EnvText("FAF_RETAIL_EMITTERS");
    if (folder.empty()) {
      GTEST_SKIP() << "FAF_RETAIL_EMITTERS is not set";
    }
    int checked = 0;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
      std::ifstream in(entry.path(), std::ios::binary);
      const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      EmitterBlueprint e;
      std::string error;
      if (text.rfind("EmitterBlueprint", 0) != 0 || !ParseEmitter(text, e, error)) {
        continue;
      }
      // Curves with no keys stay empty only through a Curve node; the file's own have keys (or none: kept as none).
      NodeGraph graph(EffectNodeTypes());
      BuildEffectGraph(graph, "t", {{"e", e}});
      std::vector<std::pair<std::string, EmitterBlueprint>> out;
      NodeGraph read(EffectNodeTypes());
      ASSERT_TRUE(read.Load(graph.Save(), error)) << error;
      ASSERT_TRUE(GraphEmitters(read, out, error)) << entry.path().filename().string() << ": " << error;
      if (!SameEmitter(out[0].second, e)) {
        // What differs, for the failure's message.
        std::string diff;
        for (int c = 0; c < kEmitterCurveCount; ++c) {
          const EmitterCurve& x = e.curves[static_cast<std::size_t>(c)];
          const EmitterCurve& y = out[0].second.curves[static_cast<std::size_t>(c)];
          if (x.keys.size() != y.keys.size() || x.xRange != y.xRange) {
            diff += std::string(" ") + CurveInfo(c).name + " keys " + std::to_string(x.keys.size()) + "/" + std::to_string(y.keys.size()) + " range " +
                    std::to_string(x.xRange) + "/" + std::to_string(y.xRange);
          }
        }
        diff += " lod " + std::to_string(e.lodCutoff) + "/" + std::to_string(out[0].second.lodCutoff) + " sort " + std::to_string(e.sortOrder) + "/" +
                std::to_string(out[0].second.sortOrder);
        ADD_FAILURE() << entry.path().filename().string() << ":" << diff;
      }
      ++checked;
    }
    std::printf("emitters through a graph and back: %d\n", checked);
    EXPECT_GT(checked, 2000);
    // FAF's templates file, when it is beside the emitters (tmp: lua/EffectTemplates.lua copied there).
    std::ifstream lua(std::filesystem::path(folder) / ".." / "EffectTemplates.lua", std::ios::binary);
    if (lua) {
      const std::string text((std::istreambuf_iterator<char>(lua)), std::istreambuf_iterator<char>());
      const std::vector<EffectTemplate> templates = ParseEffectTemplates(text);
      std::size_t paths = 0;
      for (const EffectTemplate& t : templates) {
        paths += t.paths.size();
      }
      std::printf("effect templates read: %zu, %zu emitter paths\n", templates.size(), paths);
      EXPECT_GT(templates.size(), 600U);
    }
  }
} // namespace
