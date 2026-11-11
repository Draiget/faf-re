// Emitter blueprint files (src/editor/doc/EdEmitter.cpp): read, written as retail's emitter editor writes them, read back.

#include "editor/doc/EdEmitter.h"
#include "TestEnv.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>

namespace
{
  using namespace faf::editor;

  bool Same(const EmitterBlueprint& a, const EmitterBlueprint& b)
  {
    if (a.blueprintId != b.blueprintId || a.texture != b.texture || a.rampTexture != b.rampTexture || a.flags != b.flags ||
        a.lowFidelity != b.lowFidelity || a.medFidelity != b.medFidelity || a.highFidelity != b.highFidelity || a.extra != b.extra) {
      return false;
    }
    // Numbers as the file keeps them (two decimals; keys three).
    const auto near = [](const float x, const float y, const float step) { return std::fabs(x - y) <= step * 0.51f; };
    const float values[2][7] = {{a.lifetime, a.repeatTime, a.textureFrameCount, a.blendMode, a.lodCutoff, a.textureStripCount, a.sortOrder},
                                {b.lifetime, b.repeatTime, b.textureFrameCount, b.blendMode, b.lodCutoff, b.textureStripCount, b.sortOrder}};
    for (int i = 0; i < 7; ++i) {
      if (!near(values[0][i], values[1][i], 0.01f)) {
        return false;
      }
    }
    for (int c = 0; c < kEmitterCurveCount; ++c) {
      const EmitterCurve& x = a.curves[static_cast<std::size_t>(c)];
      const EmitterCurve& y = b.curves[static_cast<std::size_t>(c)];
      if (!near(x.xRange, y.xRange, 0.01f) || x.keys.size() != y.keys.size()) {
        return false;
      }
      for (std::size_t k = 0; k < x.keys.size(); ++k) {
        if (!near(x.keys[k].x, y.keys[k].x, 0.001f) || !near(x.keys[k].y, y.keys[k].y, 0.001f) || !near(x.keys[k].z, y.keys[k].z, 0.001f)) {
          return false;
        }
      }
    }
    return true;
  }

  TEST(Emitter, ANewEmitterWritesAndReadsBack)
  {
    const EmitterBlueprint made = NewEmitter();
    const std::string text = WriteEmitter(made);
    EmitterBlueprint read;
    std::string error;
    ASSERT_TRUE(ParseEmitter(text, read, error)) << error;
    EXPECT_TRUE(Same(made, read));
    EXPECT_EQ(WriteEmitter(read), text);
    // Retail's layout: the header first, the curves in the file's order.
    EXPECT_EQ(text.rfind("EmitterBlueprint {\n\tBlueprintId = 'new_emitter',\n\tLifetime = 10.00,\n", 0), 0U);
    EXPECT_LT(text.find("XDirectionCurve"), text.find("RampSelectionCurve"));
    EXPECT_NE(text.find("\t\t\t{ x=5.000,y=1.000,z=0.000 },\n"), std::string::npos); // the emit rate's key
  }

  TEST(Emitter, OtherSpellingsAndUnknownKeysAreKept)
  {
    const std::string text = R"(-- a hand-written emitter
EmitterBlueprint {
    BlueprintId = "hand",  Lifetime = 2, Blendmode = 3,
    Gravity = true, Flat = 1,
    Texture = '/textures/particles/a.dds',
    Note = { 'kept', 1 },
    SizeCurve = { XRange = 2, Keys = { { x = 0, y = 1.5, z = 0.25 }, { 1, 2, 3 } } },
}
)";
    EmitterBlueprint read;
    std::string error;
    ASSERT_TRUE(ParseEmitter(text, read, error)) << error;
    EXPECT_EQ(read.blueprintId, "hand");
    EXPECT_FLOAT_EQ(read.blendMode, 3.0f);
    EXPECT_TRUE(read.flags[kGravity]);
    EXPECT_TRUE(read.flags[kFlat]);
    EXPECT_EQ(read.texture, "/textures/particles/a.dds");
    ASSERT_EQ(read.curves[kSize].keys.size(), 2U);
    EXPECT_FLOAT_EQ(read.curves[kSize].keys[0].z, 0.25f);
    EXPECT_FLOAT_EQ(read.curves[kSize].keys[1].y, 2.0f);
    ASSERT_EQ(read.extra.size(), 1U);
    EXPECT_EQ(read.extra[0].first, "Note");
    EXPECT_EQ(read.extra[0].second, "{ 'kept', 1 }");
    // Written and read again: the same emitter.
    EmitterBlueprint again;
    ASSERT_TRUE(ParseEmitter(WriteEmitter(read), again, error)) << error;
    EXPECT_TRUE(Same(read, again));
  }

  TEST(Emitter, NotAnEmitterSaysWhere)
  {
    EmitterBlueprint read;
    std::string error;
    EXPECT_FALSE(ParseEmitter("BeamBlueprint { Length = 1 }", read, error));
    EXPECT_NE(error.find("not an EmitterBlueprint"), std::string::npos);
    EXPECT_FALSE(ParseEmitter("EmitterBlueprint {\n  Lifetime = ,\n}", read, error));
    EXPECT_EQ(error.rfind("line 2", 0), 0U) << error;
  }

  TEST(Emitter, TheGamesEmittersReadAndWriteBack)
  {
    const std::string folder = faf::editor::test::EnvText("FAF_RETAIL_EMITTERS");
    if (folder.empty()) {
      GTEST_SKIP() << "FAF_RETAIL_EMITTERS is not set (a folder of the game's effects/emitters/*.bp)";
    }
    int emitters = 0;
    int others = 0;
    int identical = 0;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
      std::ifstream in(entry.path(), std::ios::binary);
      std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      std::string unix;
      for (const char c : text) {
        if (c != '\r') {
          unix += c;
        }
      }
      if (unix.rfind("EmitterBlueprint", 0) != 0) {
        ++others; // TrailEmitterBlueprint, BeamBlueprint
        continue;
      }
      ++emitters;
      EmitterBlueprint read;
      std::string error;
      ASSERT_TRUE(ParseEmitter(unix, read, error)) << entry.path().filename().string() << ": " << error;
      const std::string written = WriteEmitter(read);
      identical += written == unix ? 1 : 0;
      EmitterBlueprint again;
      ASSERT_TRUE(ParseEmitter(written, again, error)) << entry.path().filename().string() << ": " << error;
      EXPECT_TRUE(Same(read, again)) << entry.path().filename().string();
    }
    std::printf("emitters %d (others %d), written byte for byte as the file: %d\n", emitters, others, identical);
    EXPECT_GT(emitters, 2000);
  }
  TEST(Emitter, CurvesSampleAsTheEngineDoes)
  {
    EmitterCurve curve;
    curve.keys = {{10.0f, 4.0f, 2.0f}, {0.0f, 0.0f, 0.0f}}; // out of order: sorted as SEfxCurve keeps them
    EXPECT_FLOAT_EQ(EmitterCurveValue(curve, 5.0f, 0.5f), 2.0f);     // halfway, no spread at random 0.5
    EXPECT_FLOAT_EQ(EmitterCurveValue(curve, 5.0f, 1.0f), 2.5f);     // + 0.5 * the interpolated spread 1
    EXPECT_FLOAT_EQ(EmitterCurveValue(curve, -3.0f, 0.5f), 0.0f);    // before the first key
    EXPECT_FLOAT_EQ(EmitterCurveValue(curve, 30.0f, 0.0f), 3.0f);    // after the last: 4 - 0.5 * 2
    EXPECT_FLOAT_EQ(EmitterCurveValue(EmitterCurve{}, 1.0f, 1.0f), 0.0f);
  }

  TEST(Emitter, EmissionCarriesItsFractionsAndSpreadsOverTheTick)
  {
    EmitterBlueprint e = NewEmitter();
    e.curves[kEmitRate].keys = {{0.0f, 2.5f, 0.0f}};
    e.curves[kVelocity].keys = {{0.0f, 2.0f, 0.0f}};
    e.curves[kYDirection].keys = {{0.0f, 1.0f, 0.0f}};
    e.flags[kGravity] = true;
    const auto half = [] { return 0.5f; };
    float carry = 0.0f;
    std::vector<int> counts;
    for (int tick = 0; tick < 4; ++tick) {
      counts.push_back(static_cast<int>(EmitTick(e, static_cast<float>(tick), carry, half).size()));
    }
    EXPECT_EQ(counts, (std::vector<int>{2, 3, 2, 3}));
    carry = 0.6f;
    const std::vector<EmittedParticle> three = EmitTick(e, 0.0f, carry, half);
    ASSERT_EQ(three.size(), 3U);
    EXPECT_FLOAT_EQ(three[1].birth, 1.0f / 3.0f); // InterpolateEmission: a third of a tick apart
    EXPECT_FLOAT_EQ(three[0].dir[1], 2.0f);       // direction times velocity
    EXPECT_FLOAT_EQ(three[0].accel[1], -0.02f);   // gravity
    EXPECT_FLOAT_EQ(three[0].angle, 180.0f * 0.017453292f);
    e.flags[kInterpolateEmission] = false;
    carry = 0.0f;
    EXPECT_FLOAT_EQ(EmitTick(e, 1.0f, carry, half).back().birth, 0.0f);
  }

  TEST(Emitter, TypeTagsAsTheEngineSetsThem)
  {
    EmitterBlueprint e = NewEmitter();
    EXPECT_EQ(EmitterTypeTag(e), "TRamp");
    e.flags[kFlat] = true;
    EXPECT_EQ(EmitterTypeTag(e), "TRampFlat");
    e.textureFrameCount = 4.0f;
    EXPECT_EQ(EmitterTypeTag(e), "TRampAnimateFlat");
    e.flags[kAlignRotation] = true;
    EXPECT_EQ(EmitterTypeTag(e), "TRampAnimateAlign");
    EXPECT_FALSE(EmitterFinished(e, 9.0f));
    EXPECT_TRUE(EmitterFinished(e, 10.0f));
    e.lifetime = -1.0f;
    EXPECT_FALSE(EmitterFinished(e, 1e6f));
  }
  bool SameFlat(const FlatBlueprint& a, const FlatBlueprint& b)
  {
    if (a.kind != b.kind || a.fields.size() != b.fields.size()) {
      return false;
    }
    for (std::size_t i = 0; i < a.fields.size(); ++i) {
      const FlatValue& x = a.fields[i].second;
      const FlatValue& y = b.fields[i].second;
      const auto near = [](const float p, const float q) { return std::fabs(p - q) <= 1e-5f * std::max(1.0f, std::fabs(p)); };
      if (a.fields[i].first != b.fields[i].first || x.kind != y.kind || x.flag != y.flag || x.text != y.text || !near(x.number, y.number)) {
        return false;
      }
      for (int c = 0; c < 4; ++c) {
        if (!near(x.color[static_cast<std::size_t>(c)], y.color[static_cast<std::size_t>(c)])) {
          return false;
        }
      }
    }
    return true;
  }

  TEST(Emitter, BeamsWithCommentsAndColoursReadAndWriteBack)
  {
    const std::string text = "BeamBlueprint {\n    Lifetime = 3.0,\n    TextureName = '/textures/particles/beam_white_03.dds',\n"
                             "    Thickness = 0.0175,\n    StartColor = {x=0,y=0.5,z=1,w=0}, # R,G,B,A\n}\n";
    FlatBlueprint beam;
    std::string error;
    ASSERT_TRUE(ParseFlatBlueprint(text, beam, error)) << error;
    EXPECT_EQ(beam.kind, "BeamBlueprint");
    ASSERT_EQ(beam.fields.size(), 4U);
    EXPECT_FLOAT_EQ(beam.Number("Thickness", 1.0f), 0.0175f);
    EXPECT_FLOAT_EQ(beam.Number("Length", 10.0f), 10.0f); // missing: the engine's default
    EXPECT_FLOAT_EQ(beam.Color("StartColor", {}).at(1), 0.5f);
    EXPECT_EQ(beam.Text("TextureName"), "/textures/particles/beam_white_03.dds");
    FlatBlueprint again;
    ASSERT_TRUE(ParseFlatBlueprint(WriteFlatBlueprint(beam), again, error)) << error;
    EXPECT_TRUE(SameFlat(beam, again));
    EXPECT_FALSE(ParseFlatBlueprint("EmitterBlueprint { }", again, error));
  }

  TEST(Emitter, TheGamesBeamsAndTrailsReadAndWriteBack)
  {
    const std::string folder = faf::editor::test::EnvText("FAF_RETAIL_EMITTERS");
    if (folder.empty()) {
      GTEST_SKIP() << "FAF_RETAIL_EMITTERS is not set";
    }
    int beams = 0;
    int trails = 0;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
      std::ifstream in(entry.path(), std::ios::binary);
      const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      const bool beam = text.rfind("BeamBlueprint", 0) == 0;
      if (!beam && text.rfind("TrailEmitterBlueprint", 0) != 0) {
        continue;
      }
      (beam ? beams : trails) += 1;
      FlatBlueprint read;
      std::string error;
      ASSERT_TRUE(ParseFlatBlueprint(text, read, error)) << entry.path().filename().string() << ": " << error;
      FlatBlueprint again;
      ASSERT_TRUE(ParseFlatBlueprint(WriteFlatBlueprint(read), again, error)) << entry.path().filename().string() << ": " << error;
      EXPECT_TRUE(SameFlat(read, again)) << entry.path().filename().string();
    }
    std::printf("beams %d, trails %d\n", beams, trails);
    EXPECT_GT(beams, 50);
    EXPECT_GT(trails, 100);
  }
  TEST(Emitter, TheBrowserGroupsByFactionAndKind)
  {
    EXPECT_STREQ(kEffectFactions[EffectFaction("/effects/emitters/aeon_light_displacement_missile_muzzleflash_01.bp")], "Aeon");
    EXPECT_STREQ(kEffectFactions[EffectFaction("/effects/emitters/SER_contrail.bp")], "Seraphim");
    EXPECT_STREQ(kEffectFactions[EffectFaction("/effects/emitters/destruction_damaged_smoke_01_emit.bp")], "Other");
    EXPECT_STREQ(kEffectKinds[EffectKind("/effects/emitters/cannon_muzzle_smoke_01_emit.bp")], "Muzzle"); // before smoke
    EXPECT_STREQ(kEffectKinds[EffectKind("/effects/emitters/destruction_damaged_smoke_01_emit.bp")], "Explosion");
    EXPECT_STREQ(kEffectKinds[EffectKind("/effects/emitters/contrail_ser_ohw_polytrail_01_emit.bp")], "Trail");
    EXPECT_STREQ(kEffectKinds[EffectKind("/effects/emitters/quantum_generator_beam_01_emit.bp")], "Beam");
    EXPECT_STREQ(kEffectKinds[EffectKind("/effects/emitters/zzz_01.bp")], "Other");
  }
} // namespace
