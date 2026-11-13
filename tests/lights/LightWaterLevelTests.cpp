// Host test of the water level table of the light field (src/moho/render/lights/LightWaterLevels.h): the 16-bit
// packing, the block order, the lookup the field's shader mirrors (a lake never takes the level of the sea beside it),
// the share of a light path under water for two levels, and, with FAF_STOCK_FX_DIR set, that the patched terrain
// effect takes the level of the sun-under-water dimming from the field. Called from main() in LightCollectorTests.cpp.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "moho/render/lights/LightEffectPatch.h"
#include "moho/render/lights/LightWaterLevels.h"

namespace
{
  using namespace moho::lights;

  int gLevelFailures = 0;
  int gLevelChecks = 0;

#define LCHECK(cond)                                                                                                   \
  do {                                                                                                                 \
    ++gLevelChecks;                                                                                                    \
    if (!(cond)) {                                                                                                     \
      ++gLevelFailures;                                                                                                \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  bool Near(
    const float a,
    const float b,
    const float tolerance = 1.0e-5f
  )
  {
    return std::fabs(a - b) <= tolerance;
  }

  void TestPacking()
  {
    // exact multiples of 1/128 survive; the others are rounded to the nearest
    for (const float level : {0.0f, 0.5f, 3.0f, 17.25f, 25.0f, 40.0f, 123.5f, 511.0f}) {
      LCHECK(UnpackWaterLevel(PackWaterLevel(level)) == level);
    }
    LCHECK(Near(UnpackWaterLevel(PackWaterLevel(25.3f)), 25.3f, 0.5f / 128.0f + 1.0e-6f));
    LCHECK(Near(UnpackWaterLevel(PackWaterLevel(0.003f)), 0.0f, 0.5f / 128.0f + 1.0e-6f));
    // no water, the engine's sentinel, NaN and anything very low are "none"
    LCHECK(PackWaterLevel(kNoWaterLevel) == kNoWaterRaw);
    LCHECK(PackWaterLevel(-1.0e30f) == kNoWaterRaw);
    LCHECK(PackWaterLevel(std::nanf("")) == kNoWaterRaw);
    LCHECK(UnpackWaterLevel(kNoWaterRaw) == kNoWaterLevel);
    // a level at or below the lowest ground covers nothing: stored as 0, never as "none" or wrapped
    LCHECK(PackWaterLevel(-2.0f) == 0U);
    LCHECK(PackWaterLevel(-999.0f) == 0U);
    // the top of the range stays below the "none" code
    LCHECK(PackWaterLevel(600.0f) == 65534U);
    LCHECK(PackWaterLevel(600.0f) != kNoWaterRaw);
    LCHECK(WaterBlocksPerSide(0) == 0U && WaterBlocksPerSide(1) == 0U);
    LCHECK(WaterBlocksPerSide(2) == 0U && WaterBlocksPerSide(3) == 1U);
    LCHECK(WaterBlocksPerSide(513) == 256U && WaterBlocksPerSide(1025) == 512U);
  }

  // A map of 8 x 6 blocks: the sea at 25 everywhere, a lake at 40 in blocks x 1..3, z 1..2, a dry body at x 6, z 4..5.
  struct Table
  {
    static constexpr std::uint32_t kX = 8;
    static constexpr std::uint32_t kZ = 6;
    std::vector<std::uint32_t> words;
  };

  float LevelOfBlock(
    const void*,
    const std::int32_t x,
    const std::int32_t z
  )
  {
    const std::int32_t bx = x / 2;
    const std::int32_t bz = z / 2;
    if (bx >= 1 && bx <= 3 && bz >= 1 && bz <= 2) {
      return 40.0f;
    }
    if (bx == 6 && bz >= 4) {
      return kNoWaterLevel;
    }
    return 25.0f;
  }

  Table MakeTable()
  {
    Table t;
    t.words = BuildWaterLevelWords(nullptr, &LevelOfBlock, Table::kX, Table::kZ);
    return t;
  }

  void TestTableAndLookup()
  {
    const Table t = MakeTable();
    LCHECK(t.words.size() == (Table::kX * Table::kZ + 1U) / 2U);
    // every block reads back its own level from the middle of the block, in the water map's order
    for (std::uint32_t bz = 0; bz < Table::kZ; ++bz) {
      for (std::uint32_t bx = 0; bx < Table::kX; ++bx) {
        const float expected =
          LevelOfBlock(nullptr, static_cast<std::int32_t>(bx * 2), static_cast<std::int32_t>(bz * 2));
        const float got = WaterLevelAt(
          t.words.data(),
          Table::kX,
          Table::kZ,
          static_cast<float>(bx) * 2.0f + 1.0f,
          static_cast<float>(bz) * 2.0f + 1.0f
        );
        LCHECK(got == expected);
      }
    }
    // the block edges: a position belongs to the block it starts, so the lake ends exactly at x = 8
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 2.0f, 2.0f) == 40.0f);
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 7.999f, 3.0f) == 40.0f);
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 8.0f, 3.0f) == 25.0f);
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 1.999f, 3.0f) == 25.0f);
    // outside the map the nearest block stands (the clamp of the shader)
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, -50.0f, -50.0f) == 25.0f);
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 500.0f, 500.0f) == 25.0f);
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 13.0f, 99.0f) == kNoWaterLevel);
    // a dry body is "no water" and an odd block count (the last word holds one block) reads correctly
    LCHECK(WaterLevelAt(t.words.data(), Table::kX, Table::kZ, 13.0f, 9.0f) == kNoWaterLevel);
    const std::vector<std::uint32_t> odd = BuildWaterLevelWords(nullptr, &LevelOfBlock, 3U, 3U);
    LCHECK(odd.size() == 5U);
    LCHECK(
      WaterLevelAt(odd.data(), 3U, 3U, 5.0f, 5.0f) == 40.0f
    ); // block (2, 2) is the last one, in the low half of word 4
    LCHECK(WaterLevelAt(odd.data(), 3U, 3U, 3.0f, 3.0f) == 40.0f);
    LCHECK(WaterLevelAt(odd.data(), 3U, 3U, 1.0f, 1.0f) == 25.0f);
  }

  void TestPathFraction()
  {
    // one level: the single-level result of before (lights above the sea, a receiver on the bed)
    LCHECK(WaterPathFraction(30.0f, 40.0f, 25.0f, 25.0f) == 0.0f);     // both above
    LCHECK(WaterPathFraction(10.0f, 20.0f, 25.0f, 25.0f) == 1.0f);     // both under
    LCHECK(Near(WaterPathFraction(15.0f, 35.0f, 25.0f, 25.0f), 0.5f)); // crosses the surface half way
    LCHECK(Near(WaterPathFraction(35.0f, 15.0f, 25.0f, 25.0f), 0.5f)); // the same from the other end
    LCHECK(WaterPathFraction(25.0f, 25.0f, 25.0f, 25.0f) == 0.0f);     // on the surface
    LCHECK(WaterPathFraction(25.0f, 10.0f, 25.0f, 25.0f) == 1.0f);     // one end on it, the other under
    // a receiver on the sea bed (level 25) and a light 6 above a lake (level 40): the path is under the sea for the
    // part before it crosses 25 (a single level 40 would have claimed all of it under water, 25 none of the lake)
    const float f = WaterPathFraction(20.0f, 46.0f, 25.0f, 40.0f);
    LCHECK(f > 0.0f && f < 1.0f);
    LCHECK(Near(f, 5.0f / 11.0f)); // depth -5 at p, +6 at q
    // the old single level for the same pair would be wrong either way
    LCHECK(WaterPathFraction(20.0f, 46.0f, 40.0f, 40.0f) != f);
    LCHECK(WaterPathFraction(20.0f, 46.0f, 25.0f, 25.0f) != f);
    // symmetry in the endpoints
    LCHECK(Near(WaterPathFraction(46.0f, 20.0f, 40.0f, 25.0f), f));
    // a dry end (no water over it) takes nearly nothing of a path that is under water at the other end only briefly
    const float dry = WaterPathFraction(5.0f, 8.0f, kNoWaterLevel, 40.0f);
    LCHECK(dry >= 0.0f && dry < 0.01f);
    LCHECK(WaterPathFraction(5.0f, 8.0f, kNoWaterLevel, kNoWaterLevel) == 0.0f);
    // the fraction is always a share
    for (float py = -10.0f; py <= 60.0f; py += 7.0f) {
      for (float qy = -10.0f; qy <= 60.0f; qy += 5.0f) {
        for (const float lp : {25.0f, 40.0f, kNoWaterLevel}) {
          for (const float lq : {25.0f, 40.0f, kNoWaterLevel}) {
            const float share = WaterPathFraction(py, qy, lp, lq);
            LCHECK(share >= 0.0f && share <= 1.0f);
          }
        }
      }
    }
  }

  bool ReadFile(
    const std::string& path,
    std::string& out
  )
  {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
      return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
  }

  // The patched terrain effect: the sun-under-water function reads the level from the field, after the field block
  // that defines the reader and before CalculateLighting and every other read of the shadow it wraps.
  void TestTerrainPatch(
    const std::string& dir
  )
  {
    std::string text;
    if (!ReadFile(dir + "/terrain.fx", text)) {
      std::printf("water levels: no terrain.fx in FAF_STOCK_FX_DIR, patch check skipped\n");
      return;
    }
    const EffectPatchResult r = PatchTerrainEffect(text);
    LCHECK(r.patched);
    const auto find = [&](const std::string& needle) {
      return text.find(needle);
    };
    LCHECK(find("float4 dynFieldWater;") != std::string::npos);
    LCHECK(find("float DynFieldWaterLevel(float3 p, float fallback)") != std::string::npos);
    LCHECK(find("float FafSunUnder(float sun, float3 p)") != std::string::npos);
    LCHECK(find("DynFieldWaterLevel(p, WaterElevation) - p.y") != std::string::npos);
    // no read of the highest level of the map is left in the dimming
    LCHECK(find("max(WaterElevation - p.y, 0.0)") == std::string::npos);
    LCHECK(find("float DynFieldWaterLevel(") < find("float FafSunUnder("));
    LCHECK(find("float FafSunUnder(") < find("float4 CalculateLighting("));
    LCHECK(find("float FafSunUnder(") < find("shadow = FafSunUnder("));
    // the lookup is gated by the field and by the flag the binding sets only on a map with water bodies, and falls
    // back to the map's level otherwise
    LCHECK(find("dynFieldWater.x > 0.5") != std::string::npos);
    LCHECK(find("return fallback;") != std::string::npos);
    std::string water;
    if (ReadFile(dir + "/water2.fx", water)) {
      const EffectPatchResult w = PatchWaterEffect(water);
      LCHECK(w.patched);
      // the water effect carries the same declaration (its per-lake level is its own WaterElevation, set per draw)
      LCHECK(water.find("float4 dynFieldWater;") != std::string::npos);
    }
  }
} // namespace

int RunWaterLevelTests(
  int& checks
)
{
  gLevelChecks = 0;
  gLevelFailures = 0;
  TestPacking();
  TestTableAndLookup();
  TestPathFraction();
  if (const char* const dir = std::getenv("FAF_STOCK_FX_DIR"); dir != nullptr && *dir != '\0') {
    TestTerrainPatch(dir);
  }
  checks += gLevelChecks;
  return gLevelFailures;
}
