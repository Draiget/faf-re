// Host test of the terrain water level map (src/moho/terrain/water/WaterLevelTexel.h, TerrainWaterLevelPatch): the
// packing of a block's level and abyss, the depth formula the shader mirrors (zero above the water, the pixel's own
// height), the patch refusing text it does not recognise, and, when FAF_STOCK_FX_DIR names a folder with FAF's stock
// terrain.fx, the patch of the real file: every read of the depth replaced, the helper before its first use, braces
// balanced, no stacking.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>

#include "moho/terrain/water/TerrainWaterLevelPatch.h"
#include "moho/terrain/water/WaterLevelTexel.h"

namespace
{
  using namespace moho::water;

  int gFailures = 0;
  int gChecks = 0;

#define CHECK(cond)                                                                                                    \
  do {                                                                                                                 \
    ++gChecks;                                                                                                         \
    if (!(cond)) {                                                                                                     \
      ++gFailures;                                                                                                     \
      std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                                      \
    }                                                                                                                  \
  } while (0)

  bool Near(
    const float a,
    const float b,
    const float tolerance = 1.0e-4f
  )
  {
    return std::fabs(a - b) <= tolerance;
  }

  std::size_t Count(
    const std::string& s,
    const std::string& needle
  )
  {
    std::size_t n = 0;
    for (std::size_t p = s.find(needle); p != std::string::npos; p = s.find(needle, p + needle.size())) {
      ++n;
    }
    return n;
  }

  long Braces(
    const std::string& s
  )
  {
    long depth = 0;
    for (const char c : s) {
      depth += c == '{' ? 1 : (c == '}' ? -1 : 0);
    }
    return depth;
  }

  void TestPacking()
  {
    CHECK(PackRaw16(0.0f) == 0u);
    CHECK(PackRaw16(25.0f) == 3200u);
    CHECK(PackRaw16(-3.0f) == 0u);
    CHECK(PackRaw16(kNoWaterLevel) == kNoWaterRaw);
    CHECK(PackRaw16(700.0f) == 65534u);
    const std::uint32_t texel = PackLevelTexel(30.0f, 25.0f);
    CHECK((texel & 0xFFFFu) == 3840u);
    CHECK((texel >> 16u) == 3200u);
    // the bytes the shader reads: b the low and g the high byte of the level, r the low and a the high byte of the
    // abyss
    CHECK((texel & 0xFFu) == 3840u % 256u && ((texel >> 8u) & 0xFFu) == 3840u / 256u);
    CHECK(((texel >> 16u) & 0xFFu) == 3200u % 256u && (texel >> 24u) == 3200u / 256u);
    CHECK((PackLevelTexel(kNoWaterLevel, kNoWaterLevel) & 0xFFFFu) == kNoWaterRaw);
  }

  void TestDepth()
  {
    const std::uint32_t pool = PackLevelTexel(20.0f, 10.0f); // range 10
    CHECK(Near(TexelDepth(pool, 20.0f), 0.0f));              // on the surface
    CHECK(Near(TexelDepth(pool, 15.0f), 0.5f));
    CHECK(Near(TexelDepth(pool, 10.0f), 1.0f));
    CHECK(Near(TexelDepth(pool, 2.0f), 1.0f)); // below the abyss: saturated
    // above the water: nothing, whatever the neighbours are (the tint cannot reach the bank)
    CHECK(TexelDepth(pool, 20.5f) == 0.0f);
    CHECK(TexelDepth(pool, 35.0f) == 0.0f);
    // the shore moves with the pixel's height, not with the block grid: two heights in one block, two depths
    CHECK(TexelDepth(pool, 19.0f) > TexelDepth(pool, 19.5f));
    // no water in the block
    CHECK(TexelDepth(PackLevelTexel(kNoWaterLevel, kNoWaterLevel), 0.0f) == 0.0f);
    // an abyss of no value (a body without one) counts as 0: the range is the level itself
    CHECK(Near(TexelDepth(PackLevelTexel(20.0f, kNoWaterLevel), 10.0f), 0.5f));
    // a level of the sea: the shipped normalisation (level - height) / (level - abyss)
    const std::uint32_t sea = PackLevelTexel(3.0f, 0.0f);
    CHECK(Near(TexelDepth(sea, 1.5f), 0.5f));
    // always a share
    for (float h = -2.0f; h < 60.0f; h += 3.7f) {
      const float d = TexelDepth(pool, h);
      CHECK(d >= 0.0f && d <= 1.0f);
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

  void TestRefusesUnknownText()
  {
    std::string nothing = "float4 main() { return 0; }";
    const std::string before = nothing;
    CHECK(!PatchTerrainWaterLevels(nothing).patched && nothing == before);
    // an anchor but no read of the depth
    std::string noRead = "sampler2D UtilitySamplerC = sampler_state {};\nfloat3 ApplyWaterColor(float3 viewDirection, "
                         "float a) { return 0; }\n";
    const std::string noReadBefore = noRead;
    CHECK(!PatchTerrainWaterLevels(noRead).patched && noRead == noReadBefore);
    // the sampler after the anchor
    std::string late =
      "float3 ApplyWaterColor(float3 viewDirection)\n{\n}\nsampler2D UtilitySamplerC = sampler_state {};\n"
      "float w = tex2D(UtilitySamplerC, inV.mTexWT * TerrainScale).g;\n";
    const std::string lateBefore = late;
    CHECK(!PatchTerrainWaterLevels(late).patched && late == lateBefore);
  }

  void TestSynthetic()
  {
    std::string s = "sampler2D UtilitySamplerC = sampler_state {};\n"
                    "float3 ApplyWaterColor(float3 viewDirection, float h, float d, float3 c) { return c; }\n"
                    "float a = tex2D( UtilitySamplerC, inV.mTexWT * TerrainScale).g;\n"
                    "float b = tex2D(UtilitySamplerC,pixel.mTexWT*TerrainScale).g;\n"
                    "float c = tex2Dproj( UtilitySamplerC, inV.mTexWT * TerrainScale).g;\n"
                    "float d = tex2D(UtilitySamplerC, position).g;\n";
    const TerrainWaterLevelPatchResult r = PatchTerrainWaterLevels(s);
    CHECK(r.patched && r.sites == 4);
    CHECK(Count(s, "FafWaterDepth(tex2D(UtilitySamplerC, position).g, (position).xy, inV.mTexWT.z)") == 1);
    CHECK(
      Count(
        s,
        "FafWaterDepth(tex2D( UtilitySamplerC, inV.mTexWT * TerrainScale).g, (inV.mTexWT * TerrainScale).xy, "
        "inV.mTexWT.z)"
      ) == 1
    );
    CHECK(
      Count(
        s,
        "FafWaterDepth(tex2D(UtilitySamplerC,pixel.mTexWT*TerrainScale).g, (pixel.mTexWT * TerrainScale).xy, "
        "pixel.mTexWT.z)"
      ) == 1
    );
    CHECK(
      Count(
        s,
        "FafWaterDepth(tex2Dproj( UtilitySamplerC, inV.mTexWT * TerrainScale).g, (inV.mTexWT * TerrainScale).xy, "
        "inV.mTexWT.z)"
      ) == 1
    );
    CHECK(s.find("float FafWaterDepth(") < s.find("float3 ApplyWaterColor("));
    CHECK(s.find("float4 fafWaterLevelParams;") < s.find("float FafWaterDepth("));
    std::string again = s;
    CHECK(!PatchTerrainWaterLevels(again).patched && again == s);
  }

  void TestStock(
    const std::string& dir
  )
  {
    std::string original;
    if (!ReadFile(dir + "/terrain.fx", original)) {
      std::printf("skipped: no terrain.fx in FAF_STOCK_FX_DIR\n");
      return;
    }
    std::string text = original;
    const TerrainWaterLevelPatchResult r = PatchTerrainWaterLevels(text);
    if (!r.patched) {
      std::printf("terrain.fx: %s\n", r.error.c_str());
    }
    CHECK(r.patched);
    CHECK(r.sites == 12);
    CHECK(Braces(text) == Braces(original));
    CHECK(Count(text, "FafWaterDepth(") == 13); // the twelve reads and the definition
    // no read of the baked depth is left: every fetch of UtilitySamplerC is an argument of FafWaterDepth or the
    // helper's own
    CHECK(Count(text, "UtilitySamplerC") == Count(original, "UtilitySamplerC") + 1);
    CHECK(text.find("float FafWaterDepth(") < text.find("float3 ApplyWaterColor("));
    // the anchors of the shadow and light patches are untouched
    CHECK(Count(text, "float ComputeShadow( float4 vShadowCoord )") == 1);
    CHECK(Count(text, "// calculate the lit pixels\nfloat4 CalculateLighting(") == 1);
    std::string again = text;
    CHECK(!PatchTerrainWaterLevels(again).patched && again == text);
  }
} // namespace

int main()
{
  TestPacking();
  TestDepth();
  TestRefusesUnknownText();
  TestSynthetic();
  if (const char* const dir = std::getenv("FAF_STOCK_FX_DIR"); dir != nullptr && *dir != '\0') {
    TestStock(dir);
  } else {
    std::printf("FAF_STOCK_FX_DIR not set: the stock terrain.fx checks are skipped\n");
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures == 0 ? 0 : 1;
}
