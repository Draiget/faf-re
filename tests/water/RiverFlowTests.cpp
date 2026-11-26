// Host test of the render side of rivers (src/moho/terrain/water/RiverFlow.h, docs/projects/RIVERS.md stages S3 and
// S4): the speed of a river from the height gradient and the depth, the white water, the flow of a block from the
// levels around it, the packing of the flow texture's texels, the two phases of the scrolled normals (nothing pops),
// the corners of a river block's mesh, and the source patch of water2.fx (it must refuse text it does not recognise and
// leave it untouched; with FAF_STOCK_FX_DIR naming a folder with FAF's stock water2.fx it must patch it completely,
// once, and also the text the wave simulation patch makes of it). Pure C++, no engine objects.

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>

#include "moho/terrain/water/RiverFlow.h"

namespace
{
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

#define NEAR(a, b, tolerance) CHECK(std::fabs(static_cast<double>(a) - static_cast<double>(b)) <= (tolerance))

  using namespace moho::water;

  void TestSpeed()
  {
    std::printf("speed: Manning's relation from the slope and the depth\n");
    NEAR(RiverSpeed(0.01f, 1.0f), 2.5, 1e-4); // the doc's examples
    NEAR(RiverSpeed(0.05f, 0.5f), 0.2236068 / 0.04 * std::pow(0.5, 2.0 / 3.0), 1e-3);
    CHECK(RiverSpeed(0.05f, 0.5f) > 3.4f && RiverSpeed(0.05f, 0.5f) < 3.6f);
    CHECK(RiverSpeed(0.5f, 4.0f) == kRiverMaxSpeed);                          // capped
    CHECK(RiverSpeed(0.0f, 1.0f) == 0.0f && RiverSpeed(-0.1f, 1.0f) == 0.0f); // a pool, a rise
    CHECK(RiverSpeed(0.01f, 0.0f) > 0.0f);                                    // a ford still flows (the least depth)
    NEAR(RiverSpeed(0.01f, 0.0f), RiverSpeed(0.01f, kRiverMinDepth), 1e-6);
    // faster where steeper, faster where deeper, linear in the scale until the cap
    float last = 0.0f;
    for (float s = 0.001f; s < 0.2f; s += 0.002f) {
      const float v = RiverSpeed(s, 0.6f);
      CHECK(v >= last);
      last = v;
    }
    last = 0.0f;
    for (float d = 0.05f; d < 5.0f; d += 0.1f) {
      const float v = RiverSpeed(0.004f, d);
      CHECK(v >= last);
      last = v;
    }
    NEAR(RiverSpeed(0.004f, 0.5f, 2.0f), 2.0 * RiverSpeed(0.004f, 0.5f), 1e-5);
    CHECK(RiverSpeed(0.01f, 1.0f, 0.0f) == 0.0f);
  }

  void TestTurbulence()
  {
    std::printf("white water: rapids and riffles, not pools\n");
    CHECK(RiverTurbulence(0.0f, 2.0f, 0.0f) == 0.0f);
    CHECK(RiverTurbulence(0.01f, 2.0f, RiverSpeed(0.01f, 2.0f)) == 0.0f); // a deep calm reach
    CHECK(RiverTurbulence(0.12f, 2.0f, RiverSpeed(0.12f, 2.0f)) > 0.99f); // a rapid
    CHECK(RiverTurbulence(0.07f, 2.0f, 3.0f) > 0.3f && RiverTurbulence(0.07f, 2.0f, 3.0f) < 0.7f);
    // shallow and fast: a riffle; shallow and slow: not
    CHECK(RiverTurbulence(0.02f, 0.1f, 3.0f) > 0.9f);
    CHECK(RiverTurbulence(0.02f, 0.1f, 2.0f) > 0.5f && RiverTurbulence(0.02f, 0.1f, 2.0f) < 0.9f);
    CHECK(RiverTurbulence(0.02f, 0.1f, 0.5f) == 0.0f);
    CHECK(RiverTurbulence(0.02f, 1.5f, 3.0f) == 0.0f);
    CHECK(
      RiverTurbulence(0.02f, 0.3f, 3.0f) > 0.1f && RiverTurbulence(0.02f, 0.3f, 3.0f) < 0.6f
    ); // the margin of a bank
    for (float s = 0.0f; s < 0.3f; s += 0.01f) {
      for (float d = 0.0f; d < 3.0f; d += 0.2f) {
        const float t = RiverTurbulence(s, d, RiverSpeed(s, d));
        CHECK(t >= 0.0f && t <= 1.0f);
      }
    }
  }

  void TestBlockFlow()
  {
    std::printf("flow of a block from the levels around it\n");
    // the surface drops 0.05 a unit toward +x: the levels a unit before and after the middle of the block
    const SRiverFlowTexel along = RiverBlockFlow(10.05f, 9.95f, 10.0f, 10.0f, 1.0f, 0.0f, 0.5f, false);
    CHECK(along.river);
    NEAR(along.dx, 1.0, 1e-6);
    NEAR(along.dz, 0.0, 1e-6);
    NEAR(along.speed, RiverSpeed(0.05f, 0.5f), 1e-4);
    // with no centreline direction the flow runs downhill
    const SRiverFlowTexel downhill = RiverBlockFlow(10.05f, 9.95f, 10.0f, 10.0f, 0.0f, 0.0f, 0.5f, false);
    NEAR(downhill.dx, 1.0, 1e-6);
    NEAR(downhill.speed, along.speed, 1e-6);
    const SRiverFlowTexel diagonal =
      RiverBlockFlow(10.0f, 10.0f, 10.0f + 0.05f, 10.0f - 0.05f, 0.0f, 0.0f, 0.5f, false);
    NEAR(diagonal.dx, 0.0, 1e-6);
    NEAR(diagonal.dz, 1.0, 1e-6);
    // the direction of the centreline wins over the gradient, and only the part of the drop along it counts
    const SRiverFlowTexel skew = RiverBlockFlow(10.05f, 9.95f, 10.0f, 10.0f, 0.0f, 1.0f, 0.5f, false);
    NEAR(skew.dz, 1.0, 1e-6);
    NEAR(skew.speed, 0.0, 1e-6); // the surface is level along it
    // a level reach has no speed, and a reach that rises along the direction none
    const SRiverFlowTexel pool = RiverBlockFlow(10.0f, 10.0f, 10.0f, 10.0f, 1.0f, 0.0f, 2.0f, false);
    CHECK(pool.river && pool.speed == 0.0f && pool.turbulence == 0.0f);
    const SRiverFlowTexel up = RiverBlockFlow(9.9f, 10.1f, 10.0f, 10.0f, 1.0f, 0.0f, 2.0f, false);
    CHECK(up.speed == 0.0f);
    // a fall: full speed and white, whatever the levels say
    const SRiverFlowTexel fall = RiverBlockFlow(10.0f, 10.0f, 10.0f, 10.0f, 0.0f, 1.0f, 2.0f, true);
    CHECK(fall.speed == kRiverMaxSpeed && fall.turbulence == 1.0f && fall.dz == 1.0f);
    // the flow scale of the river multiplies the speed
    NEAR(RiverBlockFlow(10.05f, 9.95f, 10.0f, 10.0f, 1.0f, 0.0f, 0.5f, false, 0.5f).speed, 0.5 * along.speed, 1e-4);
    // a block with no direction at all has none
    const SRiverFlowTexel none = RiverBlockFlow(10.0f, 10.0f, 10.0f, 10.0f, 0.0f, 0.0f, 1.0f, false);
    CHECK(none.river && none.dx == 0.0f && none.dz == 0.0f && none.speed == 0.0f);
  }

  void TestPacking()
  {
    std::printf("texel packing\n");
    CHECK(PackRiverFlowTexel(SRiverFlowTexel{}) == 0u);
    CHECK(!UnpackRiverFlowTexel(0u).river);
    SRiverFlowTexel t;
    t.river = true;
    t.dx = 0.6f;
    t.dz = -0.8f;
    t.speed = 3.0f;
    t.turbulence = 0.5f;
    const std::uint32_t bits = PackRiverFlowTexel(t);
    // A8R8G8B8: the shader's r, g are the direction, b the speed, a the turbulence
    const std::uint32_t a = bits >> 24, r = (bits >> 16) & 0xFF, g = (bits >> 8) & 0xFF, b = bits & 0xFF;
    CHECK(r == static_cast<std::uint32_t>((0.5f + 0.3f) * 255.0f + 0.5f));
    CHECK(g == static_cast<std::uint32_t>((0.5f - 0.4f) * 255.0f + 0.5f));
    CHECK(b == static_cast<std::uint32_t>(0.5f * 255.0f + 0.5f));
    CHECK(
      a == static_cast<std::uint32_t>(kRiverTexelAlphaFloor + 119 + 1) ||
      a == static_cast<std::uint32_t>(kRiverTexelAlphaFloor + 119)
    );
    const SRiverFlowTexel back = UnpackRiverFlowTexel(bits);
    CHECK(back.river);
    NEAR(back.dx, t.dx, 2.0 / 255.0);
    NEAR(back.dz, t.dz, 2.0 / 255.0);
    NEAR(back.speed, t.speed, kRiverMaxSpeed / 255.0);
    NEAR(back.turbulence, t.turbulence, 1.0 / 239.0);
    // a river is never alpha 0, even with no turbulence at all, and the alpha spans the floor to 255
    SRiverFlowTexel calm;
    calm.river = true;
    CHECK((PackRiverFlowTexel(calm) >> 24) == static_cast<std::uint32_t>(kRiverTexelAlphaFloor));
    SRiverFlowTexel white;
    white.river = true;
    white.turbulence = 1.0f;
    CHECK((PackRiverFlowTexel(white) >> 24) == 255u);
    // out of range values are clamped, not wrapped
    SRiverFlowTexel wild;
    wild.river = true;
    wild.dx = 3.0f;
    wild.dz = -3.0f;
    wild.speed = 100.0f;
    wild.turbulence = 5.0f;
    const std::uint32_t wildBits = PackRiverFlowTexel(wild);
    CHECK(
      ((wildBits >> 16) & 0xFF) == 255u && ((wildBits >> 8) & 0xFF) == 0u && (wildBits & 0xFF) == 255u &&
      (wildBits >> 24) == 255u
    );
    // round trip over a sweep: the error is the byte's
    double worst = 0.0;
    for (int i = 0; i < 360; i += 7) {
      for (float s = 0.0f; s <= kRiverMaxSpeed; s += 0.37f) {
        SRiverFlowTexel q;
        q.river = true;
        q.dx = static_cast<float>(std::cos(i * 0.0174533));
        q.dz = static_cast<float>(std::sin(i * 0.0174533));
        q.speed = s;
        q.turbulence = s / kRiverMaxSpeed;
        const SRiverFlowTexel u = UnpackRiverFlowTexel(PackRiverFlowTexel(q));
        worst = std::fmax(worst, std::fabs(u.dx - q.dx) + std::fabs(u.dz - q.dz));
        CHECK(std::fabs(u.speed - q.speed) <= kRiverMaxSpeed / 255.0 + 1e-4);
      }
    }
    CHECK(worst < 4.0 / 255.0 + 1e-3);
  }

  void TestPhase()
  {
    std::printf("the two phases of the scrolled normals: nothing pops\n");
    for (float ticks = 0.0f; ticks < 200.0f; ticks += 0.37f) {
      const SRiverPhase p = RiverPhase(ticks);
      CHECK(p.t0 >= 0.0f && p.t0 < 1.0f && p.t1 >= 0.0f && p.t1 < 1.0f);
      CHECK(p.w0 >= 0.0f && p.w0 <= 1.0f);
      // phase 1 runs half a period behind phase 0
      float gap = p.t1 - p.t0;
      gap += gap < 0.0f ? 1.0f : 0.0f;
      NEAR(gap, 0.5, 1e-4);
      // the layer that restarts has no weight at that moment: phase 0 restarts when t0 is 0, phase 1 when t0 is 0.5
      const float w1 = 1.0f - p.w0;
      if (p.t0 < 0.01f || p.t0 > 0.99f) {
        CHECK(p.w0 < 0.03f);
      }
      if (std::fabs(p.t0 - 0.5f) < 0.01f) {
        CHECK(w1 < 0.03f);
      }
    }
    // continuous in the time, including across both restarts (the weights change by less than the step's share)
    float last = RiverPhase(0.0f).w0;
    float worstJump = 0.0f;
    for (float ticks = 0.01f; ticks < 100.0f; ticks += 0.01f) {
      const float w = RiverPhase(ticks).w0;
      worstJump = std::fmax(worstJump, std::fabs(w - last));
      last = w;
    }
    CHECK(worstJump < 2.0f * 0.01f / (0.5f * kRiverPhaseTicks) + 1e-3f);
    // each phase's shift (speed x t x period) is the same at the instant the other one restarts: a continuous drift
    const SRiverPhase mid = RiverPhase(0.25f * kRiverPhaseTicks);
    NEAR(mid.t0, 0.25, 1e-5);
    NEAR(mid.t1, 0.75, 1e-5);
    NEAR(mid.w0, 0.5, 1e-5);
    CHECK(RiverPhase(0.5f * kRiverPhaseTicks).w0 > 0.999f);
  }

  void TestCorners()
  {
    std::printf("corners of a river block, shore levels\n");
    float level[4] = {10.0f, 9.0f, 8.0f, 7.0f};
    bool valid[4] = {true, true, true, true};
    CHECK(FillRiverBlockCorners(level, valid, 99.0f) == 4);
    CHECK(level[0] == 10.0f && level[3] == 7.0f);
    NEAR(RiverBlockLevel(level), 8.5, 1e-6);
    float some[4] = {10.0f, 0.0f, 8.0f, 0.0f};
    const bool someValid[4] = {true, false, true, false};
    CHECK(FillRiverBlockCorners(some, someValid, 99.0f) == 2);
    CHECK(some[1] == 9.0f && some[3] == 9.0f);
    NEAR(RiverBlockLevel(some), 9.0, 1e-6);
    float none[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    const bool noneValid[4] = {false, false, false, false};
    CHECK(FillRiverBlockCorners(none, noneValid, 5.5f) == 0);
    CHECK(none[0] == 5.5f && none[1] == 5.5f && none[2] == 5.5f && none[3] == 5.5f);
    // all nine vertices of a block
    float nine[9] = {10.0f, 9.0f, 8.0f, 0.0f, 0.0f, 0.0f, 4.0f, 0.0f, 2.0f};
    const bool nineValid[9] = {true, true, true, false, false, false, true, false, true};
    CHECK(FillRiverBlockCorners(nine, nineValid, 99.0f) == 5);
    NEAR(nine[4], 6.6, 1e-5);
    CHECK(nine[0] == 10.0f && nine[8] == 2.0f);
    // the level of a block equals the bilinear level of its middle on a linear slope
    const float slope[4] = {10.0f, 9.9f, 10.0f, 9.9f}; // 0.05 a unit toward +x over a 2 unit block
    NEAR(RiverBlockLevel(slope), 9.95, 1e-5);
    for (float l = -5.0f; l < 60.0f; l += 0.0173f) {
      const float q = RiverShoreLevel(l);
      CHECK(std::fabs(q - l) <= kRiverShoreStep * 0.5f + 1e-4f);
      CHECK(std::fabs(q / kRiverShoreStep - std::floor(q / kRiverShoreStep + 0.5f)) < 1e-3f);
    }
  }

  // ---- the source patch
  // -------------------------------------------------------------------------------------------------
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

  void TestRefusesUnknownText()
  {
    std::printf("the patch refuses text it does not recognise\n");
    std::string text = "float4 HighFidelityPS() { return 0; }\n";
    const std::string original = text;
    const RiverPatchResult result = PatchWaterRivers(text);
    CHECK(!result.patched);
    CHECK(!result.error.empty());
    CHECK(text == original);
    std::string empty;
    CHECK(!PatchWaterRivers(empty).patched && empty.empty());
  }

  // `base` is a water2.fx (stock, or as the wave simulation patch leaves it)
  void TestPatch(
    const std::string& base,
    const char* const label,
    const bool simulated
  )
  {
    std::printf("river patch on the %s text\n", label);
    std::string text = base;
    const RiverPatchResult result = PatchWaterRivers(text);
    CHECK(result.patched);
    if (!result.patched) {
      std::printf("  %s\n", result.error.c_str());
      return;
    }
    CHECK(text.size() > base.size());
    CHECK(Braces(text) == Braces(base));
    // the shipped reads of the layers stay as they are (the same instructions on a map without rivers)
    CHECK(Count(text, "float4 W0 = tex2D( NormalSampler0, inV.mLayer0 );") == 1);
    CHECK(Count(text, "float4 W3 = tex2D( NormalSampler3, inV.mLayer3 );") == 1);
    // both vertex shaders keep a river mesh's heights, and the shipped line is not there any more
    CHECK(Count(text, "inPos.y = waterRiverParams.x > 0.5 ? inPos.y : WaterElevation;") == 1);
    CHECK(Count(text, "position.y = waterRiverParams.x > 0.5 ? position.y : WaterElevation;") == 1);
    CHECK(Count(text, "inPos.y = WaterElevation;") == 0 || simulated);
    // the layers, the foam and the flow read are in, once
    for (int layer = 0; layer < 4; ++layer) {
      const std::string name = "float4 FafRiverLayer" + std::to_string(layer) + "(";
      CHECK(Count(text, name) == 1);
      CHECK(Count(text, "W" + std::to_string(layer) + " = FafRiverLayer" + std::to_string(layer) + "(W") == 1);
    }
    CHECK(Count(text, "float4 FafRiverFlow(float2 uv)") == 1);
    CHECK(Count(text, "float FafRiverWhite(float4 fl, float2 xz)") == 1);
    CHECK(Count(text, "float fafRiverWhite = FafRiverWhite(fafFlow, fafRiverXZ);") == 1);
    CHECK(Count(text, "float4 waterRiverParams;") == 1);
    CHECK(Count(text, "texture waterFlow;") == 1);
    // the river code of the pixel shader is behind a branch on a constant
    CHECK(Count(text, "if (waterRiverParams.w > 0.5)") >= 2);
    // the foam pattern the white water calls exists exactly once (the simulation patch's, or the one this patch adds)
    CHECK(Count(text, "float FafFoamAmount(") == 1);
    CHECK(Count(text, "float FafNoiseCorner(") == 1);
    CHECK(Count(text, "float FafGradNoise(") == 1);
    // order: the variables before the vertex shaders, the functions before the pixel shader that calls them, and after
    // the pattern and the samplers they read
    const std::size_t declared = text.find("float4 waterRiverParams;");
    const std::size_t lowVertex = text.find("LOWFIDELITY_VERTEX LowFidelityVS(");
    const std::size_t pixel = text.find("float4 HighFidelityPS(");
    const std::size_t layer0 = text.find("float4 FafRiverLayer0(");
    const std::size_t pattern = text.find("float FafFoamAmount(");
    CHECK(
      declared < lowVertex && lowVertex < pixel && layer0 < pixel &&
      pattern < text.find("float FafRiverWhite(float4 fl")
    );
    CHECK(text.find("sampler NormalSampler0") < layer0 && text.find("normalRepeatRate") < layer0);
    // the river block comes after the four reads and before the sum that uses them
    CHECK(text.find("float4 W3 = tex2D") < text.find("float4 fafFlow = FafRiverFlow(inV.mTexUV);"));
    CHECK(text.find("W3 = FafRiverLayer3(") < text.find("float4 sum = W0 + W1 + W2 + W3;"));
    // the white water is mixed in after the wave crests, before the result is written
    CHECK(text.find("water = lerp(water, waveCrestColor,") < text.find("float fafRiverWhite = "));
    CHECK(text.find("float fafRiverWhite = ") < text.find("returnPixels.rgb = water;"));
    // everything after the pixel shader's end (the techniques) is untouched
    const std::size_t tail = base.rfind("technique Water_HighFidelity");
    CHECK(tail != std::string::npos && text.substr(text.size() - (base.size() - tail)) == base.substr(tail));
    // a patched text is not patched again
    std::string again = text;
    CHECK(!PatchWaterRivers(again).patched);
    CHECK(again == text);
  }

  // What the wave simulation patch (WaterSimulation.cpp) does to the stock text where this patch looks: the height line
  // becomes the else branch of the projected grid, and the foam pattern is declared before the water vertex shader.
  std::string Simulated(
    const std::string& stock
  )
  {
    std::string text = stock;
    const std::string line = "inPos.y = WaterElevation;";
    text.replace(
      text.find(line),
      line.size(),
      "if (waterGridParams.x > 0.5)\n\t{\n\t\tinPos.xyz = FafWaterGridPosition(inTexUV, "
      "WaterElevation);\n\t}\n\telse\n\t{\n\t\t" +
        line + "\n\t}"
    );
    text.insert(
      text.find("VS_OUTPUT WaterVS("),
      "float FafNoiseCorner(float2 i) { return 0.0; }\nfloat FafGradNoise(float2 p) { return 0.0; }\n"
      "float FafFoamAmount(float foam, float2 xz, float sumA) { return 0.0; }\n"
    );
    return text;
  }

  void TestStockEffect(
    const std::string& directory
  )
  {
    std::string stock;
    if (!ReadFile(directory + "/water2.fx", stock)) {
      std::printf("water2.fx not found in %s\n", directory.c_str());
      ++gFailures;
      return;
    }
    TestPatch(stock, "stock", false);
    TestPatch(Simulated(stock), "simulated", true);
  }
} // namespace

int main()
{
  TestSpeed();
  TestTurbulence();
  TestBlockFlow();
  TestPacking();
  TestPhase();
  TestCorners();
  TestRefusesUnknownText();
  if (const char* const directory = std::getenv("FAF_STOCK_FX_DIR"); directory != nullptr && *directory != '\0') {
    TestStockEffect(directory);
  } else {
    std::printf("FAF_STOCK_FX_DIR not set: the stock water2.fx checks are skipped\n");
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures == 0 ? 0 : 1;
}
