// Host test of the water2.fx source patch (src/moho/terrain/water/WaterEffectPatch): it must refuse text it does not
// recognise and leave it untouched, and, when FAF_STOCK_FX_DIR names a folder with FAF's stock water2.fx (extract it
// from effects.nx2; the file is not part of this repository), patch it completely and consistently: both lookups
// replaced, the helpers declared before the pixel shader, the braces balanced, and a second patch of the patched text
// refused (it must not stack).

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>

#include "moho/terrain/water/WaterEffectPatch.h"

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
    for (const std::string original :
         {std::string(),
          std::string("float4 main() : COLOR { return 0; }\n"),
          std::string("float4 HighFidelityPS(int x) : COLOR { return tex2D(ReflectionSampler, p); }\n")}) {
      std::string text = original;
      const moho::water::EffectPatchResult result = moho::water::PatchWaterEffect(text);
      CHECK(!result.patched);
      CHECK(!result.error.empty());
      CHECK(text == original);
    }
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
    std::string text = stock;
    const moho::water::EffectPatchResult result = moho::water::PatchWaterEffect(text);
    CHECK(result.patched);
    if (!result.patched) {
      std::printf("  %s\n", result.error.c_str());
      return;
    }
    CHECK(text.size() > stock.size());
    CHECK(Braces(text) == Braces(stock));
    CHECK(Count(text, "tex2D(ReflectionSampler, refractionPos)") == 0);
    CHECK(Count(text, "tex2D(RefractionSampler, refractionPos)") == 0);
    CHECK(Count(text, "FafSampleReflection(refractionPos)") == 1);
    CHECK(Count(text, "FafSampleRefraction(refractionPos, backGroundPixels)") == 1);
    CHECK(Count(text, "float3 faf_WaterFilter") == 1);
    CHECK(Count(text, "returnPixels.rgb = water;") == 0);
    CHECK(Count(text, "returnPixels.rgb = FafShoreline(water, screenPos);") == 1);
    // the helpers come before the pixel shader that calls them, and after the samplers they read
    const std::size_t helper = text.find("float4 FafSampleReflection(");
    const std::size_t shader = text.find("float4 HighFidelityPS(");
    CHECK(helper != std::string::npos && shader != std::string::npos && helper < shader);
    CHECK(text.find("sampler ReflectionSampler") < helper);
    CHECK(text.find("sampler RefractionSampler") < helper);
    // the techniques and everything after the pixel shader are untouched
    const std::size_t tail = stock.rfind("technique");
    CHECK(tail != std::string::npos && text.substr(text.size() - (stock.size() - tail)) == stock.substr(tail));
    // a patched text is not patched again
    std::string again = text;
    CHECK(!moho::water::PatchWaterEffect(again).patched);
    CHECK(again == text);
  }
} // namespace

int main()
{
  TestRefusesUnknownText();
  if (const char* const directory = std::getenv("FAF_STOCK_FX_DIR"); directory != nullptr && *directory != '\0') {
    TestStockEffect(directory);
  } else {
    std::printf("FAF_STOCK_FX_DIR not set: the stock water2.fx checks are skipped\n");
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures == 0 ? 0 : 1;
}
