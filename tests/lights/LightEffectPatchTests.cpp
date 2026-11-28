// Host test of the effect source patch (src/moho/render/lights/LightEffectPatch): it must refuse text it does not
// recognise and leave it untouched, and, when FAF_STOCK_FX_DIR names a folder with FAF's stock mesh.fx and terrain.fx
// (extract them from effects.nx2; the files are not part of this repository), patch both completely and consistently.
// Called from main() in LightCollectorTests.cpp.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>

#include "moho/render/lights/LightEffectPatch.h"
#include "moho/terrain/water/WaterEffectPatch.h"

namespace
{
  using namespace moho::lights;

  int gPatchFailures = 0;
  int gPatchChecks = 0;

#define PCHECK(cond)                                                                                                   \
  do {                                                                                                                 \
    ++gPatchChecks;                                                                                                    \
    if (!(cond)) {                                                                                                     \
      ++gPatchFailures;                                                                                                \
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
          std::string("technique Foo < int a = 1; > { pass P0 { } }\n")}) {
      std::string text = original;
      EffectPatchResult mesh = PatchMeshEffect(text);
      PCHECK(!mesh.patched && !mesh.error.empty() && text == original);
      EffectPatchResult terrain = PatchTerrainEffect(text);
      PCHECK(!terrain.patched && !terrain.error.empty() && text == original);
    }
    PCHECK(EffectForName("mesh") == PatchedEffect::Mesh);
    PCHECK(EffectForName("terrain") == PatchedEffect::Terrain);
    PCHECK(EffectForName("water") == PatchedEffect::None);
    PCHECK(EffectForName("") == PatchedEffect::None);
  }

  void TestStockMesh(
    const std::string& dir
  )
  {
    std::string original;
    if (!ReadFile(dir + "/mesh.fx", original)) {
      std::printf("skipped: no mesh.fx in FAF_STOCK_FX_DIR\n");
      return;
    }
    std::string text = original;
    const EffectPatchResult r = PatchMeshEffect(text);
    if (!r.patched) {
      std::printf("mesh.fx: %s\n", r.error.c_str());
    }
    PCHECK(r.patched);
    PCHECK(r.techniques == 19); // the generator's count for this FAF version
    PCHECK(Braces(text) == Braces(original));
    PCHECK(Count(text, "pass PDynLight") == static_cast<std::size_t>(r.techniques));
    PCHECK(Count(text, "int dynLightPasses = 1;") == static_cast<std::size_t>(r.techniques));
    PCHECK(Count(text, "dynLightCamera.xyz") == 2);
    PCHECK(text.find("0.01 * vertex.depth.y") == std::string::npos);
    PCHECK(Count(text, "vertex.depth.y = length(vertex.viewDirection);") >= 2);
    PCHECK(Count(text, "vertex.texcoord0.z = dynLightDist;") == 1);
    PCHECK(text.size() > original.size());
    // the meshes keep the field's sun shadow whatever the terrain does (ren_DynLightsTerrainSunShadow)
    PCHECK(r.sunShadowSites == 1);
    PCHECK(Count(text, "vis = DynFieldSun(w.xyz / w.w);") == 1);
    PCHECK(Count(text, "* DynFieldSunTerrain(") == 0);

    std::string again = text;
    PCHECK(!PatchMeshEffect(again).patched && again == text); // already patched: refused, unchanged

    // a changed FAF file (the wreckage shader moved) is refused whole
    std::string broken = original;
    broken.replace(broken.find("0.01 * vertex.depth.y"), 21, "0.02 * vertex.depth.y");
    const std::string brokenBefore = broken;
    PCHECK(!PatchMeshEffect(broken).patched && broken == brokenBefore);
  }

  void TestStockTerrain(
    const std::string& dir
  )
  {
    std::string original;
    if (!ReadFile(dir + "/terrain.fx", original)) {
      std::printf("skipped: no terrain.fx in FAF_STOCK_FX_DIR\n");
      return;
    }
    std::string text = original;
    const EffectPatchResult r = PatchTerrainEffect(text);
    if (!r.patched) {
      std::printf("terrain.fx: %s\n", r.error.c_str());
    }
    PCHECK(r.patched);
    PCHECK(r.techniques == 33);
    PCHECK(Braces(text) == Braces(original));
    PCHECK(Count(text, "pass PDynLight") == static_cast<std::size_t>(r.techniques));
    PCHECK(Count(text, "int dynLightPasses = 1;") == static_cast<std::size_t>(r.techniques));
    PCHECK(Count(text, "light += DynLightTerrainFew(worldTerrain.xzy, inNormal);") == 1);
    PCHECK(Count(text, "float3 DynLightTerrain(") == 1);
    // the declarations come before their first use
    PCHECK(text.find("float3 DynLightTerrain(") < text.find("light += DynLightTerrain("));
    PCHECK(text.find("float4 TerrainLightsPS(") < text.find("technique TTerrainDepth"));
    // the terrain reads the sun shadow through the switchable DynFieldSunTerrain (ren_DynLightsTerrainSunShadow, off
    // by default), never DynFieldSun directly; the field declaration comes first
    PCHECK(r.sunShadowSites > 0);
    PCHECK(Count(text, "float DynFieldSunTerrain(") == 1);
    PCHECK(Count(text, "* DynFieldSun(") == 0);
    PCHECK(Count(text, "* DynFieldSunTerrain(") >= static_cast<std::size_t>(r.sunShadowSites));
    PCHECK(text.find("float DynFieldSunTerrain(") < text.find("* DynFieldSunTerrain("));
    // the sun dimming under water stays wrapped around the shadow
    PCHECK(Count(text, "FafSunUnder(") >= 2);

    std::string again = text;
    PCHECK(!PatchTerrainEffect(again).patched && again == text);
  }

  // water2.fx: the light patch declares the field and lights the water; the water filter patch (Water Quality) that
  // comes after it in the effect builder still finds its anchors, and the two together do not stack on a second pass.
  void TestStockWater(
    const std::string& dir
  )
  {
    std::string original;
    if (!ReadFile(dir + "/water2.fx", original)) {
      std::printf("skipped: no water2.fx in FAF_STOCK_FX_DIR\n");
      return;
    }
    std::string text = original;
    const EffectPatchResult r = PatchWaterEffect(text);
    if (!r.patched) {
      std::printf("water2.fx: %s\n", r.error.c_str());
    }
    PCHECK(r.patched);
    PCHECK(Braces(text) == Braces(original));
    PCHECK(Count(text, "float3 DynFieldWater(") == 1 || Count(text, "dynField") > 0);
    std::string again = text;
    PCHECK(!PatchWaterEffect(again).patched && again == text);

    // the water filter patch continues from the lit text
    std::string chained = text;
    const moho::water::EffectPatchResult filtered = moho::water::PatchWaterEffect(chained);
    if (!filtered.patched) {
      std::printf("water2.fx (filter after lights): %s\n", filtered.error.c_str());
    }
    PCHECK(filtered.patched);
    PCHECK(Count(chained, "dynField") == Count(text, "dynField")); // the filter patch left the light patch alone
    PCHECK(Braces(chained) >= Braces(text));
  }
} // namespace

int RunPatchTests(
  int& checks
)
{
  TestRefusesUnknownText();
  if (const char* const dir = std::getenv("FAF_STOCK_FX_DIR"); dir != nullptr && *dir != '\0') {
    TestStockMesh(dir);
    TestStockTerrain(dir);
    TestStockWater(dir);
  } else {
    std::printf("effect patch: FAF_STOCK_FX_DIR not set, stock-file tests skipped\n");
  }
  checks += gPatchChecks;
  return gPatchFailures;
}
