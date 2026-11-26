#include "moho/terrain/water/TerrainWaterLevelPatch.h"

#include <regex>

namespace moho::water
{
  namespace
  {
    constexpr const char* kDeclarations =
      R"HLSL(// ---- FAF water level map (TerrainWaterLevelPatch.cpp, docs/WATER_SIMULATION.md): the depth of the water at the pixel ----
float4 fafWaterLevelParams;   // x: 1 = UtilityTextureC holds the level and the abyss of each block (a map with water bodies), y, z: its size in texels

// The depth the water tints a terrain pixel with. A map without water bodies: the G channel of the water map, as shipped (`stock` is
// the shipped read). With bodies: the block's own level and abyss, read at the texel's centre (the linear filter then returns the
// texel unmixed), and the depth taken at the pixel's own height. The channels are the bytes of the texel (B8G8R8A8): b the low and
// g the high byte of the level, r the low and a the high byte of the abyss, in 1/128 unit; 0xFFFF is no water.
float FafWaterDepth(float stock, float2 uv, float height)
{
    if (fafWaterLevelParams.x < 0.5)
    {
        return stock;
    }
    float2 size = fafWaterLevelParams.yz;
    float2 texel = clamp(floor(uv * size), float2(0.0, 0.0), size - 1.0);
    float4 t = tex2Dlod(UtilitySamplerC, float4((texel + 0.5) / size, 0.0, 0.0));
    float4 b = floor(t * 255.0 + 0.5);
    float levelRaw = b.g * 256.0 + b.b;
    float abyssRaw = b.a * 256.0 + b.r;
    if (levelRaw > 65534.5)
    {
        return 0.0;
    }
    float level = levelRaw * 0.0078125;
    float abyss = abyssRaw > 65534.5 ? 0.0 : abyssRaw * 0.0078125;
    return saturate((level - height) / max(level - abyss, 0.01));
}

)HLSL";
  } // namespace

  TerrainWaterLevelPatchResult PatchTerrainWaterLevels(
    std::string& source
  )
  {
    TerrainWaterLevelPatchResult result;
    if (source.find("FafWaterDepth") != std::string::npos) {
      result.error = "terrain.fx: already patched";
      return result;
    }
    const std::string anchor = "float3 ApplyWaterColor(float3 viewDirection";
    const std::size_t anchorAt = source.find(anchor);
    if (anchorAt == std::string::npos || source.find(anchor, anchorAt + 1U) != std::string::npos) {
      result.error = "terrain.fx: ApplyWaterColor not found exactly once";
      return result;
    }
    const std::size_t samplerAt = source.find("sampler2D UtilitySamplerC");
    if (samplerAt == std::string::npos || samplerAt > anchorAt) {
      result.error = "terrain.fx: UtilitySamplerC is not declared before ApplyWaterColor";
      return result;
    }

    // every read of the depth: tex2D / tex2Dproj(UtilitySamplerC, X.mTexWT * TerrainScale).g, or of a coordinate the
    // shader made before (position, coordinates: the pixel shaders with that form have the vertex output `inV` in
    // scope)
    static const std::regex kRead(
      R"((tex2D|tex2Dproj)\(\s*UtilitySamplerC\s*,\s*([A-Za-z_][A-Za-z0-9_]*)(\.mTexWT\s*\*\s*TerrainScale)?\s*\)\.g)"
    );
    std::string out;
    out.reserve(source.size() + 2048U);
    std::size_t last = 0U;
    for (std::sregex_iterator it(source.begin(), source.end(), kRead), end; it != end; ++it) {
      const std::smatch& m = *it;
      const std::size_t at = static_cast<std::size_t>(m.position(0));
      const std::string whole = m.str(0);
      const std::string fetch = whole; // the shipped read, with its .g
      const bool direct = m.length(3) > 0;
      // the uv of the fetch, and the vertex output the pixel's height comes from
      const std::string uv = direct ? "(" + m.str(2) + ".mTexWT * TerrainScale).xy" : "(" + m.str(2) + ").xy";
      const std::string var = direct ? m.str(2) : "inV";
      out.append(source, last, at - last);
      out += "FafWaterDepth(" + fetch + ", " + uv + ", " + var + ".mTexWT.z)";
      last = at + whole.size();
      ++result.sites;
    }
    if (result.sites == 0) {
      result.error = "terrain.fx: no read of the water map's depth found";
      return result;
    }
    out.append(source, last, std::string::npos);
    out.insert(out.find(anchor), kDeclarations);
    source = std::move(out);
    result.patched = true;
    return result;
  }
} // namespace moho::water
