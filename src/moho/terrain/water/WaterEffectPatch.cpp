#include "moho/terrain/water/WaterEffectPatch.h"

#include <cstddef>
#include <string_view>
#include <utility>

namespace moho::water
{
  namespace
  {
    using std::size_t;
    using std::string;
    using std::string_view;

    constexpr size_t npos = string::npos;

    // The two lookups of HighFidelityPS and the function the filter goes in front of.
    constexpr string_view kReflectionLookup = "float4 unitReflections = tex2D(ReflectionSampler, refractionPos);";
    constexpr string_view kRefractionLookup = "float4 refractedPixels = tex2D(RefractionSampler, refractionPos);";
    constexpr string_view kPixelShader = "float4 HighFidelityPS(";
    constexpr string_view kResult = "returnPixels.rgb = water;";

    // What the replaced lines call. All of it is declared before HighFidelityPS, after the samplers.
    //
    // FafFootprint: the size in uv of one screen pixel of the lookup position, per axis, limited so a wild normal
    // cannot smear a reflection across the screen. The tap offsets are in units of that footprint: a rotated grid (4
    // taps) and the same plus four between them (8).
    constexpr const char* kDeclarations = R"HLSL(
// ---- FAF water quality (WaterEffectPatch): filtered reflection and refraction lookups, see docs/WATER_QUALITY.md ----
float3 faf_WaterFilter = float3(0, 0, 0); // reflection taps (0, 4, 8), refraction taps (0, 4), shoreline blend (0, 1)

float2 FafFootprint(float2 uv)
{
    return min(abs(ddx(uv)) + abs(ddy(uv)), float2(0.02, 0.02));
}

// One reflection tap, accumulated alpha weighted: rgb * a and a. The rgb of a texel that holds no reflection (a = 0) is the clear colour and
// must not leak into the average.
void FafReflectionTap(float2 uv, inout float4 acc)
{
    float4 t = tex2D(ReflectionSampler, uv);
    acc.rgb += t.rgb * t.a;
    acc.a += t.a;
}

float4 FafSampleReflection(float2 uv)
{
    if (faf_WaterFilter.x < 3.5)
        return tex2D(ReflectionSampler, uv);
    float2 f = FafFootprint(uv);
    float4 acc = float4(0, 0, 0, 0);
    FafReflectionTap(uv + f * float2(-0.375, -0.125), acc);
    FafReflectionTap(uv + f * float2( 0.125, -0.375), acc);
    FafReflectionTap(uv + f * float2( 0.375,  0.125), acc);
    FafReflectionTap(uv + f * float2(-0.125,  0.375), acc);
    float n = 4.0;
    if (faf_WaterFilter.x > 6.5)
    {
        FafReflectionTap(uv + f * float2(-0.25,  0.25), acc);
        FafReflectionTap(uv + f * float2( 0.25, -0.25), acc);
        FafReflectionTap(uv + f * float2(-0.5,   0.0 ), acc);
        FafReflectionTap(uv + f * float2( 0.5,   0.0 ), acc);
        n = 8.0;
    }
    return float4(acc.rgb / max(acc.a, 0.0001), acc.a / n);
}

// One refraction tap: a texel that holds a unit part above the water or the land cut-out (alpha above 0) is replaced by the unrefracted
// background, as the shipped shader does for its single tap, before it is averaged.
void FafRefractionTap(float2 uv, float3 background, inout float3 acc)
{
    float4 t = tex2D(RefractionSampler, uv);
    acc += lerp(t.rgb, background, saturate(t.a * 255));
}

float4 FafSampleRefraction(float2 uv, float4 backGround)
{
    if (faf_WaterFilter.y < 3.5)
        return tex2D(RefractionSampler, uv);
    float2 f = FafFootprint(uv);
    float3 acc = float3(0, 0, 0);
    FafRefractionTap(uv + f * float2(-0.375, -0.125), backGround.rgb, acc);
    FafRefractionTap(uv + f * float2( 0.125, -0.375), backGround.rgb, acc);
    FafRefractionTap(uv + f * float2( 0.375,  0.125), backGround.rgb, acc);
    FafRefractionTap(uv + f * float2(-0.125,  0.375), backGround.rgb, acc);
    // the shipped shader lerps with the alpha of the lookup afterwards; the average is already clean, so it reports no alpha
    return float4(acc * 0.25, 0.0);
}
// The water is drawn opaque where the land mask of the refraction map is 0 and not at all where it is set, so the shoreline is a staircase of
// whole pixels. A water pixel next to land takes the colour of that land by the share of its four neighbours that are land: the staircase
// becomes a one pixel gradient. (The land pixels themselves are not drawn, so the land keeps its own colour.)
float3 FafShoreline(float3 water, float2 screenPos)
{
    if (faf_WaterFilter.z < 0.5)
        return water;
    float2 px = float2(abs(ddx(screenPos.x)), abs(ddy(screenPos.y)));
    float3 landColour = float3(0, 0, 0);
    float landShare = 0.0;
    float4 t = tex2D(RefractionSampler, screenPos + float2( px.x, 0));
    float a = saturate(t.a * 255);
    landColour += t.rgb * a;
    landShare += a;
    t = tex2D(RefractionSampler, screenPos + float2(-px.x, 0));
    a = saturate(t.a * 255);
    landColour += t.rgb * a;
    landShare += a;
    t = tex2D(RefractionSampler, screenPos + float2(0,  px.y));
    a = saturate(t.a * 255);
    landColour += t.rgb * a;
    landShare += a;
    t = tex2D(RefractionSampler, screenPos + float2(0, -px.y));
    a = saturate(t.a * 255);
    landColour += t.rgb * a;
    landShare += a;
    return lerp(water, landColour / max(landShare, 0.0001), landShare * 0.25 * 0.75);
}
// ---- end of FAF water quality ----

)HLSL";

    size_t CountOf(
      const string& text,
      string_view needle
    )
    {
      size_t n = 0;
      for (size_t p = text.find(needle); p != npos; p = text.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    }

    bool ReplaceOnce(
      string& text,
      string_view from,
      const string& to,
      string& error
    )
    {
      const size_t count = CountOf(text, from);
      if (count != 1) {
        error = string("expected exactly one \"") + string(from) + "\", found " + std::to_string(count);
        return false;
      }
      text.replace(text.find(from), from.size(), to);
      return true;
    }
  } // namespace

  EffectPatchResult PatchWaterEffect(
    string& source
  )
  {
    EffectPatchResult result;
    string text = source;

    // The pixel shader must still own the lookups and the samplers must be declared before it.
    const size_t shader = text.find(kPixelShader);
    const size_t reflectionSampler = text.find("sampler ReflectionSampler");
    const size_t refractionSampler = text.find("sampler RefractionSampler");
    if (
      shader == npos || reflectionSampler == npos || refractionSampler == npos || reflectionSampler > shader ||
      refractionSampler > shader
    ) {
      result.error = "HighFidelityPS or its samplers not found in the expected order";
      return result;
    }
    if (CountOf(text, kPixelShader) != 1) {
      result.error = "more than one HighFidelityPS";
      return result;
    }

    if (
      !ReplaceOnce(
        text, kReflectionLookup, "float4 unitReflections = FafSampleReflection(refractionPos);", result.error
      ) ||
      !ReplaceOnce(
        text,
        kRefractionLookup,
        "float4 refractedPixels = FafSampleRefraction(refractionPos, backGroundPixels);",
        result.error
      ) ||
      !ReplaceOnce(text, kResult, "returnPixels.rgb = FafShoreline(water, screenPos);", result.error)
    ) {
      return result;
    }
    // The refraction filter needs the unrefracted background pixel, which the shader reads before the lookup.
    const size_t background = text.find("float4 backGroundPixels");
    if (background == npos || background > text.find("FafSampleRefraction(refractionPos")) {
      result.error = "backGroundPixels is not defined before the refraction lookup";
      return result;
    }

    text.insert(text.find(kPixelShader), kDeclarations);
    source = std::move(text);
    result.patched = true;
    return result;
  }
} // namespace moho::water
