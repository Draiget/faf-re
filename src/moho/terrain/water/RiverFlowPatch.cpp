// The source patch of water2.fx for rivers: see RiverFlow.h. Pure text in, text out (no engine types), so the host
// tests compile it on its own.
#include <cstddef>
#include <string>
#include <string_view>

#include "moho/terrain/water/RiverFlow.h"
#include "moho/terrain/water/WaterShaderCommon.h"

namespace moho::water
{
  namespace
  {
    using std::size_t;
    using std::string;
    using std::string_view;

    constexpr size_t npos = string::npos;

    size_t CountOf(
      const string& text,
      const string_view needle
    )
    {
      size_t n = 0;
      for (size_t p = text.find(needle); p != npos; p = text.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    }

    // The variables of the patch. `waterRiverParams`: x 1 = the mesh being drawn is a river's, so its vertices keep
    // their own height (the shipped vertex shaders put every vertex at `WaterElevation`); y the speed scale of the
    // flow (ren_RiverFlow / 100); z the white water scale (ren_RiverFoam / 100); w the length of a phase of the
    // scrolled normals in ticks, 0 while no river is on the map (every river line of the pixel shader is then skipped
    // by a branch on a constant).
    constexpr const char* kDeclarations = R"HLSL(
// ---- FAF rivers (RiverFlow.cpp, docs/projects/RIVERS.md): the flow of a river scrolls the normals, steep reaches are white ----
float4 waterRiverParams;
float4 waterRiverDebug;   // x: a view of the flow (ren_RiverDebug): 1 turbulence, 2 speed, 3 the weight of the river, 4 the direction, 5 the white water, 6 to 8 the texel's alpha, blue, rgb, 9 the third normal layer, 10 a grid of ten world units
texture waterFlow;        // per 2 x 2 block (the layout of the water map): r, g the flow direction (0.5 + 0.5 d), b the speed over 6, a 0 without a river else 16 .. 255 for the turbulence
sampler2D waterFlowSampler = sampler_state
{
    Texture   = (waterFlow);
    MipFilter = NONE;
    MinFilter = LINEAR;
    MagFilter = LINEAR;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};

)HLSL";

    constexpr const char* kFlowFunctions = R"HLSL(
// The flow at a place: the velocity in world units a game tick (the direction times the speed times ren_RiverFlow), the weight of the river
// (0 outside, fading in over the edge of its blocks) and the turbulence. Zero while no river is on the map.
float4 FafRiverFlow(float2 uv)
{
    float4 r = float4(0.0, 0.0, 0.0, 0.0);
    if (waterRiverParams.w > 0.5)
    {
        float4 t = tex2Dlod(waterFlowSampler, float4(uv, 0.0, 0.0));
        float2 d = t.xy * 2.0 - 1.0;
        float len = length(d);
        d = len > 0.001 ? d / len : float2(0.0, 0.0);
        float speed = t.b * 6.0 * waterRiverParams.y;
        r = float4(d * (speed * 0.1), saturate(t.a * (255.0 / 16.0)), saturate((t.a * 255.0 - 16.0) / 239.0));
    }
    return r;
}

// a view of the flow for the cvar ren_RiverDebug
float3 FafRiverDebug(float4 fl, float white, float2 uv)
{
    float mode = waterRiverDebug.x;
    if (mode > 5.5) { float4 raw = tex2Dlod(waterFlowSampler, float4(uv, 0.0, 0.0)); return mode < 6.5 ? float3(raw.a, raw.a, raw.a) : (mode < 7.5 ? float3(raw.b, raw.b, raw.b) : raw.rgb); }
    if (mode < 1.5) return float3(fl.w, fl.w, fl.w);
    if (mode < 2.5) { float v = length(fl.xy) * 10.0 / 6.0; return float3(v, v, v); }
    if (mode < 3.5) return float3(fl.z, fl.z, fl.z);
    if (mode < 4.5) return float3(0.5 + 0.5 * normalize(fl.xy + 0.0001), 0.0);
    return float3(white, white, white);
}

// the two phases of the clock for the scrolled layers: x, y the shift (in ticks of flow) of the two reads, z the weight of the first
float3 FafRiverPhase()
{
    float x = Time / waterRiverParams.w;
    float t0 = frac(x);
    float t1 = frac(x + 0.5);
    return float3(t0 * waterRiverParams.w, t1 * waterRiverParams.w, 1.0 - abs(1.0 - 2.0 * t0));
}

// White water: the foam of the shipped pattern, thresholded by the turbulence, on coordinates that run with the flow, in the two phases of the
// layers (a flow that changes from place to place would shear a pattern that had run for a long time). The amount is 0 off the rapids, so the
// pattern's own early out returns at once (and the pattern is never asked in a branch: it takes derivatives).
float FafRiverWhite(float4 fl, float2 xz)
{
    if (waterRiverParams.w < 0.5)
    {
        return 0.0;
    }
    float3 ph = FafRiverPhase();
    float amount = fl.w * fl.w * waterRiverParams.z * 0.6 * step(0.0001, fl.z);
    float a0 = FafFoamAmount(amount, xz - fl.xy * ph.x, 0.0);
    float a1 = FafFoamAmount(amount, xz - fl.xy * ph.y + float2(17.3, 5.1), 0.0);
    return lerp(a1, a0, ph.z) * fl.z;
}

)HLSL";

    string LayerFunction(
      const int layer
    )
    {
      static constexpr const char* kComponent[4] = {"x", "y", "z", "w"};
      string text = R"HLSL(
// Layer %N% of the water's normal map where a river runs: two reads of the layer, its coordinates shifted along the flow by the speed times a phase
// of the clock, blended by a weight that is zero where a phase restarts (so nothing pops), and the contrast put back that the blend takes (two
// reads of unrelated texels average toward grey). `base` is the layer as the shipped shader read it, `g` its coordinates' derivatives, `ph` the phase.
float4 FafRiverLayer%N%(float4 base, float2 xz, float4 g, float4 fl, float3 ph)
{
    if (fl.z <= 0.0)
    {
        return base;
    }
    float rate = normalRepeatRate.%R%;
    float4 a = tex2Dgrad(NormalSampler%N%, (xz - fl.xy * ph.x) * rate, g.xy, g.zw);
    float4 b = tex2Dgrad(NormalSampler%N%, (xz - fl.xy * ph.y) * rate + 0.5, g.xy, g.zw);
    float k = rsqrt(ph.z * ph.z + (1.0 - ph.z) * (1.0 - ph.z));
    float4 river = 0.5 + (lerp(b, a, ph.z) - 0.5) * k;
    return lerp(base, river, fl.z);
}
)HLSL";
      for (size_t at = text.find("%N%"); at != npos; at = text.find("%N%", at)) {
        text.replace(at, 3, std::to_string(layer));
      }
      for (size_t at = text.find("%R%"); at != npos; at = text.find("%R%", at)) {
        text.replace(at, 3, kComponent[layer]);
      }
      return text;
    }

    constexpr string_view kLowVertex = "LOWFIDELITY_VERTEX LowFidelityVS(";
    constexpr string_view kLowHeight = "position.y = WaterElevation;";
    constexpr string_view kHighHeight = "inPos.y = WaterElevation;";
    constexpr string_view kPixelShader = "float4 HighFidelityPS(";
    constexpr string_view kLayer3 = "float4 W3 = tex2D( NormalSampler3, inV.mLayer3 );";
    constexpr string_view kResult = "returnPixels.rgb = water;";
    constexpr string_view kCrestMix =
      "water = lerp(water, waveCrestColor, (1 - waterTexture.a) * (1 - waterTexture.b) * waveCrest);";
  } // namespace

  RiverPatchResult PatchWaterRivers(
    string& source
  )
  {
    RiverPatchResult result;
    if (
      CountOf(source, kLowVertex) != 1 || CountOf(source, kLowHeight) != 1 || CountOf(source, kHighHeight) != 1 ||
      CountOf(source, kPixelShader) != 1 || CountOf(source, kLayer3) != 1 || CountOf(source, kCrestMix) != 1 ||
      CountOf(source, kResult) != 1 || source.find("waterRiverParams") != npos
    ) {
      result.error =
        "LowFidelityVS, WaterVS, HighFidelityPS or their anchor lines not found exactly once (or already patched)";
      return result;
    }
    const size_t low = source.find(kLowVertex);
    const size_t pixel = source.find(kPixelShader);
    if (
      source.find(kLowHeight) < low || source.find(kHighHeight) > pixel || source.find(kLayer3) < pixel ||
      source.find(kCrestMix) < pixel
    ) {
      result.error = "the anchor lines are not in the expected order";
      return result;
    }
    if (source.find("normalRepeatRate") == npos || source.find("normalRepeatRate") > low) {
      result.error = "normalRepeatRate is not declared before the vertex shaders";
      return result;
    }
    string text = source;

    // The later edits first, so the earlier anchors keep their places.
    // 1. the white water, after the wave crests are mixed into the colour
    text.insert(
      text.find(kCrestMix) + kCrestMix.size(),
      "\n    float fafRiverWhite = FafRiverWhite(fafFlow, fafRiverXZ);"
      "\n    float3 fafRiverWhiteColor = float3(0.95, 0.98, 1.0) * (0.8 + 0.2 * saturate(dot(N, SunDirection)));"
      "\n    water = lerp(water, fafRiverWhiteColor, fafRiverWhite * 0.92);"
    );
    // 1b. the view of the flow (ren_RiverDebug) replaces the colour last, after every other patch's additions to it
    text.insert(
      text.find(kResult),
      "if (waterRiverDebug.x > 0.5) { water = FafRiverDebug(fafFlow, fafRiverWhite, inV.mTexUV); }"
      "\n    if (waterRiverDebug.x > 8.5 && waterRiverDebug.x < 9.5) { water = W2.rgb * 0.5; }"
      "\n    if (waterRiverDebug.x > 9.5) { float2 fafG = abs(frac(fafRiverXZ / 10.0) - 0.5); water = min(fafG.x, "
      "fafG.y) > 0.46 ? float3(1.0, 1.0, 1.0) : float3(0.1, 0.1, 0.3); }"
      "\n    "
    );
    // 2. the layers: after the four reads of the shipped shader, a block that a branch on a constant skips on a map
    // without rivers. The derivatives are taken before the branch on the river of the pixel (they cannot be inside it).
    text.insert(
      text.find(kLayer3) + kLayer3.size(),
      "\n    float4 fafFlow = FafRiverFlow(inV.mTexUV);"
      "\n    float2 fafRiverXZ = ViewPosition.xz - inV.mViewVec.xz;"
      "\n    if (waterRiverParams.w > 0.5)"
      "\n    {"
      "\n        float3 fafPhase = FafRiverPhase();"
      "\n        W0 = FafRiverLayer0(W0, fafRiverXZ, float4(ddx(inV.mLayer0), ddy(inV.mLayer0)), fafFlow, fafPhase);"
      "\n        W1 = FafRiverLayer1(W1, fafRiverXZ, float4(ddx(inV.mLayer1), ddy(inV.mLayer1)), fafFlow, fafPhase);"
      "\n        W2 = FafRiverLayer2(W2, fafRiverXZ, float4(ddx(inV.mLayer2), ddy(inV.mLayer2)), fafFlow, fafPhase);"
      "\n        W3 = FafRiverLayer3(W3, fafRiverXZ, float4(ddx(inV.mLayer3), ddy(inV.mLayer3)), fafFlow, fafPhase);"
      "\n    }"
    );
    // 3. the functions, before the pixel shader; the foam pattern they call comes from the wave simulation patch, or is
    // added here when that did not run
    string functions;
    if (text.find("float FafNoiseCorner(") == npos) {
      functions += kWaterNoiseHlsl;
    }
    if (text.find("float FafGradNoise(") == npos) {
      functions += kWaterGradientNoiseHlsl;
    }
    if (text.find("float FafFoamAmount(") == npos) {
      functions += kWaterFoamLookHlsl;
    }
    functions += kFlowFunctions;
    for (int layer = 0; layer < 4; ++layer) {
      functions += LayerFunction(layer);
    }
    text.insert(text.find(kPixelShader), functions);
    // 4. the heights of the vertex shaders: a river's mesh keeps the vertices' own
    text.replace(
      text.find(kHighHeight), kHighHeight.size(), "inPos.y = waterRiverParams.x > 0.5 ? inPos.y : WaterElevation;"
    );
    text.replace(
      text.find(kLowHeight), kLowHeight.size(), "position.y = waterRiverParams.x > 0.5 ? position.y : WaterElevation;"
    );
    // 5. the variables, before the first vertex shader
    text.insert(text.find(kLowVertex), kDeclarations);
    source = std::move(text);
    result.patched = true;
    return result;
  }
} // namespace moho::water
