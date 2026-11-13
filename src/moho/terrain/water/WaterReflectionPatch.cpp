#include "moho/terrain/water/WaterReflectionPatch.h"

#include <cstddef>
#include <utility>

// The text of the water pixel shader's reflection, thickness, caustic, sheen and shadow additions
// (docs/WATER_REFLECTIONS.md). Pure text in, text out; the engine side that fills the parameters is
// WaterReflections.cpp.
namespace moho::water
{
  namespace
  {
    constexpr const char* kDeclarations = R"HLSL(
// ---- FAF water reflections (WaterReflectionPatch.cpp, docs/WATER_REFLECTIONS.md): screen-space reflections of the scene -------------
texture waterSceneDepth;
sampler2D waterSceneDepthSampler = sampler_state
{
    Texture   = (waterSceneDepth);
    MipFilter = NONE;
    MinFilter = POINT;
    MagFilter = POINT;
    AddressU  = CLAMP;
    AddressV  = CLAMP;
};
float4 waterSsrParams;    // x: steps of the march (0: off), y: the longest ray in world units, zw: the size of the depth buffer in pixels
float4 waterSsrParams2;   // x: how much the hits replace the reflection, y: 1 = show the hits, z: how much of the normal's tilt the marched ray keeps, w: 1 = the scene depth copy is bound (the traced reflections check their hits against it)

// The distance along the view axis of a depth value (the engine's projection is right handed: Projection[2][3] is -1, the eye z is negative).
float FafWaterViewZ(float depth)
{
    return -Projection[3][2] / (depth * Projection[2][3] - Projection[2][2]);
}

float2 FafWaterScreen(float4 clip)
{
    return clip.xy / clip.w * ViewportScaleOffset.xy + ViewportScaleOffset.zw;
}

float FafWaterSceneZ(float2 uv)
{
    return FafWaterViewZ(tex2Dlod(waterSceneDepthSampler, float4(uv, 0.0, 0.0)).x);
}

float4 waterAbsorbParams; // w: how far the Fresnel and the sky tint are moved from the shipped look (0..1); x: 0 = the baked depth map, 1 = the real depth, 2 = the real depth and colour extinction, y: the depth in world units of 63 percent tint

// The sun shadow map (the one the terrain and the meshes read), on the water plane. 1 = lit. The texture is named ShadowTexture on purpose:
// that is the name by which the effect layer knows a lighting shadow lookup (gpg/gal/effects/ShadowCascades.h), so with ren_ShadowCascades
// on the lookup below goes through the cascade atlas like the terrain's and the meshes' do, and outside the tiles it reads "lit".
float4x4 waterShadowMatrix;
texture ShadowTexture;
sampler2D waterShadowSampler = sampler_state
{
    Texture   = (ShadowTexture);
    MipFilter = LINEAR;
    MinFilter = LINEAR;
    MagFilter = LINEAR;
    AddressU  = BORDER;
    AddressV  = BORDER;
    BorderColor = float4(1, 1, 1, 1);
};
float4 waterShadowParams; // x: how much the shade darkens the water (0: off), y: world units per depth unit of the shadow map, z: caster distance that still shades fully, w: distance over which it fades out

float FafWaterShadow(float3 position)
{
    if (waterShadowParams.x <= 0.0)
    {
        return 1.0;
    }
    float4 coord = mul(float4(position, 1.0), waterShadowMatrix);
    // the matrix gives clip space; the terrain's vertex shaders map it to texture space the same way (x right, y down), so does this
    coord.xy = float2(coord.x + coord.w, -coord.y + coord.w) * 0.5 / coord.w;
    coord.z /= coord.w;
    float4 texel = tex2Dlod(waterShadowSampler, float4(coord.xy, 0.0, 0.0));
    // The map stores the depth of the nearest caster (R) and the blurred shade (G) without knowing the receiver. A caster far up the sun ray from the
    // water (a tree on a hill, a cliff top) is not what shades the water next to it. Only casters within reach of the surface count, the way
    // the shadow of a tree on the shore or of a unit afloat falls on the water. The ground is a caster in the map too: the sea bed and the
    // land under the surface lie behind the water along the ray (negative gap, lit), the bank beside it casts as it should.
    float gap = (coord.z - texel.r) * waterShadowParams.y;
    float reach = (gap > 0.0) ? saturate(1.0 - (gap - waterShadowParams.z) / waterShadowParams.w) : 0.0;
    return lerp(1.0, texel.g, reach);
}

// The debug views 10 to 13 of ren_WaterSSRDebug: what the shadow map holds at the water point (G, R, the distance to the caster, the coordinate).
float3 FafWaterShadowDebug(float3 position, float mode)
{
    float4 coord = mul(float4(position, 1.0), waterShadowMatrix);
    coord.xy = float2(coord.x + coord.w, -coord.y + coord.w) * 0.5 / coord.w;
    coord.z /= coord.w;
    float4 texel = tex2Dlod(waterShadowSampler, float4(coord.xy, 0.0, 0.0));
    float gap = (coord.z - texel.r) * waterShadowParams.y;
    if (mode < 10.5) { return float3(texel.g, texel.g, texel.g); }
    if (mode < 11.5) { return float3(texel.r, texel.r, texel.r); }
    if (mode < 12.5) { return float3(saturate(gap / 32.0), saturate(-gap / 32.0), 0.0); }
    return float3(frac(coord.xy), saturate(coord.z));
}

// ---- caustics on the sea bed (replaces the finite differences of the 2 unit normal map, which aliased and had nothing to do with the surface) ----
// The slope of the simulated surface at a world position and how far the simulation reaches there (x, z: slope, w: weight). Without the
// simulation (FAF_WATER_SIM is defined by the patch only when the simulation patch is in the shader) the surface is treated as flat.
float3 FafCausticWaves(float2 xz)
{
#ifdef FAF_WATER_SIM
    float4 r = FafWaterRipple(xz);
    return float3(r.x, r.y, r.w);
#else
    return float3(0.0, 0.0, 0.0);
#endif
}

// ---- CAUSTIC WEB BEGIN (tools/watersimlab caustic compiles this text as it is) ----
// A smooth, bounded web of bright lines (an iterated warp of sines; no texture lookups, so nothing to alias but its own lines). One layer repeats
// every 10 units and evolves with `t` (radians of its slowest clock).
float FafCausticLayer(float2 xz, float t)
{
    const float tau = 6.28318530718;
    float2 p = fmod(xz * (tau / 14.0), tau) - 250.0;
    float2 i = p;
    float c = 1.0;
    [unroll] for (int n = 0; n < 5; ++n)
    {
        float tt = t * (1.0 - 3.5 / (float(n) + 1.0));
        i = p + float2(cos(tt - i.x) + sin(tt + i.y), sin(tt - i.y) + cos(tt + i.x));
        c += 1.0 / length(float2(p.x / (sin(i.x + tt) / 0.005), p.y / (cos(i.y + tt) / 0.005)));
    }
    c = 1.17 - pow(c / 5.0, 1.4);
    float c2 = c * c;
    return c2 * c * 2.03;
}

float FafCausticHash(float2 p)
{
    p = frac(p * float2(123.34, 456.21));
    p += dot(p, p + 45.32);
    return frac(p.x * p.y);
}

float FafCausticNoise(float2 p)
{
    float2 i = floor(p);
    float2 f = frac(p);
    f = f * f * (3.0 - 2.0 * f);
    float a = FafCausticHash(i);
    float b = FafCausticHash(i + float2(1.0, 0.0));
    float c = FafCausticHash(i + float2(0.0, 1.0));
    float d = FafCausticHash(i + float2(1.0, 1.0));
    return lerp(lerp(a, b, f.x), lerp(c, d, f.x), f.y);
}

// Two layers of different scale and heading (1.37 times finer, turned by 37 degrees), the position warped by a slow noise: a single layer repeats
// every 10 units and the eye finds the tiles; two that do not fit, on a ground that is bent a little differently everywhere, do not. Mean 1.
float FafCausticWeb(float2 xz, float t)
{
    float2 warp = float2(FafCausticNoise(xz * 0.045 + 3.1), FafCausticNoise(xz * 0.045 + 17.3)) - 0.5;
    float2 a = xz + warp * 16.0;
    float2 b = float2(a.x * 0.8 - a.y * 0.6, a.x * 0.6 + a.y * 0.8) * 1.37 + float2(31.0, 17.0);
    float web = 0.5 * (FafCausticLayer(a, t) + FafCausticLayer(b, t * 0.71 + 3.0));
    return max(1.0 + 1.5 * (web - 1.0), 0.05);
}
// ---- CAUSTIC WEB END ----

// The debug views 6 to 9 of ren_WaterSSRDebug: the caustic factor, and the channels of the wave simulation at the point of the surface.
float3 FafWaterDebugView(float mode, float caustic, float2 xz)
{
    float3 view = float3(1.0, 1.0, 1.0) * saturate(0.5 * caustic);
#ifdef FAF_WATER_SIM
    if (mode > 6.5)
    {
        float4 t = float4(0.0, 0.0, 0.0, 0.0);
        if (waterSimParams2.x > 0.5)
        {
            t = tex2Dlod(waterSimSampler, float4(xz * waterSimParams.x, 0.0, 0.0));
        }
        if (mode < 7.5)
        {
            float h = t.z * 4.0;
            view = h > 0.0 ? float3(saturate(h), 0.25 * saturate(h), 0.0) : float3(0.0, 0.25 * saturate(-h), saturate(-h));
        }
        else if (mode < 8.5)
        {
            view = float3(1.0, 1.0, 1.0) * saturate(t.w);
        }
        else
        {
            view = float3(saturate(abs(t.x) * 8.0), saturate(abs(t.y) * 8.0), 0.0);
        }
    }
#endif
    return view;
}

// The light the surface focuses on the bed point `bedXZ` under `depth` units of water. The sun ray that reaches the bed there entered the surface
// up-sun of it (shifted by the refracted sun direction times the depth), so the pattern is pinned to the surface and slides with the depth and the
// sun. The simulated waves act on it as they act on light: their slope displaces it (refraction), their curvature focuses it (a crest is a lens),
// and calm water gives a soft pattern, rough water a contrasty one. `footprint` is the size of a pixel on the surface: a web finer than that fades out.
float FafCaustic(float2 bedXZ, float depth, float footprint)
{
    float2 toSun = SunDirection.xz;
    toSun = SunDirection.y < 0.0 ? -toSun : toSun;
    float sinI = min(length(toSun), 0.98);
    float tanR = sinI / sqrt(1.7689 - sinI * sinI);
    float2 entry = bedXZ + (sinI > 0.001 ? toSun / sinI : float2(0.0, 0.0)) * (tanR * depth);

    float3 w = FafCausticWaves(entry);
    const float e = 1.0;
    float3 wx0 = FafCausticWaves(entry - float2(e, 0.0));
    float3 wx1 = FafCausticWaves(entry + float2(e, 0.0));
    float3 wz0 = FafCausticWaves(entry - float2(0.0, e));
    float3 wz1 = FafCausticWaves(entry + float2(0.0, e));
    float curvature = ((wx1.x - wx0.x) + (wz1.y - wz0.y)) / (2.0 * e);   // the Laplacian of the height: negative on a crest
    float shake = w.z * saturate(length(w.xy) * 4.0);                       // how steep the waves are here, 0 in calm water and outside the simulation

    // the waves shift the pattern (refraction), by at most a unit: the slope of a rough sea is noise and a long shift only jumbles the web
    float2 shift = w.xy * (w.z * depth * 1.2);
    shift *= min(1.0, 1.0 / max(length(shift), 1.0e-4));
    float2 pos = entry - shift;
    // `Time` counts game ticks (ten a second): an eighth of a radian a second (the slowest clock of the web) moves its fastest line about half a unit a second: the picture is a new one in ten seconds or so
    float web = FafCausticWeb(pos, Time * 0.0125);
    float focus = exp(clamp(-curvature * w.z * depth * 8.0, -0.8, 0.8));
    float contrast = 0.45 + 0.55 * shake;
    float caustic = lerp(1.0, web * focus, contrast);
    return lerp(1.0, caustic, saturate(1.5 - footprint * 1.5));
}

// The distance the view ray travels through the water before it meets what the scene drew at uv (0 when the scene is in front of the water).
float FafWaterPath(float2 uv, float surfaceZ, float eyeDistance)
{
    float sceneZ = FafWaterSceneZ(uv);
    if (!(sceneZ > 0.0))
    {
        sceneZ = 100000.0;                          // nothing drawn there: as deep as it gets
    }
    return max(sceneZ - surfaceZ, 0.0) * eyeDistance / max(surfaceZ, 0.01);
}

// rgb: the scene colour the reflected ray meets; a: how sure the hit is (0: nothing, use the sky and the mirrored units)
float4 FafWaterSSR(float3 position, float3 dir, float2 pixel)
{
    float4 result = float4(0.0, 0.0, 0.0, 0.0);
    if (waterSsrParams.x < 0.5 || dir.y < 0.02)
    {
        return result;
    }
    float4x4 viewProjection = mul(WorldToView, Projection);
    float4 c0 = mul(float4(position, 1.0), viewProjection);
    float4 dc = mul(float4(dir, 0.0), viewProjection);
    if (c0.w < 0.5)
    {
        return result;
    }
    float len = waterSsrParams.y;
    if (dc.w < 0.0)
    {
        len = min(len, (c0.w - 0.5) / -dc.w);       // the ray ends in front of the camera plane
    }
    float4 c1 = c0 + dc * len;
    float k0 = 1.0 / c0.w;
    float k1 = 1.0 / c1.w;
    float2 s0 = FafWaterScreen(c0);
    float2 s1 = FafWaterScreen(c1);
    float2 delta = s1 - s0;
    float smax = 1.0;                               // the part of the ray that stays on the screen
    if (delta.x > 0.0001) { smax = min(smax, (1.0 - s0.x) / delta.x); }
    if (delta.x < -0.0001) { smax = min(smax, -s0.x / delta.x); }
    if (delta.y > 0.0001) { smax = min(smax, (1.0 - s0.y) / delta.y); }
    if (delta.y < -0.0001) { smax = min(smax, -s0.y / delta.y); }
    if (smax <= 0.0)
    {
        return result;
    }
    // A fixed, unrolled march with a latched hit: the dynamic loop with a break that stood here took the GPU down (a device hang with a page fault
    // in the water draw within a minute or two of play, on Direct3D 12; the same shader with the march skipped ran for good).
    float jitter = frac(52.9829189 * frac(dot(pixel, float2(0.06711056, 0.00583715))));
    float sPrev = 0.0;
    float hit = -1.0;
    [unroll] for (int i = 0; i < 32; ++i)
    {
        float s = smax * (float(i) + jitter) / 32.0;
        float rayZ = 1.0 / lerp(k0, k1, s);
        float sceneZ = FafWaterSceneZ(lerp(s0, s1, s));
        float nextZ = 1.0 / lerp(k0, k1, s + smax / 32.0);
        float stride = abs(nextZ - rayZ);
        float gap = rayZ - sceneZ;
        bool open = hit < 0.0;
        bool found = open && gap > 0.0 && gap < stride * 2.0 + 0.3;   // the ray went behind what the scene drew, by less than a step: a hit, not an occluder
        sPrev = (open && !found) ? s : sPrev;
        hit = found ? s : hit;
    }
    if (hit < 0.0)
    {
        return result;
    }
    float lo = sPrev;
    float hi = hit;
    [unroll] for (int j = 0; j < 5; ++j)
    {
        float mid = 0.5 * (lo + hi);
        float midZ = 1.0 / lerp(k0, k1, mid);
        if (midZ > FafWaterSceneZ(lerp(s0, s1, mid))) { hi = mid; } else { lo = mid; }
    }
    float2 uv = lerp(s0, s1, hi);
    float2 edge = min(uv, 1.0 - uv);
    float confidence = saturate(min(edge.x, edge.y) * 10.0) * (1.0 - smoothstep(0.7, 1.0, hi / smax));
    result.rgb = tex2Dlod(RefractionSampler, float4(uv, 0.0, 0.0)).rgb;
    result.a = confidence;
    return result;
}

)HLSL";
  } // namespace

  ReflectionPatchResult PatchWaterReflections(
    std::string& source
  )
  {
    ReflectionPatchResult result;
    const auto count = [&](const std::string& needle) {
      std::size_t n = 0;
      for (std::size_t p = source.find(needle); p != std::string::npos; p = source.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    };
    const std::string shader = "float4 HighFidelityPS(";
    const std::string mixLine =
      "float3 reflections = lerp(skyReflection.rgb, unitReflections.rgb, saturate(unitReflections.a));";
    const std::string unitSun = "sunReflection *= (1 - saturate(unitReflections.a * 4));";
    const std::string sunAdd = "water += sunReflection;";
    const std::string refractOffset = "refractionPos -= sqrt(waterDepth) * refractionScale * N.xz * OneOverW;";
    const std::string tintLine = "refractedPixels.rgb = lerp(refractedPixels.rgb, waterColor, factor);";
    const std::string waterMix =
      "float3 water = lerp(refractedPixels, reflections, saturate(fresnel * skyreflectionAmount));";
    if (
      count(waterMix) != 1 || count(shader) != 1 || count(mixLine) != 1 || count(unitSun) != 1 || count(sunAdd) != 1 ||
      count(refractOffset) != 1 || count(tintLine) != 1 || source.find("FafWaterSSR") != std::string::npos
    ) {
      result.error = "HighFidelityPS, the reflection mix lines or the refraction lines not found exactly once";
      return result;
    }
    if (
      source.find("sampler RefractionSampler") == std::string::npos ||
      source.find("ViewportScaleOffset;") == std::string::npos || source.find("Projection;") == std::string::npos ||
      source.find("WorldToView;") == std::string::npos || source.find("float waterDepth") == std::string::npos ||
      source.find("mScreenPos") == std::string::npos
    ) {
      result.error =
        "RefractionSampler, ViewportScaleOffset, Projection, WorldToView, waterDepth or mScreenPos not declared";
      return result;
    }
    std::string text = source;
    // Fresnel: the shipped term is F0 0.08 on the sharpened per-pixel normal. F0 of water is 0.02; the normal of a
    // rough sea reflects the sky as the average of its facets does, so the grazing angle is taken on a smoothed normal
    // (the per-pixel tilt is kept at 35 percent). The reflection of a sky that is grey or beige is tinted toward the
    // colour of the water, which it mixes with. All of it scales with waterAbsorbParams.w (the cvar ren_WaterSheen).
    const std::string fresnelLine = "float fresnel = FresnelSchlick(NDotV, 0.08);";
    if (text.find(fresnelLine) != std::string::npos && text.find(fresnelLine) == text.rfind(fresnelLine)) {
      text.replace(
        text.find(fresnelLine),
        fresnelLine.size(),
        "float fresnel = lerp(FresnelSchlick(NDotV, 0.08), FresnelSchlick(saturate(dot(viewVector, "
        "normalize(float3(N.x * 0.35, N.y, N.z * 0.35)))), 0.03), waterAbsorbParams.w);"
      );
    }
    // the later line first, so the earlier anchors stay valid: the extinction of the colours (before the tint toward
    // the deep colour)
    const std::size_t tintAt = text.find(tintLine);
    text.insert(
      tintAt,
      "float2 fafSurfaceXZ = ViewPosition.xz - inV.mViewVec.xz;"
      "\n    float fafFoot = length(ddx(fafSurfaceXZ)) + length(ddy(fafSurfaceXZ));"
      "\n    if (waterAbsorbParams.x > 1.5) { refractedPixels.rgb *= exp(-float3(1.0, 0.4, 0.15) * fafPath / "
      "(waterAbsorbParams.y * 4.0)); }"
      "\n    if (waterAbsorbParams.x > 0.5 && waterAbsorbParams.z > 0.0 && fafPath > 0.0)"
      "\n    {"
      "\n        float fafVerticalDepth = fafPath * abs(viewVector.y);"
      "\n        float3 fafBed = ViewPosition - inV.mViewVec - viewVector * fafPath;"
      "\n        float fafFade = exp(-fafVerticalDepth / (waterAbsorbParams.y * 0.5));"
      "\n        fafDebugCaustic = FafCaustic(fafBed.xz, fafVerticalDepth, fafFoot);"
      "\n        refractedPixels.rgb *= 1.0 + waterAbsorbParams.z * fafFade * waterTexture.r * (fafDebugCaustic - 1.0);"
      "\n    }"
      "\n    "
    );
    // the sun glint is not seen where a scene hit is reflected: first the later line, so the earlier anchor stays valid
    const std::size_t sunAddAt = text.find(sunAdd);
    text.insert(
      sunAddAt + sunAdd.size(),
      "\n    if (waterSsrParams2.y > 0.5 && waterSsrParams2.y < 1.5) { water = lerp(float3(0.0, 0.0, 0.4), float3(1.0, "
      "0.0, 0.0), ssrHit.a); }"
      "\n    if (waterSsrParams2.y > 1.5 && waterSsrParams2.y < 2.5) { water = float3(fafShadow, fafShadow, "
      "waterShadowParams.x > 0.0 ? fafShadow : 0.0); }"
      "\n    if (waterSsrParams2.y > 2.5 && waterSsrParams2.y < 3.5) { water = sunReflection; }"
      "\n    if (waterSsrParams2.y > 3.5 && waterSsrParams2.y < 4.5) { water = reflections * saturate(fresnel * "
      "skyreflectionAmount); }"
      "\n    if (waterSsrParams2.y > 4.5 && waterSsrParams2.y < 5.5) { water = float3(saturate(fresnel * "
      "skyreflectionAmount), 0.0, 0.0); }"
      "\n    if (waterSsrParams2.y > 5.5) { water = FafWaterDebugView(waterSsrParams2.y, fafDebugCaustic, "
      "ViewPosition.xz - inV.mViewVec.xz); }"
      "\n    if (waterSsrParams2.y > 9.5) { water = FafWaterShadowDebug(ViewPosition - inV.mViewVec, "
      "waterSsrParams2.y); }"
    );
    const std::size_t unitSunAt = text.find(unitSun);
    text.insert(
      unitSunAt + unitSun.size(),
      "\n\tsunReflection *= (1.0 - saturate(ssrHit.a * waterSsrParams2.x));\n\tsunReflection *= fafShadow;"
    );
    // the transmitted light is darker where a unit, a building or a tree shades the surface
    text.insert(text.find(waterMix), "refractedPixels.rgb *= lerp(1.0 - waterShadowParams.x, 1.0, fafShadow);\n    ");
    const std::size_t mixAt = text.find(mixLine);
    text.insert(
      mixAt + mixLine.size(),
      "\n    reflections *= lerp(float3(1.0, 1.0, 1.0), waterColor / max(max(waterColor.r, max(waterColor.g, "
      "waterColor.b)), 0.001), 0.3 * waterAbsorbParams.w);"
      "\n    float fafShadow = FafWaterShadow(ViewPosition - inV.mViewVec);"
      "\n    float4 ssrHit = FafWaterSSR(ViewPosition - inV.mViewVec, reflect(-viewVector, normalize(float3(N.x * "
      "waterSsrParams2.z, N.y, N.z * waterSsrParams2.z))), screenPos * waterSsrParams.zw);"
      "\n    reflections = lerp(reflections, ssrHit.rgb, saturate(ssrHit.a * waterSsrParams2.x));"
    );
    // The thickness the view ray crosses replaces the baked depth: the map's waterLerp range, the refraction strength
    // and the tint keep their meaning (the depth stays 0..1). The first pass sizes the refraction offset, the second
    // reads the thickness where the refracted ray lands; a refracted pixel in front of the water plane (a unit, a
    // bridge, the shore) falls back to the straight view.
    const std::size_t offsetAt = text.find(refractOffset);
    text.insert(
      offsetAt + refractOffset.size(),
      "\n    if (waterAbsorbParams.x > 0.5)"
      "\n    {"
      "\n        if (FafWaterSceneZ(refractionPos) < fafSurfaceZ - 0.05) { refractionPos = screenPos; }"
      "\n        fafPath = FafWaterPath(refractionPos, fafSurfaceZ, fafEye);"
      "\n        waterDepth = 1.0 - exp(-fafPath / waterAbsorbParams.y);"
      "\n    }"
    );
    text.insert(
      offsetAt,
      "float fafSurfaceZ = inV.mScreenPos.w;"
      "\n    float fafDebugCaustic = 1.0;"
      "\n    float fafEye = length(inV.mViewVec);"
      "\n    float fafPath = 0.0;"
      "\n    if (waterAbsorbParams.x > 0.5)"
      "\n    {"
      "\n        fafPath = FafWaterPath(screenPos, fafSurfaceZ, fafEye);"
      "\n        waterDepth = 1.0 - exp(-fafPath / waterAbsorbParams.y);"
      "\n    }"
      "\n    "
    );
    // the caustics follow the wave simulation when its patch is in the shader (FafWaterRipple is declared before the
    // pixel shader then)
    text.insert(
      text.find(shader),
      std::string(text.find("float4 FafWaterRipple(") != std::string::npos ? "#define FAF_WATER_SIM 1\n" : "") +
        kDeclarations
    );
    source = std::move(text);
    result.patched = true;
    return result;
  }
} // namespace moho::water
