#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

// FAF addition, not in the shipped binary: the screen-space ambient occlusion that darkens the finished 3D world where
// the geometry closes in (creases, the feet of cliffs and buildings, the gaps between units). Ground-truth ambient
// occlusion (GTAO) from the scene depth alone: the view-space normal comes from depth differences, the horizons from a
// few depth taps along some screen directions, the result is cleaned with two depth-aware blur passes. The HLSL is
// shared by Direct3D 11, 12 and Vulkan (the GPU programs of GpuDriven.h; docs/RENDERER_BACKENDS.md, "Ambient
// occlusion"); this header holds that source and the pure arithmetic around it so a host test can run it.
namespace gpg::gal
{
  /** The quality levels of the render feature `ambient_occlusion` (Off is level 0 and draws nothing). */
  enum AmbientOcclusionLevel : std::uint32_t
  {
    kAmbientOcclusionOff = 0,
    kAmbientOcclusionLow = 1,
    kAmbientOcclusionMedium = 2,
    kAmbientOcclusionHigh = 3,
    kAmbientOcclusionLevelCount = 4,
  };

  /** What one level costs: how many directions and steps the horizon search takes, and the resolution it runs at. */
  struct AmbientOcclusionQuality
  {
    int slices = 0;       ///< screen directions per pixel (rotated per pixel inside a 4x4 pattern)
    int steps = 0;        ///< depth taps per direction and side
    bool halfRes = false; ///< the horizon search runs at half the resolution; the last blur pass upsamples depth-aware
  };

  [[nodiscard]] inline AmbientOcclusionQuality AmbientOcclusionQualityFor(
    const int level
  ) noexcept
  {
    switch (level) {
    case kAmbientOcclusionLow:
      return {2, 4, true};
    case kAmbientOcclusionMedium:
      return {3, 5, true};
    case kAmbientOcclusionHigh:
      return {3, 6, false};
    default:
      return {};
    }
  }

  /** The inputs of one frame's pass. Lengths are world units, rectangles are pixels of the back buffer. */
  struct AmbientOcclusionParams
  {
    int level = 0;
    /// The perspective projection in Direct3D's row-vector form: x scale (m00), y scale (m11), and the depth terms
    /// (m22, m32) with depth = m22 + m32 / viewZ.
    float projectionXScale = 1.0f;
    float projectionYScale = 1.0f;
    float projectionDepthScale = 1.0f;
    float projectionDepthBias = 0.0f;
    float rectX = 0.0f;
    float rectY = 0.0f;
    float rectWidth = 0.0f;
    float rectHeight = 0.0f;
    float radius = 1.5f;     ///< world units the horizon search reaches
    float intensity = 1.0f;  ///< 1 = the occlusion as computed; more darkens further
    float power = 1.6f;      ///< shapes the occlusion: more contrast in the creases, less on open ground
    int halfResolution = -1; ///< -1 the level's choice, 0 full, 1 half
    /// The blur's wide taps and the smoothing count while the surface bends by less than this inside their span: the
    /// change of the surface's slope (the tangent of its tilt to the view plane), measured as the second difference of
    /// the inverse depth. Rolling ground and a coarse mesh's facets stay under it; a crease, a wall's foot and a
    /// silhouette are over it.
    float planeTolerance = 0.35f;
    /// World units the last blur reaches over smooth ground, beyond its five core taps, to average the pattern of a
    /// coarse mesh's triangles away (0: only the core taps, two draws less).
    float smoothReach = 1.5f;
    /// The horizon search reads the depth at each tap's own screen position, interpolated (inverse depth over the four
    /// texels, exact on a plane), instead of the texel it rounds to: a rounded tap leaves the slice plane and reads as
    /// geometry rising above the surface, which darkened open ground by up to 4 % depending on the view angle.
    bool interpolateTaps = true;
  };

  /** The b0 block of the three programs (all float4, so every backend lays it out alike). */
  struct AmbientOcclusionConstants
  {
    float projection[4]; ///< m00, m11, m22, m32
    float rect[4];       ///< back buffer pixels: x, y, width, height
    float aoRect[4];     ///< the same in pixels of the occlusion target: first x, first y, last x, last y
    float quality[4];    ///< radius, intensity, slices, steps
    float size[4];       ///< scale (1 or 2: depth pixels per occlusion pixel), 1 / far view depth, 0, power
    float blur[4];       ///< direction x, y (in occlusion pixels), depth tolerance, 0
    float shape[4]; ///< plane tolerance (change of slope), 1 to interpolate the taps, smooth reach (world units), 0
  };
  static_assert(sizeof(AmbientOcclusionConstants) == 112, "seven float4");

  /** Occlusion target size for a back buffer of `width` x `height` pixels. */
  [[nodiscard]] inline std::uint32_t AmbientOcclusionTargetExtent(
    const std::uint32_t extent,
    const bool halfRes
  ) noexcept
  {
    return std::max<std::uint32_t>(1U, halfRes ? (extent + 1U) / 2U : extent);
  }

  [[nodiscard]] inline bool AmbientOcclusionHalfRes(
    const AmbientOcclusionParams& params
  ) noexcept
  {
    return params.halfResolution < 0 ? AmbientOcclusionQualityFor(params.level).halfRes : params.halfResolution != 0;
  }

  /** View-space depth of a depth-buffer value, the inverse of depth = m22 + m32 / z. */
  [[nodiscard]] inline float AmbientOcclusionViewDepth(
    const AmbientOcclusionParams& params,
    const float depth
  ) noexcept
  {
    return params.projectionDepthBias / (depth - params.projectionDepthScale);
  }

  /** The block for the pass at `level`; `farDepth` is the view depth stored as 1.0 in the occlusion target's depth
   * channel. */
  [[nodiscard]] inline AmbientOcclusionConstants BuildAmbientOcclusionConstants(
    const AmbientOcclusionParams& params
  ) noexcept
  {
    const AmbientOcclusionQuality quality = AmbientOcclusionQualityFor(params.level);
    const bool half = AmbientOcclusionHalfRes(params);
    const float scale = half ? 2.0f : 1.0f;
    AmbientOcclusionConstants constants{};
    constants.projection[0] = params.projectionXScale;
    constants.projection[1] = params.projectionYScale;
    constants.projection[2] = params.projectionDepthScale;
    constants.projection[3] = params.projectionDepthBias;
    constants.rect[0] = params.rectX;
    constants.rect[1] = params.rectY;
    constants.rect[2] = params.rectWidth;
    constants.rect[3] = params.rectHeight;
    constants.aoRect[0] = std::floor(params.rectX / scale);
    constants.aoRect[1] = std::floor(params.rectY / scale);
    constants.aoRect[2] = std::ceil((params.rectX + params.rectWidth) / scale) - 1.0f;
    constants.aoRect[3] = std::ceil((params.rectY + params.rectHeight) / scale) - 1.0f;
    constants.quality[0] = std::max(params.radius, 0.01f);
    constants.quality[1] = std::max(params.intensity, 0.0f);
    constants.quality[2] = static_cast<float>(quality.slices);
    constants.quality[3] = static_cast<float>(quality.steps);
    // The far end of the stored depth: the view depth of depth value 1.
    // (an infinite far plane, depth scale 1, has none: a fixed range keeps the 16-bit channel useful)
    float farDepth = std::fabs(AmbientOcclusionViewDepth(params, 1.0f));
    if (!(farDepth < 8192.0f)) {
      farDepth = 8192.0f;
    }
    constants.size[0] = scale;
    constants.size[1] = 1.0f / std::max(farDepth, 1.0f);
    constants.size[2] = 0.0f;
    constants.size[3] = std::max(params.power, 0.1f);
    constants.shape[0] = std::max(params.planeTolerance, 1.0e-3f);
    constants.shape[1] = params.interpolateTaps ? 1.0f : 0.0f;
    constants.shape[2] = std::max(params.smoothReach, 0.0f);
    constants.blur[2] = 40.0f; // relative depth difference at which a neighbour stops counting: 1 / 40 = 2.5 %
    return constants;
  }
} // namespace gpg::gal

namespace gpg::gal::backend
{
  /**
   * The HLSL: one full-screen triangle vertex shader `AoVS` and three pixel shaders (shader model 4 only, explicit
   * registers: depth `t6`, the occlusion target `t4`, constants `b0`; `Load` only, so the sampler is never used).
   *   AoComputePS   depth -> (occlusion, view depth / far) per occlusion pixel: GTAO horizon search
   *   AoBlurPS      (occlusion, depth) -> the same, blurred along `blur.xy` with weights that drop at depth edges
   *   AoWidePS      the wide taps alone over smooth ground (drawn only with `smoothReach` above 0, after the two core
   * blurs) AoCompositePS the vertical blur at back buffer resolution, upsampling a half-resolution target depth-aware,
   * written as black with alpha = 1 - occlusion so a plain alpha blend multiplies the colour by the occlusion
   */
  inline constexpr char kAmbientOcclusionSource[] = R"hlsl(
cbuffer AoConstants : register(b0)
{
    float4 uProj;    // m00, m11, m22, m32
    float4 uRect;    // back buffer pixels: x, y, width, height
    float4 uAoRect;  // occlusion pixels: first x, first y, last x, last y
    float4 uQuality; // radius, intensity, slices, steps
    float4 uSize;    // scale, 1 / far depth, -, power
    float4 uBlur;    // direction x, y, depth tolerance, 1 in the last pass (which adds the wide taps to the core ones)
    float4 uShape;   // plane tolerance (change of slope), 1 to interpolate the taps, smooth reach (world units), -
};
// The registers of the GPU-driven binding model (GpuDriven.h): the occlusion target is GpuBindings::targets[0] (t4), the scene depth
// GpuBindings::depthTarget (t6, binding 10 on Vulkan).
#ifdef __spirv__
[[vk::binding(10, 0)]]
#endif
Texture2D<float> faf_depth : register(t6);
Texture2D<float2> faf_ao : register(t4);

struct AoVertex { float4 position : SV_Position; float2 uv : TEXCOORD0; };
AoVertex AoVS(uint id : SV_VertexID)
{
    AoVertex o;
    float2 p = float2((id << 1) & 2, id & 2);
    o.position = float4(p * float2(2, -2) + float2(-1, 1), 0, 1);
    o.uv = p;
    return o;
}

static const float AO_PI = 3.14159265;
static const float AO_HALF_PI = 1.57079633;
// The occlusion is kept in the target as ao / AO_HEADROOM (so up to AO_HEADROOM can be stored): a pixel's horizon search is noisy and its
// estimate of a plane's openness scatters around 1, and clamping it at 1 before the blur would turn that scatter into darkening of open
// ground (up to 1.4 % at Low). The composite clamps after the blur.
static const float AO_HEADROOM = 1.25;
static const float AO_OPEN = 1.0 / AO_HEADROOM; // stored value of no occlusion
static const float AO_SMOOTH_RANGE_GAIN = 40.0; // a wide blur tap gets no weight once its stored occlusion differs from the centre's by 1 / 40 (an occlusion step of 1 / 32)
static const float AO_BAYER[16] = { 0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5 };

// Pixel of the output as an integer (Vulkan draws through a viewport the engine shifts by half a pixel: the floor is right either way).
int2 AoPixel(float4 position) { return int2(floor(position.xy)); }

float AoViewZ(float depth) { return uProj.w / (depth - uProj.z); }

int2 AoClampToRect(int2 p) { return clamp(p, int2(uRect.xy), int2(uRect.xy + uRect.zw) - 1); }

float AoDepthAt(int2 p) { return faf_depth.Load(int3(AoClampToRect(p), 0)); }

// Depth buffer value at a back buffer pixel; the sky (depth 1) and anything outside the rectangle read as the nearest valid pixel / far.
float AoViewZAt(int2 p)
{
    float d = faf_depth.Load(int3(AoClampToRect(p), 0));
    return d >= 0.99999 ? 1.0e5 : AoViewZ(d);
}

float3 AoViewPos(float2 pixelCentre, float z)
{
    float2 ndc = (pixelCentre - uRect.xy) / uRect.zw * 2.0 - 1.0;
    ndc.y = -ndc.y;
    return float3(ndc.x * z / uProj.x, ndc.y * z / uProj.y, z);
}

float3 AoViewPosAt(int2 p, float z) { return AoViewPos(float2(p) + 0.5, z); }

// View depth at a continuous screen position (pixel centres at +0.5). The depth buffer value is affine in the inverse depth, so over a
// plane it is affine in screen position, and interpolating it between the four texels is exact there; a tap on a slanted plane then lies
// in its slice plane (a tap rounded to a texel does not, and reads as geometry that rises above the plane). Across an edge (the texels
// disagree by more than 5 % of the inverse depth, or one is the sky) the nearest texel is taken, so no depth is invented between surfaces.
float AoSampleZ(float2 position)
{
    float2 f = position - 0.5;
    int2 i0 = int2(floor(f));
    float2 w = f - float2(i0);
    float d00 = AoDepthAt(i0);
    float d10 = AoDepthAt(i0 + int2(1, 0));
    float d01 = AoDepthAt(i0 + int2(0, 1));
    float d11 = AoDepthAt(i0 + int2(1, 1));
    float low = min(min(d00, d10), min(d01, d11));
    float high = max(max(d00, d10), max(d01, d11));
    if (high >= 0.99999 || high - low > 0.05 * abs(low - uProj.z))
        return AoViewZAt(int2(floor(position)));
    return AoViewZ(lerp(lerp(d00, d10, w.x), lerp(d01, d11, w.x), w.y));
}

float2 AoComputePS(AoVertex v) : SV_Target0
{
    int2 aoPixel = AoPixel(v.position);
    int2 p = int2(float2(aoPixel) * uSize.x);
    float d = faf_depth.Load(int3(AoClampToRect(p), 0));
    if (d >= 0.99999)
        return float2(AO_OPEN, 1.0);
    float z = AoViewZ(d);
    float zNorm = saturate(z * uSize.y);
    float3 P = AoViewPosAt(p, z);

    // View-space normal from the depth differences, taking the nearer neighbour on each axis so it does not smear over silhouettes.
    float zl = AoViewZAt(p + int2(-1, 0)); float zr = AoViewZAt(p + int2(1, 0));
    float zu = AoViewZAt(p + int2(0, -1)); float zd = AoViewZAt(p + int2(0, 1));
    float3 dx = abs(zr - z) < abs(zl - z) ? AoViewPosAt(p + int2(1, 0), zr) - P : P - AoViewPosAt(p + int2(-1, 0), zl);
    float3 dy = abs(zd - z) < abs(zu - z) ? AoViewPosAt(p + int2(0, 1), zd) - P : P - AoViewPosAt(p + int2(0, -1), zu);
    float3 N = cross(dx, dy);
    float nl = length(N);
    if (nl < 1.0e-12)
        return float2(AO_OPEN, zNorm);
    N /= nl;
    float3 V = normalize(-P);
    if (dot(N, V) < 0.0)
        N = -N;

    float radius = uQuality.x;
    // The search is also capped in screen space (6 % of the view height): zoomed in, the world radius spans hundreds of pixels, the taps
    // leave the cache and the cost doubles, and the occlusion becomes a wide haze around every object instead of a contact shadow.
    float radiusPixels = min(radius / z * uProj.x * 0.5 * uRect.z, uRect.w * 0.06);
    if (radiusPixels < 1.5)
        return float2(AO_OPEN, zNorm);

    int slices = (int)uQuality.z;
    int steps = (int)uQuality.w;
    float noiseSlice = (AO_BAYER[(aoPixel.y & 3) * 4 + (aoPixel.x & 3)] + 0.5) / 16.0;
    float noiseStep = (AO_BAYER[((aoPixel.y + 1) & 3) * 4 + ((aoPixel.x + 2) & 3)] + 0.5) / 16.0;

    float falloffRange = 0.615 * radius;
    float falloffMul = -1.0 / falloffRange;
    float falloffAdd = (radius - falloffRange) / falloffRange + 1.0;

    float visibility = 0.0;
    [loop] for (int slice = 0; slice < slices; slice++)
    {
        float phi = (float(slice) + noiseSlice) / float(slices) * AO_PI;
        float sinPhi, cosPhi;
        sincos(phi, sinPhi, cosPhi);
        float2 omega = float2(cosPhi, -sinPhi);
        float3 directionVec = float3(cosPhi, sinPhi, 0.0);
        float3 orthoDirectionVec = directionVec - dot(directionVec, V) * V;
        float3 axisVec = normalize(cross(orthoDirectionVec, V));
        float3 projectedNormal = N - axisVec * dot(N, axisVec);
        float projectedLength = length(projectedNormal);
        float signNorm = sign(dot(orthoDirectionVec, projectedNormal));
        float cosNorm = saturate(dot(projectedNormal, V) / max(projectedLength, 1.0e-6));
        float nAngle = signNorm * acos(cosNorm);

        float horizonCos0 = cos(nAngle + AO_HALF_PI);
        float horizonCos1 = cos(nAngle - AO_HALF_PI);
        float low0 = horizonCos0;
        float low1 = horizonCos1;
        [loop] for (int tap = 0; tap < steps; tap++)
        {
            float s = (float(tap) + noiseStep) / float(steps);
            float offset = 1.3 + s * s * radiusPixels;
            float2 so = omega * offset;
            float2 s0 = float2(p) + 0.5 + so;
            float2 s1 = float2(p) + 0.5 - so;
            float3 delta0, delta1;
            if (uShape.y > 0.5)
            {
                // The depth at the tap's own position, so the tap lies in the slice plane.
                delta0 = AoViewPos(s0, AoSampleZ(s0)) - P;
                delta1 = AoViewPos(s1, AoSampleZ(s1)) - P;
            }
            else
            {
                // The texel the tap rounds to, at that texel's centre (the old behaviour, ren_AOTapInterp 0).
                int2 p0 = int2(floor(s0));
                int2 p1 = int2(floor(s1));
                delta0 = AoViewPosAt(p0, AoViewZAt(p0)) - P;
                delta1 = AoViewPosAt(p1, AoViewZAt(p1)) - P;
            }
            float dist0 = max(length(delta0), 1.0e-5);
            float dist1 = max(length(delta1), 1.0e-5);
            float shc0 = dot(delta0 / dist0, V);
            float shc1 = dot(delta1 / dist1, V);
            shc0 = lerp(low0, shc0, saturate(dist0 * falloffMul + falloffAdd));
            shc1 = lerp(low1, shc1, saturate(dist1 * falloffMul + falloffAdd));
            horizonCos0 = max(horizonCos0, shc0);
            horizonCos1 = max(horizonCos1, shc1);
        }

        float h0 = -acos(clamp(horizonCos1, -1.0, 1.0));
        float h1 = acos(clamp(horizonCos0, -1.0, 1.0));
        h0 = nAngle + clamp(h0 - nAngle, -AO_HALF_PI, AO_HALF_PI);
        h1 = nAngle + clamp(h1 - nAngle, -AO_HALF_PI, AO_HALF_PI);
        float iarc0 = (cosNorm + 2.0 * h0 * sin(nAngle) - cos(2.0 * h0 - nAngle)) * 0.25;
        float iarc1 = (cosNorm + 2.0 * h1 * sin(nAngle) - cos(2.0 * h1 - nAngle)) * 0.25;
        visibility += projectedLength * (iarc0 + iarc1);
    }
    visibility = max(visibility / float(slices), 0.0);
    return float2(min(pow(visibility, uSize.w), AO_HEADROOM) / AO_HEADROOM, zNorm);
}

// The wide taps of the smoothing pass. A terrain mesh of one triangle pair per world unit leaves the pattern of its triangles in the
// occlusion (every facet has its own tilt against the surface the neighbours lie on), which is as wide as the triangles: these taps
// average it away over smooth ground. Three pairs, evenly spread out to uShape.z world units from the centre (at most 32 pixels), count
// while both ends lie in the plane of the centre (the second difference of the inverse depth, as the normal's, measured as a change of
// slope, stays under uShape.x: a crease, an edge, a wall's foot do not) and their occlusion is close to the centre's (a real crease keeps
// its contrast, a facet's faint step is averaged). They read an input the core blur has already cleaned of the noise pattern.
void AoWideTaps(int2 centre, int2 direction, float centreZ, float centreAo, inout float sum, inout float weightSum)
{
    int2 lo = int2(uAoRect.xy);
    int2 hi = int2(uAoRect.zw);
    float viewZ = max(centreZ / uSize.y, 1.0e-3);
    float focal = uProj.y * 0.5 * uRect.w / uSize.x; // pixels of the occlusion target per world unit at distance 1
    float reach = min(uShape.z * focal / viewZ, 32.0);
    float spacing = reach / 3.0;
    if (spacing < 1.0)
        return;
    [unroll] for (int j = 1; j <= 3; j++)
    {
        int offset = (int)round(spacing * float(j));
        float2 tapA = faf_ao.Load(int3(clamp(centre + direction * offset, lo, hi), 0));
        float2 tapB = faf_ao.Load(int3(clamp(centre - direction * offset, lo, hi), 0));
        float bend = abs(centreZ / max(tapA.y, 1.0e-4) + centreZ / max(tapB.y, 1.0e-4) - 2.0) * focal / float(offset);
        float valid = saturate(1.0 - bend / uShape.x);
        float wA = valid * saturate(1.0 - abs(tapA.x - centreAo) * AO_SMOOTH_RANGE_GAIN);
        float wB = valid * saturate(1.0 - abs(tapB.x - centreAo) * AO_SMOOTH_RANGE_GAIN);
        sum += tapA.x * wA + tapB.x * wB;
        weightSum += wA + wB;
    }
}

// The blur taps: offsets -2..2 with weights 0.5 1 1 1 0.5, which covers one period of the 4x4 noise pattern exactly; a tap whose depth
// differs from the centre's by more than the tolerance gets no weight. In the last pass (uBlur.w) the wide taps come on top.
float2 AoBlurAt(int2 centre, int2 direction, float centreZ)
{
    float sum = 0.0;
    float weightSum = 0.0;
    float centreAo = 1.0;
    int2 lo = int2(uAoRect.xy);
    int2 hi = int2(uAoRect.zw);
    [unroll] for (int i = -2; i <= 2; i++)
    {
        float2 tap = faf_ao.Load(int3(clamp(centre + direction * i, lo, hi), 0));
        float w = (i == -2 || i == 2) ? 0.5 : 1.0;
        float relative = abs(tap.y - centreZ) / (centreZ + 0.002);
        w *= saturate(1.0 - relative * uBlur.z);
        if (i == 0)
            centreAo = tap.x;
        sum += tap.x * w;
        weightSum += w;
    }
    if (uShape.z > 0.0 && uBlur.w > 0.5)
        AoWideTaps(centre, direction, centreZ, centreAo, sum, weightSum);
    return float2(weightSum > 1.0e-4 ? sum / weightSum : AO_OPEN, centreZ);
}

// The smoothing pass proper (only drawn with uShape.z > 0): the wide taps alone, over the occlusion the two core passes cleaned.
float2 AoWidePS(AoVertex v) : SV_Target0
{
    int2 aoPixel = clamp(AoPixel(v.position), int2(uAoRect.xy), int2(uAoRect.zw));
    float2 centre = faf_ao.Load(int3(aoPixel, 0));
    if (centre.y >= 0.99999)
        return float2(AO_OPEN, 1.0);
    float sum = centre.x;
    float weightSum = 1.0;
    AoWideTaps(aoPixel, int2(uBlur.xy), centre.y, centre.x, sum, weightSum);
    return float2(sum / weightSum, centre.y);
}

float2 AoBlurPS(AoVertex v) : SV_Target0
{
    int2 aoPixel = AoPixel(v.position);
    float2 centre = faf_ao.Load(int3(clamp(aoPixel, int2(uAoRect.xy), int2(uAoRect.zw)), 0));
    if (centre.y >= 0.99999)
        return float2(AO_OPEN, 1.0);
    return AoBlurAt(aoPixel, int2(uBlur.xy), centre.y);
}

float4 AoCompositePS(AoVertex v) : SV_Target0
{
    int2 pixel = AoPixel(v.position);
    float d = faf_depth.Load(int3(AoClampToRect(pixel), 0));
    if (d >= 0.99999)
        return float4(0, 0, 0, 0);
    float zNorm = saturate(AoViewZ(d) * uSize.y);
    int2 aoPixel = int2(float2(pixel) / uSize.x);
    float2 blurred = AoBlurAt(aoPixel, int2(uBlur.xy), zNorm);
    return float4(0, 0, 0, saturate((1.0 - blurred.x * AO_HEADROOM) * uQuality.y));
}
)hlsl";

  /** The source a backend compiles (the registers are the GPU-driven binding model's t4 and t6). */
  [[nodiscard]] inline std::string AmbientOcclusionSource()
  {
    return std::string(kAmbientOcclusionSource);
  }
} // namespace gpg::gal::backend
