#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

// FAF addition, not in the shipped binary: render scale. The 3D world is drawn into a target that is a fraction of the
// window and then upscaled into the back buffer before the interface, which is drawn at native resolution
// (docs/RENDERER_BACKENDS.md, "Render scale"). This header holds the quality table, the pure arithmetic around the pass
// and the HLSL (shared by Direct3D 11, 12 and Vulkan through the GPU programs of GpuDriven.h); a host test runs the
// same source on a software device.
//
// The upscaler is our own, in the spirit of an edge-adaptive spatial upscaler:
//   - Upscale: the 4x4 source texels around the sample point are weighted with a Lanczos-2 style kernel whose axes
//   follow the local image
//     structure. A structure tensor of the luma (bilinearly blended from the four central texels) gives the edge
//     direction and how one-sided the neighbourhood is; the kernel is stretched along the edge and tightened across it,
//     so a diagonal edge is reconstructed as a clean line instead of a staircase. The result is clamped to the range of
//     the four texels around the sample, which removes ringing.
//   - Sharpen: a contrast-adaptive 5-tap pass on the upscaled image. The negative lobe is limited per pixel to what the
//   neighbours can take
//     without leaving the 0..1 range, so flat areas and already-bright edges get nothing and thin dark lines get the
//     most.
namespace gpg::gal
{
  /**
   * Fraction of the window's width and height the world is drawn at, from `ren_RenderScale` (0.5 to 1; 1, or anything
   * that is not a number, draws at the window's size and nothing extra).
   */
  [[nodiscard]] inline float RenderScaleFactorFor(
    const float requested
  ) noexcept
  {
    if (!(requested < 1.0f)) {
      return 1.0f;
    }
    return requested < 0.5f ? 0.5f : requested;
  }

  /** Size of the scaled target for a window extent: rounded up, at least 1. */
  [[nodiscard]] inline std::uint32_t RenderScaleExtent(
    const std::uint32_t extent,
    const float factor
  ) noexcept
  {
    const float scaled = std::ceil(static_cast<float>(extent) * factor - 1.0e-4f);
    return std::max(1U, static_cast<std::uint32_t>(scaled));
  }

  /** Integer pixel rectangle (x, y, width, height). */
  struct RenderScaleRect
  {
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
  };

  /**
   * The rectangle of the scaled target that stands for `window` (a view's pixel rectangle in the window): origin
   * rounded down, far edge rounded up, so adjacent views neither leave a gap nor overlap by more than a pixel, clamped
   * to the scaled target.
   */
  [[nodiscard]] inline RenderScaleRect RenderScaleSourceRect(
    const RenderScaleRect& window,
    const float factor,
    const std::uint32_t targetWidth,
    const std::uint32_t targetHeight
  ) noexcept
  {
    const int x0 = std::max(0, static_cast<int>(std::floor(static_cast<float>(window.x) * factor + 1.0e-4f)));
    const int y0 = std::max(0, static_cast<int>(std::floor(static_cast<float>(window.y) * factor + 1.0e-4f)));
    const int x1 = std::min(
      static_cast<int>(targetWidth),
      static_cast<int>(std::ceil(static_cast<float>(window.x + window.width) * factor - 1.0e-4f))
    );
    const int y1 = std::min(
      static_cast<int>(targetHeight),
      static_cast<int>(std::ceil(static_cast<float>(window.y + window.height) * factor - 1.0e-4f))
    );
    RenderScaleRect rect;
    rect.x = x0;
    rect.y = y0;
    rect.width = std::max(0, x1 - x0);
    rect.height = std::max(0, y1 - y0);
    return rect;
  }

  /** The b0 block of the programs (float4s, so every backend lays it out alike). */
  struct RenderScaleConstants
  {
    float source[4]; ///< texels of the scaled target: x, y, width, height of the region that is upscaled
    float dest[4];   ///< pixels of the back buffer: x, y, width, height of the region it fills
    float params[4]; ///< sharpness 0..1, 0, 0, 0
  };
  static_assert(sizeof(RenderScaleConstants) == 48, "three float4");

  [[nodiscard]] inline RenderScaleConstants BuildRenderScaleConstants(
    const RenderScaleRect& source,
    const RenderScaleRect& dest,
    const float sharpness
  ) noexcept
  {
    RenderScaleConstants constants{};
    constants.source[0] = static_cast<float>(source.x);
    constants.source[1] = static_cast<float>(source.y);
    constants.source[2] = static_cast<float>(source.width);
    constants.source[3] = static_cast<float>(source.height);
    constants.dest[0] = static_cast<float>(dest.x);
    constants.dest[1] = static_cast<float>(dest.y);
    constants.dest[2] = static_cast<float>(dest.width);
    constants.dest[3] = static_cast<float>(dest.height);
    constants.params[0] = std::clamp(sharpness, -1.0f, 1.0f); // < 0: diagnostic, the scaled texels unfiltered
    return constants;
  }

  /**
   * HLSL. Entry points: `ScaleVS` (one full-screen triangle), `UpscalePS` (source texture `t4` -> the upscaled colour)
   * and `SharpenPS`
   * (`t4` is the upscaled image, at back buffer coordinates). `Load` only, so the sampler is never used. Pixel
   * coordinates come from SV_Position floored (Vulkan draws through a viewport the engine shifts by half a pixel: the
   * floor is right either way).
   */
  inline constexpr char kRenderScaleSource[] = R"hlsl(
cbuffer ScaleConstants : register(b0)
{
    float4 uSource; // texels of the scaled target: x, y, width, height
    float4 uDest;   // back buffer pixels: x, y, width, height
    float4 uParams; // sharpness, -, -, -
};
#ifndef SCALE_TEXTURE_REG
#define SCALE_TEXTURE_REG t4
#endif
Texture2D<float4> faf_scene : register(SCALE_TEXTURE_REG);

struct ScaleVertex { float4 position : SV_Position; };
ScaleVertex ScaleVS(uint id : SV_VertexID)
{
    ScaleVertex o;
    float2 p = float2((id << 1) & 2, id & 2);
    o.position = float4(p * float2(2, -2) + float2(-1, 1), 0, 1);
    return o;
}

float ScaleLuma(float3 c) { return dot(c, float3(0.25, 0.5, 0.25)); }

// Kernel weight at squared distance x2 (0..4): a smooth polynomial with Lanczos-2's zeros at 1 and 2 and the value 1 at 0.
float ScaleKernel(float x2)
{
    float a = 0.4 * x2 - 1.0;
    float b = 0.25 * x2 - 1.0;
    return (1.5625 * a * a - 0.5625) * b * b * step(x2, 4.0);
}

float4 UpscalePS(ScaleVertex v) : SV_Target0
{
    int2 pixel = int2(floor(v.position.xy));
    // The sample point in texels of the scaled target, continuous (texel i has its centre at i + 0.5).
    float2 uv = (float2(pixel) + 0.5 - uDest.xy) * (uSource.zw / uDest.zw) + uSource.xy;
    if (uParams.x < 0.0)
    {
        // diagnostic (ren_RenderScaleSharpness = -1): the texels of the scaled world as they are, no filter
        int2 lo0 = int2(uSource.xy);
        return float4(faf_scene.Load(int3(clamp(int2(floor(uv)), lo0, lo0 + int2(uSource.zw) - 1), 0)).rgb, 1.0);
    }
    float2 f = uv - 0.5;
    float2 base = floor(f);
    float2 fr = f - base;
    int2 origin = int2(base) - 1;
    int2 lo = int2(uSource.xy);
    int2 hi = lo + int2(uSource.zw) - 1;

    float3 c[16];
    float l[16];
    [unroll] for (int j = 0; j < 4; ++j)
    {
        [unroll] for (int i = 0; i < 4; ++i)
        {
            int2 p = clamp(origin + int2(i, j), lo, hi);
            float3 s = faf_scene.Load(int3(p, 0)).rgb;
            c[j * 4 + i] = s;
            l[j * 4 + i] = ScaleLuma(s);
        }
    }

    // Structure tensor of the luma gradient at the four central texels, blended with the bilinear weights of the sample point.
    float4 bw = float4((1.0 - fr.x) * (1.0 - fr.y), fr.x * (1.0 - fr.y), (1.0 - fr.x) * fr.y, fr.x * fr.y);
    float txx = 0.0, tyy = 0.0, txy = 0.0;
    [unroll] for (int q = 0; q < 4; ++q)
    {
        int ci = 1 + (q & 1);
        int cj = 1 + (q >> 1);
        float gx = l[cj * 4 + ci + 1] - l[cj * 4 + ci - 1];
        float gy = l[(cj + 1) * 4 + ci] - l[(cj - 1) * 4 + ci];
        txx += bw[q] * gx * gx;
        tyy += bw[q] * gy * gy;
        txy += bw[q] * gx * gy;
    }
    // Eigen decomposition of [[txx, txy], [txy, tyy]]: the normal is the strong gradient direction, the edge runs across it.
    float tr = txx + tyy;
    float dif = txx - tyy;
    float root = sqrt(dif * dif + 4.0 * txy * txy);
    float lam1 = 0.5 * (tr + root);
    float lam2 = 0.5 * (tr - root);
    float2 normal = float2(1.0, 0.0);
    if (root > 1.0e-8)
        normal = normalize(float2(dif + root, 2.0 * txy));
    else if (tyy > txx)
        normal = float2(0.0, 1.0);
    float2 edge = float2(-normal.y, normal.x);
    // One-sidedness of the neighbourhood (0 isotropic, 1 a clean edge) gated by its contrast, so noise and flat areas keep the plain kernel.
    float aniso = (lam1 - lam2) / (lam1 + lam2 + 1.0e-6);
    float contrast = saturate(sqrt(lam1) * 6.0);
    float a = aniso * contrast;
    float alongScale = lerp(1.0, 0.72, a);   // < 1: the kernel reaches further along the edge
    float acrossScale = lerp(1.0, 1.30, a);  // > 1: and is tighter across it

    float3 sum = 0.0;
    float wsum = 0.0;
    [unroll] for (int j2 = 0; j2 < 4; ++j2)
    {
        [unroll] for (int i2 = 0; i2 < 4; ++i2)
        {
            float2 d = float2(float(i2 - 1), float(j2 - 1)) - fr;
            float along = dot(d, edge) * alongScale;
            float across = dot(d, normal) * acrossScale;
            float w = ScaleKernel(along * along + across * across);
            sum += w * c[j2 * 4 + i2];
            wsum += w;
        }
    }
    float3 result = sum / max(wsum, 1.0e-5);
    // No ringing: stay inside the range of the four texels the sample point lies between.
    float3 mn = min(min(c[5], c[6]), min(c[9], c[10]));
    float3 mx = max(max(c[5], c[6]), max(c[9], c[10]));
    return float4(clamp(result, mn, mx), 1.0);
}

float4 SharpenPS(ScaleVertex v) : SV_Target0
{
    int2 pixel = int2(floor(v.position.xy));
    int2 lo = int2(uDest.xy);
    int2 hi = lo + int2(uDest.zw) - 1;
    float3 cc = faf_scene.Load(int3(pixel, 0)).rgb;
    float3 cn = faf_scene.Load(int3(clamp(pixel + int2(0, -1), lo, hi), 0)).rgb;
    float3 cs = faf_scene.Load(int3(clamp(pixel + int2(0, 1), lo, hi), 0)).rgb;
    float3 cw = faf_scene.Load(int3(clamp(pixel + int2(-1, 0), lo, hi), 0)).rgb;
    float3 ce = faf_scene.Load(int3(clamp(pixel + int2(1, 0), lo, hi), 0)).rgb;
    float3 mn = min(min(cn, cs), min(cw, ce));
    float3 mx = max(max(cn, cs), max(cw, ce));
    // How negative the lobe may get before the result reaches 0 (low side) or 1 (high side), per channel; the least of the three channels
    // limits the pixel so no colour shifts.
    float3 hitMin = mn / (4.0 * mx + 1.0e-5);
    float3 hitMax = (1.0 - mx) / (4.0 * mn - 4.0 - 1.0e-5);
    float3 lobes = max(-hitMin, hitMax);
    float lobe = max(-0.1875, min(max(lobes.r, max(lobes.g, lobes.b)), 0.0)) * uParams.x;
    float3 result = (lobe * (cn + cs + cw + ce) + cc) / (4.0 * lobe + 1.0);
    return float4(saturate(result), 1.0);
}
)hlsl";

  [[nodiscard]] inline std::string RenderScaleSource()
  {
    return std::string(kRenderScaleSource);
  }
} // namespace gpg::gal
