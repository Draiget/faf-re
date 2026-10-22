#pragma once

// Engine-owned HLSL for GPU-instanced projectile icons (`ren_GpuProjectileIcons`,
// ProjectileIconRenderer).
//
// `CWldSession::RenderProjectileIcons` draws one `CD3DPrimBatcher::DrawQuad`
// per visible projectile under primbatcher.fx TAlphaBlendLinearSampleNoDepth:
// a screen quad around the floored projected point, white vertex colour,
// textured with the projectile's strategic icon or its army's solid colour.
// Here each projectile is one 20-byte record (centre, half extents, texture
// slot) and one instanced draw expands the quads in the same order, with the
// same corners, the same UVs (the batcher's atlas rectangle) and the pass's
// shading: texel times the vertex colour, alpha times the batcher's alpha
// multiplier, D3D9's alpha test (AlphaFunc Greater, AlphaRef 0) on the 8-bit
// alpha, src-alpha / inv-src-alpha blend into RGB, no depth, no culling.
//
// Bindings follow gpg/gal/GpuDriven.h (b0, t0..t1, t4, s0), so DXC builds the
// same source for D3D12 (DXIL) and Vulkan (SPIR-V).

#include <cstdint>

namespace moho
{
  /** One projectile icon (`IconRecord` below). */
  struct ProjectileIconInstance
  {
    float mCenter[2] = {};     ///< the floored projected point
    float mHalfExtent[2] = {}; ///< half width and half height, in pixels
    std::uint32_t mSlot = 0U;  ///< index into the frame's slot table
  };
  static_assert(sizeof(ProjectileIconInstance) == 20, "ProjectileIconInstance must match IconRecord");

  /** One texture's atlas rectangle (`IconSlot` below). */
  struct ProjectileIconSlot
  {
    float mUv[4] = {}; ///< atlas origin (xy) and extent (zw), as CD3DPrimBatcher::SetTexture keeps them
  };
  static_assert(sizeof(ProjectileIconSlot) == 16, "ProjectileIconSlot must match IconSlot");

  inline constexpr std::uint32_t kProjectileIconVerticesPerInstance = 6U;

  inline constexpr char kProjectileIconShaderSource[] = R"hlsl(
cbuffer ProjectileIconConstants : register(b0)
{
    row_major float4x4 Composite; // CD3DPrimBatcher's view * projection
    float AlphaMultiplier;        // the batcher's alpha multiplier
    float3 Unused;
};

struct IconRecord
{
    float2 center;
    float2 halfExtent;
    uint slot;
};

struct IconSlot
{
    float4 uv;
};

StructuredBuffer<IconRecord> Records : register(t0);
StructuredBuffer<IconSlot> Slots : register(t1);
Texture2D Atlas : register(t4);
SamplerState LinearSampler : register(s0);

struct IconVertex
{
    float4 position : SV_Position;
    float2 uv : TEXCOORD0;
};

IconVertex ProjectileIconVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID)
{
    // RenderProjectileIcons' DrawQuad corners, in its order: (left, top, uv 0,1),
    // (left, bottom, 0,0), (right, bottom, 1,0), (right, top, 1,1); the batcher
    // draws corners 0,1,2 and 2,3,0.
    static const uint kCornerOfVertex[6] = { 0, 1, 2, 2, 3, 0 };
    static const float2 kSide[4] = { float2(-1.0, -1.0), float2(-1.0, 1.0), float2(1.0, 1.0), float2(1.0, -1.0) };
    static const float2 kUv[4] = { float2(0.0, 1.0), float2(0.0, 0.0), float2(1.0, 0.0), float2(1.0, 1.0) };

    IconRecord record = Records[instanceId];
    uint corner = kCornerOfVertex[vertexId];
    float2 side = kSide[corner];
    // centre - half / centre + half, as the CPU computes them.
    precise float x = side.x < 0.0 ? record.center.x - record.halfExtent.x : record.center.x + record.halfExtent.x;
    precise float y = side.y < 0.0 ? record.center.y - record.halfExtent.y : record.center.y + record.halfExtent.y;

    IconSlot slot = Slots[record.slot];
    IconVertex output;
    output.position = mul(float4(x, y, 1.0, 1.0), Composite);
    output.uv = slot.uv.xy + slot.uv.zw * kUv[corner];
    return output;
}

float4 ProjectileIconPS(IconVertex input) : SV_Target
{
    // The vertex colour is white, so the texel is the colour.
    float4 color = Atlas.Sample(LinearSampler, input.uv);
    color.a *= AlphaMultiplier;
    // D3D9 alpha test, AlphaFunc Greater, AlphaRef 0, on the 8-bit alpha.
    if ((uint)round(saturate(color.a) * 255.0) <= 0u)
    {
        discard;
    }
    return color;
}
)hlsl";
} // namespace moho
