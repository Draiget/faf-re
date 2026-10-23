#pragma once

// Engine-owned HLSL for GPU-instanced selection brackets (`ren_GpuSelectBrackets`,
// SelectionBracketGpuRenderer).
//
// `DrawSelectionBrackets` draws four textured quads per selected entity through
// `CD3DPrimBatcher` (primbatcher.fx TAlphaBlendLinearSample): one bracket tile at
// each ground corner of the entity's flattened selection box, each tile the
// same four rotated corner offsets, each with its quarter of the 2x2 bracket
// texture. Here the CPU writes one 96-byte record per entity - the four ground
// corners and the four tile offsets, computed exactly as before - and one
// instanced draw expands them: 24 vertices per instance, four quads in the
// CPU's order, each quad's corners in `DrawQuad`'s order, so the blended result
// is the same.
//
// The pixel shader is TAlphaBlendLinearSample's: the texel (linear, clamped,
// from the prim batcher's atlas) times the vertex colour, alpha times the
// batcher's alpha multiplier, and D3D9's alpha test (AlphaFunc Greater,
// AlphaRef 0) on the 8-bit alpha. Blend src-alpha/inv-src-alpha into RGB, no
// culling; the depth state is whatever the frame already has bound, as for the
// technique, which sets none.
//
// Bindings follow gpg/gal/GpuDriven.h (b0, t0..t1, t4, s0), so DXC builds the
// same source for D3D12 (DXIL) and Vulkan (SPIR-V).

#include <cstdint>

namespace moho
{
  /** One entity's brackets (`BracketInstance` below). */
  struct SelectionBracketInstance
  {
    float mGroundCorners[4][3] = {}; ///< the box's ground corners 0, 1, 5, 4 (the order the quads are drawn in)
    float mTileOffsets[4][3] = {};   ///< the rotated tile corners, in `DrawQuad` order
  };
  static_assert(sizeof(SelectionBracketInstance) == 96, "SelectionBracketInstance must match BracketInstance");

  inline constexpr std::uint32_t kSelectionBracketVerticesPerInstance = 24U;

  inline constexpr char kSelectionBracketShaderSource[] = R"hlsl(
cbuffer SelectionBracketConstants : register(b0)
{
    row_major float4x4 Composite; // CD3DPrimBatcher's view * projection
    float4 AtlasRect;             // the bracket texture's atlas origin (xy) and extent (zw)
    float4 Color;                 // ren_SelectColor, as the vertex colour reaches the pixel shader
    float AlphaMultiplier;        // the batcher's alpha multiplier
    float3 Unused;
};

struct BracketInstance
{
    float3 groundCorners[4];
    float3 tileOffsets[4];
};

StructuredBuffer<BracketInstance> Instances : register(t0);
Texture2D Atlas : register(t4);
SamplerState LinearSampler : register(s0);

struct BracketVertex
{
    float4 position : SV_Position;
    float2 uv : TEXCOORD0;
};

BracketVertex SelectionBracketVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID)
{
    // DrawQuad's two triangles: corners 0,1,2 and 2,3,0.
    static const uint kCornerOfVertex[6] = { 0, 1, 2, 2, 3, 0 };
    // The top-left of each bracket's quarter of the 2x2 texture, in drawing order.
    static const float2 kTileOrigin[4] = { float2(0.0, 0.0), float2(0.5, 0.0), float2(0.5, 0.5), float2(0.0, 0.5) };

    BracketInstance instance = Instances[instanceId];
    uint bracket = vertexId / 6;
    uint corner = kCornerOfVertex[vertexId % 6];

    precise float3 world = instance.groundCorners[bracket] + instance.tileOffsets[corner];
    float2 tileUv = kTileOrigin[bracket] + float2(corner == 1 || corner == 2 ? 0.5 : 0.0, corner >= 2 ? 0.5 : 0.0);

    BracketVertex output;
    output.position = mul(float4(world, 1.0), Composite);
    output.uv = AtlasRect.xy + AtlasRect.zw * tileUv;
    return output;
}

float4 SelectionBracketPS(BracketVertex input) : SV_Target
{
    float4 color = Atlas.Sample(LinearSampler, input.uv) * Color;
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
