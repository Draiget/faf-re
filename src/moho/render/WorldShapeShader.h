#pragma once

// Engine-owned HLSL for the GPU path of FAF's world shapes (`ren_GpuShapes`,
// WorldShapeGpuRenderer): UI_DrawLine, UI_DrawRect and UI_DrawCircle from
// FAF FA-Binary-Patches (section/DrawFunc.cpp).
//
// The prim-batcher path draws each shape as `CD3DPrimBatcher::DrawQuad` calls
// through primbatcher.fx TAlphaBlendLinearSampleNoDepth with a solid white
// texture: a line is one quad, a rectangle the four quads of `DRAW_Rect`, a
// circle the 48 quads of `DRAW_Oval`. Here the CPU writes one 112-byte record
// per shape holding exactly the corner points (or, for a circle, the centre and
// the four axes) the batcher path computes, and one instanced draw per run of
// same-kind shapes expands them in the same order: each quad's corners in
// `DrawQuad`'s order and triangles (0,1,2)(2,3,0), each circle segment's
// cosine and sine taken from a table the CPU fills with the same `std::cos` /
// `std::sin` calls `DRAW_Oval` makes. The blended result is the batcher's.
//
// The pixel shader is TAlphaBlendLinearSampleNoDepth's: the texel (linear,
// clamped, the solid white texture's place in the prim batcher's atlas) times
// the vertex colour, alpha times the batcher's alpha multiplier, and D3D9's
// alpha test (AlphaFunc Greater, AlphaRef 0) on the 8-bit alpha. Blend
// src-alpha/inv-src-alpha into RGB, no culling, no depth test or write.
//
// Bindings follow gpg/gal/GpuDriven.h (b0, t0, t4, s0), so DXC builds the same
// source for D3D12 (DXIL) and Vulkan (SPIR-V).

#include <cstdint>

#include "moho/render/d3d/CD3DPrimBatcher.h"

namespace moho
{
  enum class WorldShapeKind : std::uint32_t
  {
    Line = 0U,   ///< `mPoints[0..3]`: one quad, `DrawQuad` corner order
    Rect = 1U,   ///< `mPoints[0..3]` outer ring, `mPoints[4..7]` inner ring (`DrawRectRing`)
    Circle = 2U, ///< `mPoints[0]` centre, `[1..4]` inner sine, outer cosine, outer sine, inner cosine axes
  };

  /** One shape (`ShapeRecord` below). */
  struct WorldShapeRecord
  {
    float mPoints[8][3] = {};
    std::uint32_t mColor = 0U; ///< ARGB, as the batcher's vertex colour
    WorldShapeKind mKind = WorldShapeKind::Line;
    std::uint32_t mUnused[2] = {};
  };
  static_assert(sizeof(WorldShapeRecord) == 112, "WorldShapeRecord must match ShapeRecord");

  /** Quads each kind expands to. */
  [[nodiscard]] constexpr std::uint32_t WorldShapeQuadCount(const WorldShapeKind kind) noexcept
  {
    return kind == WorldShapeKind::Line ? 1U : kind == WorldShapeKind::Rect ? 4U : kDrawOvalSegmentCount;
  }

  static_assert(kDrawOvalSegmentCount == 48U, "OvalCosSin below holds 48 segments");

  inline constexpr char kWorldShapeShaderSource[] = R"hlsl(
cbuffer WorldShapeConstants : register(b0)
{
    row_major float4x4 Composite; // CD3DPrimBatcher's view * projection
    float4 UvTransform;           // the batcher's uv scale (xy) and offset (zw) for the solid white texture
    float AlphaMultiplier;        // the batcher's alpha multiplier
    uint BaseRecord;              // first record of this run
    uint Kind;                    // WorldShapeKind of every record in the run
    uint Unused;
    float4 OvalCosSin[24];        // DRAW_Oval's cos/sin per segment: xy segment 2i, zw segment 2i+1
};

struct ShapeRecord
{
    float3 points[8];
    uint color;
    uint kind;
    uint2 unused;
};

StructuredBuffer<ShapeRecord> Records : register(t0);
Texture2D Atlas : register(t4);
SamplerState LinearSampler : register(s0);

struct ShapeVertex
{
    float4 position : SV_Position;
    float4 color : COLOR0;
    float2 uv : TEXCOORD0;
};

float2 SegmentCosSin(uint segment)
{
    float4 pair = OvalCosSin[segment >> 1];
    return (segment & 1u) != 0u ? pair.zw : pair.xy;
}

ShapeVertex WorldShapeVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID)
{
    // DrawQuad's two triangles: corners 0,1,2 and 2,3,0.
    static const uint kCornerOfVertex[6] = { 0, 1, 2, 2, 3, 0 };
    // DRAW_Rect's four quads over the outer (0..3) and inner (4..7) rings.
    static const uint kRectCorner[16] = { 0, 4, 5, 1,  1, 5, 6, 2,  7, 3, 2, 6,  0, 3, 7, 4 };

    ShapeRecord record = Records[BaseRecord + instanceId];
    uint quad = vertexId / 6;
    uint corner = kCornerOfVertex[vertexId % 6];

    precise float3 world;
    if (Kind == 0u)
    {
        world = record.points[corner];
    }
    else if (Kind == 1u)
    {
        world = record.points[kRectCorner[quad * 4 + corner]];
    }
    else
    {
        // DRAW_Oval's quad: inner current, outer current, outer next, inner next.
        uint segment = corner >= 2 ? (quad + 1) % 48 : quad;
        bool outer = corner == 1 || corner == 2;
        float2 cs = SegmentCosSin(segment);
        float3 cosAxis = outer ? record.points[2] : record.points[4];
        float3 sinAxis = outer ? record.points[3] : record.points[1];
        precise float3 scaledCos = cosAxis * cs.x;
        precise float3 scaledSin = sinAxis * cs.y;
        precise float3 partial = record.points[0] + scaledCos;
        world = partial + scaledSin;
    }

    float2 unitUv = float2(corner == 1 || corner == 2 ? 1.0 : 0.0, corner >= 2 ? 1.0 : 0.0);

    ShapeVertex output;
    output.position = mul(float4(world, 1.0), Composite);
    // D3DCOLOR (ARGB) as it reaches the pixel shader.
    output.color = float4(
        (float)((record.color >> 16) & 0xFFu),
        (float)((record.color >> 8) & 0xFFu),
        (float)(record.color & 0xFFu),
        (float)(record.color >> 24)) / 255.0;
    output.uv = UvTransform.zw + UvTransform.xy * unitUv;
    return output;
}

float4 WorldShapePS(ShapeVertex input) : SV_Target
{
    float4 color = Atlas.Sample(LinearSampler, input.uv) * input.color;
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
