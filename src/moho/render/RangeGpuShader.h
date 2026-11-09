#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_GpuRanges` (RangeGpuRenderer): range.fx's "Cast" vertex shader
// with its two vertex streams pulled from structured buffers. The ring template
// is the static vertex buffer `RangeRenderer::Init` writes (five floats per
// vertex: position, then the inner/outer radius coefficients), the instances are
// the `SRangeExtractionPayload`s `func_RenderRings` builds. The depth/stencil
// state is the technique's, set on the program (RangeGpuRenderer.cpp).

namespace moho
{
  inline constexpr char kRangeGpuShaderSource[] = R"hlsl(
cbuffer RangeConstants : register(b0)
{
    row_major float4x4 View;       // range.fx viewMatrix
    row_major float4x4 Projection; // range.fx projMatrix
    uint FirstPayload;             // this batch's first payload in Payloads
    uint3 Unused;
};

// SRangeExtractionPayload: centre (x, z), then inner and outer radius.
struct RangePayload
{
    float2 Center;
    float2 Radius;
};

StructuredBuffer<float> CylinderVertices : register(t0);
StructuredBuffer<RangePayload> Payloads : register(t1);

float4 CastRangeVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID) : SV_Position
{
    const uint base = vertexId * 5;
    float3 vertex = float3(CylinderVertices[base], CylinderVertices[base + 1], CylinderVertices[base + 2]);
    const float2 coeff = float2(CylinderVertices[base + 3], CylinderVertices[base + 4]);
    const RangePayload payload = Payloads[FirstPayload + instanceId];

    // range.fx vertexShader, unchanged.
    vertex.xz = dot(coeff, payload.Radius) * vertex.xz + payload.Center;
    return mul(float4(vertex, 1.0), mul(View, Projection));
}

float4 CastRangePS() : SV_Target
{
    return float4(0.0, 0.0, 0.0, 0.0);
}
)hlsl";
} // namespace moho
