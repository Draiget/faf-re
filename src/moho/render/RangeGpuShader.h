#pragma once

namespace moho
{
  inline constexpr char kRangeGpuShaderSource[] = R"hlsl(
cbuffer RangeConstants : register(b0)
{
    row_major float4x4 View;
    row_major float4x4 Projection;
};

struct RangeEnvelopeInstance
{
    float Thickness;
    float IsInner;
    float2 Padding;
    float2 Points[48];
};

StructuredBuffer<float> CylinderVertices : register(t0);
StructuredBuffer<RangeEnvelopeInstance> Instances : register(t1);

float4 CastRangeVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID) : SV_Position
{
    RangeEnvelopeInstance inst = Instances[instanceId];
    uint segmentIdx = vertexId % 45;

    uint base = vertexId * 5;
    float3 pos = float3(CylinderVertices[base], CylinderVertices[base + 1], CylinderVertices[base + 2]);
    float lane0 = CylinderVertices[base + 3];
    float lane1 = CylinderVertices[base + 4];

    float2 pt = inst.Points[segmentIdx];
    float2 norm = pos.xz;

    float2 worldXZ;
    if (inst.IsInner > 0.5)
    {
        worldXZ = lane0 * pt + lane1 * (pt + norm * inst.Thickness);
    }
    else
    {
        worldXZ = lane0 * (pt - norm * inst.Thickness) + lane1 * pt;
    }

    float3 worldPos = float3(worldXZ.x, pos.y, worldXZ.y);
    return mul(float4(worldPos, 1.0), mul(View, Projection));
}

float4 CastRangePS() : SV_Target
{
    return float4(0.0, 0.0, 0.0, 0.0);
}
)hlsl";
} // namespace moho
