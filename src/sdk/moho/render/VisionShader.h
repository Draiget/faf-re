#pragma once

// Engine-owned HLSL for the GPU-driven fog-of-war circles (`ren_GpuFog`,
// VisionRenderer.cpp).
//
// The CastVision pass of the game's vision effect, as one instanced draw: every
// visible vision circle is one instance of the shared 92-vertex cylinder, read
// from a structured buffer instead of a per-instance vertex stream, so all
// circles go in one draw instead of one draw per 12,288. The cylinder vertices
// come from a structured buffer indexed by SV_VertexID (the draw is indexed by
// the cylinder's own index buffer). Colour writes are off; the program's
// depth/stencil state does the work (z-fail increment on front faces,
// decrement on back faces), exactly as CastVision's.
//
// Bindings follow gpg/gal/GpuDriven.h (b0, t0..t1), so DXC builds the same
// source for D3D12 (DXIL) and Vulkan (SPIR-V).

namespace moho
{
  inline constexpr char kVisionShaderSource[] = R"hlsl(
cbuffer VisionConstants : register(b0)
{
    row_major float4x4 View;       // the camera's view matrix (vision.fx viewMatrix)
    row_major float4x4 Projection; // the camera's projection matrix (vision.fx projMatrix)
};

struct VisionCircle
{
    float2 center; // world x, z
    float radius;
};

StructuredBuffer<float3> CylinderVertices : register(t0);
StructuredBuffer<VisionCircle> Circles : register(t1);

float4 CastVisionVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID) : SV_Position
{
    float3 vertex = CylinderVertices[vertexId];
    VisionCircle circle = Circles[instanceId];
    // visionVertexShader: vertex.xz = radius * vertex.xz + position.xy
    vertex.xz = circle.radius.xx * vertex.xz + circle.center.xy;
    return mul(float4(vertex, 1.0), mul(View, Projection));
}

float4 CastVisionPS() : SV_Target
{
    return float4(0.0, 0.0, 0.0, 0.0);
}
)hlsl";
} // namespace moho
