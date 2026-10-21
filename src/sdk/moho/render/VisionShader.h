#pragma once

// Engine-owned HLSL for the GPU-driven fog-of-war circles (`ren_GpuFog`,
// VisionRenderer.cpp).
//
// The CastVision pass of the game's vision effect, as one instanced draw: every
// emitter VisionDB::CollectEmitters reports is one instance of the shared
// 92-vertex cylinder, read from a structured buffer that changes only when the
// vision tree does. The vertex shader does what VisionDB::TryAdd did on the CPU
// every frame: it interpolates the emitter's circle by the frame's interpolant
// and drops the instance (a zero-area cylinder) when the circle misses the
// camera's terrain footprint box. Stencil increments and decrements commute, so
// the instance order does not matter. The cylinder vertices
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
    float2 BoxCenter;              // the terrain footprint box (axis-aligned, x and z)
    float2 BoxExtent;
    float Interpolant;             // the frame's sub-tick fraction
    float3 Unused;
};

struct VisionEmitter
{
    float2 previousCenter; // world x, z
    float previousRadius;
    float2 currentCenter;
    float currentRadius;
};

StructuredBuffer<float3> CylinderVertices : register(t0);
StructuredBuffer<VisionEmitter> Emitters : register(t1);

// Wm3::DistVector2Box2f::GetSquared for the unit axes RenderFogOfWar uses, then
// IntrBox2Circle2f::Test (distance <= radius). `precise` keeps every operation
// rounded as the CPU rounds it.
bool CircleMeetsBox(float2 center, float radius)
{
    precise float squaredDistance = 0.0;
    precise float2 delta = center - BoxCenter;
    [unroll] for (int axis = 0; axis < 2; ++axis)
    {
        precise float closest = delta[axis];
        if (closest < -BoxExtent[axis])
        {
            precise float d = closest + BoxExtent[axis];
            squaredDistance += d * d;
        }
        else if (closest > BoxExtent[axis])
        {
            precise float d = closest - BoxExtent[axis];
            squaredDistance += d * d;
        }
    }
    return sqrt(squaredDistance) <= radius;
}

float4 CastVisionVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID) : SV_Position
{
    VisionEmitter emitter = Emitters[instanceId];
    // InterpolateCircle: from + (to - from) * t, componentwise.
    precise float2 center = emitter.previousCenter + (emitter.currentCenter - emitter.previousCenter) * Interpolant;
    precise float radius = (emitter.currentRadius - emitter.previousRadius) * Interpolant + emitter.previousRadius;
    if (!CircleMeetsBox(center, radius))
    {
        return float4(0.0, 0.0, 0.0, 1.0);
    }
    float3 vertex = CylinderVertices[vertexId];
    // visionVertexShader: vertex.xz = radius * vertex.xz + position.xy
    vertex.xz = radius.xx * vertex.xz + center.xy;
    return mul(float4(vertex, 1.0), mul(View, Projection));
}

float4 CastVisionPS() : SV_Target
{
    return float4(0.0, 0.0, 0.0, 0.0);
}
)hlsl";
} // namespace moho
