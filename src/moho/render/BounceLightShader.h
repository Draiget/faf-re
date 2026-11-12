#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_RayBounce`, BounceLight.h): one bounce of diffuse light. `BounceCS` runs at half
// resolution: it rebuilds each point and its normal from the depth (as ren_Ao does), traces a few cosine-weighted
// rays over the half-sphere above it into the ray-traced scene, and where one meets the ground or a unit that is on
// the screen and not hidden there, takes the colour drawn there (a copy of the frame so far, lit) as the light that
// surface sends back, weighted by how close it is. `BounceCompositeVS`/`PS` blur the half-resolution terms over 4x4
// samples, weighted by distance, and brighten the colour by them (GpuBlend::Brighten: colour * (1 + light)).
//
// The frame copy is read at t4, the scene depth at t6 (Vulkan binding 10), the ray scene at t0 space1 (Vulkan
// set 2, binding 0), as ren_RayAo's pass does.

namespace moho
{
  inline constexpr char kBounceLightShaderSource[] = R"hlsl(
cbuffer BounceConstants : register(b0)
{
    row_major float4x4 InverseViewProjection;
    row_major float4x4 ViewProjection;
    float4 ViewRect;   // origin and size of the view, in target pixels
    float4 BufferSize; // samples across and down, then their reciprocals
    float4 Eye;        // camera position, then the fade-out distance
    float4 Params;     // ray length, strength, rays per point, lift per unit of camera distance
    float4 Params2;    // how far under the traced ground a drawn point can lie (RayTracedShadows.h [7].y), the water's
                       // surface height (-1e9: no water), unused, unused
};

RWStructuredBuffer<float4> BounceTerms : register(u0);
StructuredBuffer<float4> BounceInput : register(t0);
Texture2D<float4> Frame : register(t4);
#ifdef __spirv__
[[vk::binding(10, 0)]]
#endif
Texture2D<float> SceneDepth : register(t6);
#ifdef __spirv__
[[vk::binding(0, 2)]]
#endif
RaytracingAccelerationStructure RayScene : register(t0, space1);

float3 WorldPosition(int2 pixel, float depth)
{
    const float2 local = (float2(pixel) + 0.5 - ViewRect.xy) / ViewRect.zw;
    const float4 world = mul(float4(local.x * 2.0 - 1.0, 1.0 - local.y * 2.0, depth, 1.0), InverseViewProjection);
    return world.xyz / world.w;
}

float3 WorldPositionAt(int2 pixel)
{
    const int2 low = int2(ViewRect.xy);
    const int2 high = low + int2(ViewRect.zw) - 1;
    pixel = clamp(pixel, low, high);
    return WorldPosition(pixel, SceneDepth.Load(int3(pixel, 0)));
}

float3 Tangent(float3 center, int2 pixel, int2 step)
{
    const float3 forward = WorldPositionAt(pixel + step) - center;
    const float3 backward = center - WorldPositionAt(pixel - step);
    const float ahead = dot(forward, forward);
    const float behind = dot(backward, backward);
    // At the view's edge one neighbour is clamped onto the pixel itself, a zero step: take the other one (a zero
    // tangent made the normal 0/0, NaN, on the view's left column and top row).
    if (behind <= 1.0e-12) {
        return forward;
    }
    if (ahead <= 1.0e-12) {
        return backward;
    }
    return ahead < behind ? forward : backward;
}

// The nearest opaque hit along `direction` (trees count as solid), or -1.
float Hit(float3 origin, float3 direction, float tMin, uint mask)
{
    if (tMin >= Params.x) {
        return -1.0;
    }
    RayDesc ray;
    ray.Origin = origin;
    ray.Direction = direction;
    ray.TMin = tMin;
    ray.TMax = Params.x;
    RayQuery<RAY_FLAG_FORCE_OPAQUE | RAY_FLAG_SKIP_PROCEDURAL_PRIMITIVES> query;
    query.TraceRayInline(RayScene, RAY_FLAG_NONE, mask, ray);
    query.Proceed();
    return (query.CommittedStatus() == COMMITTED_TRIANGLE_HIT) ? query.CommittedRayT() : -1.0;
}

// How far under the traced ground `p` lies, 0 when it doesn't (as ren_RayAo's TracedUnderGround).
float UnderGround(float3 p)
{
    RayDesc ray;
    ray.Origin = p;
    ray.Direction = float3(0, 1, 0);
    ray.TMin = 0;
    ray.TMax = 200;
    RayQuery<RAY_FLAG_ACCEPT_FIRST_HIT_AND_END_SEARCH | RAY_FLAG_SKIP_PROCEDURAL_PRIMITIVES | RAY_FLAG_FORCE_OPAQUE> query;
    query.TraceRayInline(RayScene, RAY_FLAG_NONE, 1, ray);
    query.Proceed();
    return (query.CommittedStatus() == COMMITTED_TRIANGLE_HIT) ? query.CommittedRayT() : 0.0;
}

// The light a hit point sends back: the frame's colour there when it is on the screen and not hidden behind
// something nearer the camera; none otherwise.
float3 Bounced(float3 hit)
{
    const float4 clip = mul(float4(hit, 1.0), ViewProjection);
    if (clip.w <= 0.0) {
        return 0.0;
    }
    const float3 ndc = clip.xyz / clip.w;
    if (any(abs(ndc.xy) > 1.0)) {
        return 0.0;
    }
    // Under the water's surface: the screen shows the water there, not this point (and the copy is taken before
    // the water draws, so it would hand back the seabed's colour).
    if (hit.y < Params2.y) {
        return 0.0;
    }
    const int2 low = int2(ViewRect.xy);
    const int2 high = low + int2(ViewRect.zw) - 1;
    const int2 pixel = clamp(int2(ViewRect.xy + float2(ndc.x * 0.5 + 0.5, 0.5 - ndc.y * 0.5) * ViewRect.zw), low, high);
    const float3 seen = WorldPosition(pixel, SceneDepth.Load(int3(pixel, 0)));
    const float3 toHit = hit - Eye.xyz;
    const float3 toSeen = seen - Eye.xyz;
    // Hidden when the screen shows something clearly nearer the camera at that pixel.
    if (dot(toSeen, toSeen) < dot(toHit, toHit) * 0.9 - 1.0) {
        return 0.0;
    }
    return Frame.Load(int3(pixel, 0)).rgb;
}

[numthreads(8, 8, 1)]
void BounceCS(uint3 id : SV_DispatchThreadID)
{
    if (id.x >= (uint)BufferSize.x || id.y >= (uint)BufferSize.y) {
        return;
    }
    const uint index = id.y * (uint)BufferSize.x + id.x;
    const int2 pixel = int2(ViewRect.xy) + int2(id.xy) * 2;
    const float depth = SceneDepth.Load(int3(pixel, 0));
    if (depth <= 0.0 || depth >= 1.0) {
        BounceTerms[index] = float4(0.0, 0.0, 0.0, 1.0e9);
        return;
    }
    const float3 center = WorldPosition(pixel, depth);
    const float distance = length(center - Eye.xyz);
    if (distance > Eye.w) {
        BounceTerms[index] = float4(0.0, 0.0, 0.0, distance);
        return;
    }
    const float3 across = cross(Tangent(center, pixel, int2(2, 0)), Tangent(center, pixel, int2(0, 2)));
    float3 normal = (dot(across, across) > 1.0e-20) ? normalize(across) : float3(0.0, 1.0, 0.0);
    if (dot(normal, Eye.xyz - center) < 0.0) {
        normal = -normal;
    }
    const float3 helper = (abs(normal.y) < 0.9) ? float3(0, 1, 0) : float3(1, 0, 0);
    const float3 tangent = normalize(cross(helper, normal));
    const float3 bitangent = cross(normal, tangent);
    const float spin = frac(52.9829189 * frac(dot(float2(id.xy), float2(0.06711056, 0.00583715)))) * 6.2831853;
    const float lift = 0.05 + Params.w * distance;
    const float3 origin = center + float3(0, UnderGround(center), 0) + normal * lift;
    const int count = clamp((int)Params.z, 1, 16);
    float3 light = 0.0;
    for (int i = 0; i < count; ++i) {
        const float u = (i + 0.5) / count;
        const float angle = i * 2.39996323 + spin;
        const float r = sqrt(u);
        const float3 direction = normalize(tangent * (r * cos(angle)) + bitangent * (r * sin(angle)) + normal * sqrt(max(1.0 - u, 0.0)));
        // Meshes from the surface; the traced ground only past the depth a drawn point can lie under it.
        float t = Hit(origin, direction, 0.01, 2);
        if (t < 0.0) {
            t = Hit(origin, direction, Params2.x / max(direction.y, 0.2) + 0.05, 1);
        }
        if (t >= 0.0) {
            light += Bounced(origin + direction * t) * (1.0 - t / Params.x);
        }
    }
    const float fade = saturate((Eye.w - distance) / (0.2 * Eye.w));
    BounceTerms[index] = float4(light / count * Params.y * fade, distance);
}

float4 BounceCompositeVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 BounceCompositePS(float4 position : SV_Position) : SV_Target
{
    const int2 size = int2(BufferSize.xy);
    const float2 local = floor(position.xy) - ViewRect.xy;
    const float2 at = local * 0.5;
    const int2 nearest = clamp(int2(at), int2(0, 0), size - 1);
    const float reference = BounceInput[nearest.y * size.x + nearest.x].w;
    float3 total = 0.0;
    float weight = 0.0;
    [unroll]
    for (int y = -1; y <= 2; ++y) {
        [unroll]
        for (int x = -1; x <= 2; ++x) {
            const int2 cell = clamp(int2(floor(at)) + int2(x, y), int2(0, 0), size - 1);
            const float4 term = BounceInput[cell.y * size.x + cell.x];
            const float2 d = at - float2(cell);
            const float near = saturate(1.0 - abs(term.w - reference) / (min(reference, 1.0e6) * 0.03 + 0.05));
            const float w = exp(-0.5 * dot(d, d)) * near + 1.0e-4;
            total += term.rgb * w;
            weight += w;
        }
    }
    // Brighten blending: colour * light + colour.
    return float4(total / weight, 1.0);
}
)hlsl";
} // namespace moho
