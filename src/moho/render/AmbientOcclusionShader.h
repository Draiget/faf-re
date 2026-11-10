#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_Ao` (AmbientOcclusionRenderer), with contact shadows and terrain shadows
// from the heightfield (`TerrainShadowCS` bakes them once per map): screen-space ambient occlusion
// from the depth of terrain and opaque meshes. Each sample counts by how steeply
// it rises above the surface (the cosine to the normal) less an allowance.
// `AoCS` runs at half resolution and writes one {occlusion, distance} pair per
// sample into a buffer; `AoCompositeVS`/`AoCompositePS` draw one triangle over
// the view that blurs those pairs, weighting neighbours by how close their
// distance is, and multiplies the result into the colour (alpha holds the glow
// amount and the water mask, so the program doesn't write it).
//
// Positions are rebuilt in world space from the camera's inverse view-projection.
// The scene depth is the depth target bound when the dispatch runs
// (`GpuBindings::readBoundDepth`), at t6; on Vulkan that is binding 10.

namespace moho
{
  inline constexpr char kAmbientOcclusionShaderSource[] = R"hlsl(
cbuffer AoConstants : register(b0)
{
    row_major float4x4 InverseViewProjection;
    float4 ViewRect;   // origin and size of the view, in target pixels
    float4 BufferSize; // samples across and down, then their reciprocals
    float4 Eye;        // camera position (w unused)
    float Radius;      // world units
    float Intensity;
    float ProjScale;   // samples per world unit at distance 1
    float Bias;        // cosine a neighbour must rise above the surface before it occludes
    float FadeStart;   // camera distance where occlusion starts to fade
    float FadeEnd;     // and where it is gone
    float2 Unused;
    row_major float4x4 ViewProjection;
    float4 Sun;        // direction towards the sun, then the contact shadow strength (0: off)
    float4 Contact;    // contact ray length and the thickness that counts as a blocker, world units
    float4 TerrainGrid;   // heightfield width and depth, field cells per terrain-shadow cell, strength (0: off)
    float4 TerrainShadowSize; // terrain-shadow cells across and down, shadow map reach (0: none), unused
    row_major float4x4 ShadowMatrix; // world to the sun's clip space, terrain.fx's ShadowMatrix
    float4 ShadowParams;  // 1 when ShadowMap holds this frame's sun shadow (contact shadows only where it is sunlit), then unused
    float4 ShadowCascades[9]; // the effects' faf_ShadowCascades (ren_ShadowCascades, gpg/gal/effects/ShadowCascades.h)
    float4 RayParams;     // 1 when occlusion is traced (ren_RayAo), rays per point, ray lift per unit of camera distance,
                          // how far under the traced ground a drawn ground point can lie (RayTracedShadows.h [7].y)
};

#define CONTACT_STEPS 8

#define AO_SAMPLES 12
#define AO_TURNS 7.0

RWStructuredBuffer<float2> AoTerms : register(u0);
RWStructuredBuffer<float> TerrainShadowOut : register(u1);
StructuredBuffer<float2> AoInput : register(t0);
StructuredBuffer<uint> TerrainHeights : register(t1); // two 16-bit samples per element, row by row
StructuredBuffer<float> TerrainShadow : register(t2);
#ifdef __spirv__
[[vk::binding(10, 0)]]
#endif
Texture2D<float> SceneDepth : register(t6);
// The sun's shadow texture the terrain samples: green is 1 in sunlight, 0 in shadow (terrain.fx).
Texture2D<float4> ShadowMap : register(t4);

#ifdef FAF_RAY_QUERY
// Engine addition (ren_RayAo): the device's ray-traced scene (gpg/gal/RayTracing.h, moho/render/RayScene.h).
#ifdef __spirv__
[[vk::binding(0, 2)]]
#endif
RaytracingAccelerationStructure RayScene : register(t0, space1);
// Alpha-tested pieces (trees): as ModernHlsl.cpp's faf_ray_solid.
#ifdef __spirv__
[[vk::binding(1, 2)]]
#endif
ByteAddressBuffer RayAttributes : register(t1, space1);
#ifdef __spirv__
[[vk::binding(2, 2)]]
#endif
StructuredBuffer<uint4> RayRecords : register(t2, space1);
#ifdef __spirv__
[[vk::binding(3, 2)]]
#endif
Texture2D RayTextures[64] : register(t0, space2);
#ifdef __spirv__
[[vk::binding(4, 2)]]
#endif
SamplerState RaySampler : register(s0, space1);
bool TracedSolid(uint instance, uint primitive, float2 bary)
{
    const uint4 record = RayRecords[instance];
    if (record.w == 0) {
        return true;
    }
    const uint3 corner = RayAttributes.Load3(record.x + primitive * 12);
    const float2 uv0 = asfloat(RayAttributes.Load2(record.y + corner.x * 8));
    const float2 uv1 = asfloat(RayAttributes.Load2(record.y + corner.y * 8));
    const float2 uv2 = asfloat(RayAttributes.Load2(record.y + corner.z * 8));
    const float2 uv = uv0 + bary.x * (uv1 - uv0) + bary.y * (uv2 - uv0);
    return RayTextures[NonUniformResourceIndex(record.z)].SampleLevel(RaySampler, uv, 1).a >= 0.5;
}

// Ambient light that reaches `center` by rays: RayParams.y rays spread over the hemisphere around `normal`
// (cosine-weighted, turned per point by `spin`), each up to Radius long; a hit takes more of the light the
// closer it is. Occluders off the screen and behind others count, which the depth samples miss.
// The nearest hit along `direction` between tMin and Radius among the instances in `mask` (RayTracing.h:
// 1 ground, 2 meshes), or -1.
float TracedHit(float3 origin, float3 direction, float tMin, uint mask)
{
    if (tMin >= Radius) {
        return -1.0;
    }
    RayDesc ray;
    ray.Origin = origin;
    ray.Direction = direction;
    ray.TMin = tMin;
    ray.TMax = Radius;
    RayQuery<RAY_FLAG_SKIP_PROCEDURAL_PRIMITIVES> query;
    query.TraceRayInline(RayScene, RAY_FLAG_NONE, mask, ray);
    while (query.Proceed()) {
        if (query.CandidateType() == CANDIDATE_NON_OPAQUE_TRIANGLE &&
            TracedSolid(query.CandidateInstanceIndex(), query.CandidatePrimitiveIndex(), query.CandidateTriangleBarycentrics())) {
            query.CommitNonOpaqueTriangleHit();
        }
    }
    return (query.CommittedStatus() == COMMITTED_TRIANGLE_HIT) ? query.CommittedRayT() : -1.0;
}

// How far under the traced ground `p` lies, 0 when it doesn't (ModernHlsl.cpp's faf_ray_under_ground): the
// drawn ground is coarser than the traced height field with camera distance, by more than any fixed lift.
float TracedUnderGround(float3 p)
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

// `center` is rebuilt from the depth buffer, whose error grows with camera distance; the rays leave from
// above the surface by more than that error (RayParams.z per unit of distance), or they would start under
// the ground and hit it from below. A point under the traced ground moves up onto it first.
float TracedOcclusion(float3 center, float3 normal, float spin, float distance)
{
    const float3 helper = (abs(normal.y) < 0.9) ? float3(0, 1, 0) : float3(1, 0, 0);
    const float3 tangent = normalize(cross(helper, normal));
    const float3 bitangent = cross(normal, tangent);
    const int count = clamp((int)RayParams.y, 1, 16);
    const float lift = 0.05 + RayParams.z * distance;
    const float3 origin = center + float3(0, TracedUnderGround(center), 0) + normal * lift;
    float blocked = 0.0;
    const float under = RayParams.w;
    for (int i = 0; i < count; ++i) {
        // A spiral over the disc, lifted onto the hemisphere: cosine-weighted directions.
        const float u = (i + 0.5) / count;
        const float angle = i * 2.39996323 + spin;
        const float r = sqrt(u);
        const float3 direction = normalize(tangent * (r * cos(angle)) + bitangent * (r * sin(angle)) + normal * sqrt(max(1.0 - u, 0.0)));
        float t = -1.0;
        if (under > 0.0) {
            // The traced ground can lie above the drawn one here (a coarse field, tessellation): meshes from the
            // surface, the traced ground only past the depth a drawn point can lie under it.
            t = TracedHit(origin, direction, 0.01, 2);
            if (t < 0.0) {
                t = TracedHit(origin, direction, under / max(direction.y, 0.2), 1);
            }
        } else {
            t = TracedHit(origin, direction, 0.01, 0xFF);
        }
        if (t >= 0.0) {
            const float near = 1.0 - t / Radius;
            blocked += 0.35 + 0.65 * near;
        }
    }
    return saturate(1.0 - Intensity * 1.5 * blocked / count);
}
#endif

// How much sun the shadow map gives this point: 1 when there is no shadow map.
float SunVisibility(float3 world)
{
    if (ShadowParams.x <= 0.0) {
        return 1.0;
    }
    // Clip space to texture space as terrain.fx's vertex shaders do it.
    const float4 coord = mul(float4(world, 1.0), ShadowMatrix);
    float2 uv = float2(coord.x + coord.w, coord.w - coord.y) * 0.5 / coord.w;
    if (any(uv < 0.0) || any(uv > 1.0)) {
        return 1.0;
    }
    // The finest cascade tile that holds the point, as the effects' shadow lookups pick it.
    const int count = (int)ShadowCascades[0].x;
    if (count > 0) {
        bool found = false;
        [unroll] for (int k = 0; k < 4; ++k) {
            if (!found && k < count) {
                const float4 box = ShadowCascades[1 + 2 * k];
                if (all(uv >= box.xy) && all(uv <= box.zw)) {
                    const float4 map = ShadowCascades[2 + 2 * k];
                    uv = uv * map.xy + map.zw;
                    found = true;
                }
            }
        }
        if (!found) {
            return 1.0;
        }
    }
    uint width;
    uint height;
    ShadowMap.GetDimensions(width, height);
    return saturate(ShadowMap.Load(int3(int2(uv * float2(width, height)), 0)).g);
}

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

// Of the two neighbours on one axis, the one on the same surface: the smaller step.
float3 Tangent(float3 center, int2 pixel, int2 step)
{
    const float3 forward = WorldPositionAt(pixel + step) - center;
    const float3 backward = center - WorldPositionAt(pixel - step);
    return dot(forward, forward) < dot(backward, backward) ? forward : backward;
}

// The sim's heightfield: one sample per world unit, raw heights in 1/128 units.
float FieldHeight(int2 cell)
{
    cell = clamp(cell, int2(0, 0), int2(TerrainGrid.xy) - 1);
    const uint index = (uint)cell.y * (uint)TerrainGrid.x + (uint)cell.x;
    const uint pair = TerrainHeights[index >> 1];
    return (float)(((index & 1) != 0) ? (pair >> 16) : (pair & 0xFFFF)) * 0.0078125;
}

float FieldHeightAt(float2 xz)
{
    const float2 base = floor(xz);
    const float2 f = xz - base;
    const int2 c = int2(base);
    return lerp(lerp(FieldHeight(c), FieldHeight(c + int2(1, 0)), f.x), lerp(FieldHeight(c + int2(0, 1)), FieldHeight(c + int2(1, 1)), f.x), f.y);
}

// Bakes sun visibility over the heightfield once per map: each cell marches towards the sun in growing
// steps and keeps how far the ray clears the ground, softened with distance into a penumbra.
[numthreads(8, 8, 1)]
void TerrainShadowCS(uint3 id : SV_DispatchThreadID)
{
    if (id.x >= (uint)TerrainShadowSize.x || id.y >= (uint)TerrainShadowSize.y) {
        return;
    }
    const float2 xz = (float2(id.xy) + 0.5) * TerrainGrid.z;
    const float3 start = float3(xz.x, FieldHeightAt(xz) + 0.1, xz.y);
    float visibility = Sun.y > 0.0 ? 1.0 : 0.0;
    float t = 0.5;
    [loop]
    for (int i = 0; i < 160 && visibility > 0.0; ++i) {
        t += 0.5 + t * 0.04;
        const float3 q = start + Sun.xyz * t;
        if (q.x < 0.0 || q.z < 0.0 || q.x > TerrainGrid.x - 1.0 || q.z > TerrainGrid.y - 1.0) {
            break;
        }
        const float clearance = q.y - FieldHeightAt(q.xz);
        visibility = min(visibility, saturate(0.5 + clearance / (0.03 * t + 0.4)));
    }
    TerrainShadowOut[id.y * (uint)TerrainShadowSize.x + id.x] = visibility;
}

// How much of the sun's direct light the heightfield's shadow takes from this point, beyond the reach
// of the shadow map. Lighting falls with the heightfield's own normal, so far terrain stays smooth.
float TerrainShadowFactor(float3 world, float distance)
{
    if (TerrainGrid.w <= 0.0) {
        return 1.0;
    }
    const float reach = TerrainShadowSize.z;
    const float fadeIn = reach > 0.0 ? saturate((distance - reach) / (0.15 * reach + 1.0)) : 1.0;
    if (fadeIn <= 0.0) {
        return 1.0;
    }
    const float2 at = world.xz / TerrainGrid.z - 0.5;
    const float2 base = floor(at);
    const float2 f = at - base;
    const int2 size = int2(TerrainShadowSize.xy);
    const int2 c0 = clamp(int2(base), int2(0, 0), size - 1);
    const int2 c1 = clamp(int2(base) + 1, int2(0, 0), size - 1);
    const float v = lerp(lerp(TerrainShadow[c0.y * size.x + c0.x], TerrainShadow[c0.y * size.x + c1.x], f.x),
                         lerp(TerrainShadow[c1.y * size.x + c0.x], TerrainShadow[c1.y * size.x + c1.x], f.x), f.y);
    const float2 xz = world.xz;
    const float3 normal = normalize(float3(FieldHeightAt(xz - float2(1.0, 0.0)) - FieldHeightAt(xz + float2(1.0, 0.0)), 2.0,
                                           FieldHeightAt(xz - float2(0.0, 1.0)) - FieldHeightAt(xz + float2(0.0, 1.0))));
    const float lit = saturate(dot(normal, Sun.xyz));
    return 1.0 - TerrainGrid.w * (1.0 - v) * lit * fadeIn;
}

[numthreads(8, 8, 1)]
void AoCS(uint3 id : SV_DispatchThreadID)
{
    if (id.x >= (uint)BufferSize.x || id.y >= (uint)BufferSize.y) {
        return;
    }
    const uint index = id.y * (uint)BufferSize.x + id.x;
    const int2 pixel = int2(ViewRect.xy) + int2(id.xy) * 2;
    const float depth = SceneDepth.Load(int3(pixel, 0));
    // Cleared depth is the sky; 0 is what a backend without a readable depth target returns.
    if (depth <= 0.0 || depth >= 1.0) {
        AoTerms[index] = float2(1.0, 1.0e9);
        return;
    }

    const float3 center = WorldPosition(pixel, depth);
    const float distance = length(center - Eye.xyz);
    const float terrain = TerrainShadowFactor(center, distance);
    const float fade = saturate((FadeEnd - distance) / max(FadeEnd - FadeStart, 0.001));
    const float sampleRadius = Radius * ProjScale / max(distance, 0.001);
    if (fade <= 0.0 || sampleRadius < 1.0) {
        AoTerms[index] = float2(terrain, distance);
        return;
    }

    float3 normal = normalize(cross(Tangent(center, pixel, int2(2, 0)), Tangent(center, pixel, int2(0, 2))));
    if (dot(normal, Eye.xyz - center) < 0.0) {
        normal = -normal;
    }

    // Interleaved gradient noise turns the spiral per sample; the composite blur averages it out.
    const float spin = frac(52.9829189 * frac(dot(float2(id.xy), float2(0.06711056, 0.00583715)))) * 6.2831853;
#ifdef FAF_RAY_QUERY
    if (RayParams.x > 0.0) {
        // Traced: the sun's shadows are traced in the lit passes too, so no contact shadow or terrain bake here.
        AoTerms[index] = float2(lerp(1.0, TracedOcclusion(center, normal, spin, distance), fade) * terrain, distance);
        return;
    }
#endif
    const float radius2 = Radius * Radius;
    const int2 low = int2(ViewRect.xy);
    const int2 high = low + int2(ViewRect.zw) - 1;
    float sum = 0.0;
    float taps = 0.0;
    [unroll]
    for (int i = 0; i < AO_SAMPLES; ++i) {
        const float along = (i + 0.5) / AO_SAMPLES;
        const float angle = along * AO_TURNS * 6.2831853 + spin;
        const int2 tap = pixel + int2(round(float2(cos(angle), sin(angle)) * (along * sampleRadius * 2.0)));
        // Off the view there is nothing to read: clamping would make the edge an occluder.
        if (any(tap < low) || any(tap > high)) {
            continue;
        }
        const float3 v = WorldPositionAt(tap) - center;
        const float vv = dot(v, v);
        // How steeply the neighbour rises above the surface, less the allowance that keeps the
        // shallow creases between terrain triangles clean, faded out towards the radius.
        const float rise = dot(v, normal) * rsqrt(vv + 1.0e-6);
        sum += max(rise - Bias, 0.0) * saturate(1.0 - vv / radius2);
        taps += 1.0;
    }
    float occlusion = (taps > 0.0) ? saturate(1.0 - Intensity * 2.0 * sum / (taps * (1.0 - Bias))) : 1.0;

    // Contact shadow: a short ray towards the sun, blocked where the depth in front of it shows a
    // surface closer to the camera within the blocker thickness. It catches the contact the shadow
    // map is too coarse for; surfaces facing away from the sun are the shadow map's alone, and so
    // are points the shadow map already shades: darkening them again turned the ground under trees
    // near-black. Partly lit points (the blurred shadow edge) take the part that is lit.
    const float sunlit = (Sun.w > 0.0) ? SunVisibility(center) : 0.0;
    if (Sun.w > 0.0 && sunlit > 0.0 && dot(normal, Sun.xyz) > 0.05) {
        const float3 start = center + normal * 0.03;
        [unroll]
        for (int s = 1; s <= CONTACT_STEPS; ++s) {
            const float3 q = start + Sun.xyz * (Contact.x * s / CONTACT_STEPS);
            const float4 clip = mul(float4(q, 1.0), ViewProjection);
            const float2 ndc = clip.xy / clip.w;
            const int2 at = int2(ViewRect.xy + float2(ndc.x * 0.5 + 0.5, 0.5 - ndc.y * 0.5) * ViewRect.zw);
            if (any(at < low) || any(at > high)) {
                break;
            }
            const float3 seen = WorldPosition(at, SceneDepth.Load(int3(at, 0)));
            const float gap = length(q - Eye.xyz) - length(seen - Eye.xyz);
            if (gap > 0.02 && gap < Contact.y) {
                occlusion *= 1.0 - Sun.w * sunlit;
                break;
            }
        }
    }
    AoTerms[index] = float2(lerp(1.0, occlusion, fade) * terrain, distance);
}

float4 AoCompositeVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 AoCompositePS(float4 position : SV_Position) : SV_Target
{
    const int2 size = int2(BufferSize.xy);
    const float2 local = floor(position.xy) - ViewRect.xy;
    const float2 at = local * 0.5;
    const int2 nearest = clamp(int2(at), int2(0, 0), size - 1);
    const float reference = AoInput[nearest.y * size.x + nearest.x].y;

    float total = 0.0;
    float weight = 0.0;
    [unroll]
    for (int y = -1; y <= 2; ++y) {
        [unroll]
        for (int x = -1; x <= 2; ++x) {
            const int2 cell = clamp(int2(floor(at)) + int2(x, y), int2(0, 0), size - 1);
            const float2 term = AoInput[cell.y * size.x + cell.x];
            const float2 d = at - float2(cell);
            const float near = saturate(1.0 - abs(term.y - reference) / (reference * 0.03 + 0.05));
            const float w = exp(-0.5 * dot(d, d)) * near + 1.0e-4;
            total += term.x * w;
            weight += w;
        }
    }
    const float occlusion = total / weight;
    return float4(occlusion, occlusion, occlusion, 1.0);
}
)hlsl";
} // namespace moho
