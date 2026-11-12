#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_Atmosphere`, Atmosphere.h): height fog lit by the sun, with shafts where hills block it.
//  - `SunHeightCS` bakes, once per map and sun direction, the height above each cell where the sun's light starts:
//    the highest of the ground there and of every point towards the sun less the sun's rise to it. A point in the
//    air below that height is in a hill's shadow, one read and no march per step.
//  - `AtmosphereCS` runs at half resolution: it marches from the camera to the scene's depth (or to the water's
//    surface, or the far reach for the sky) through the layer where the fog is (its density falls off with height
//    above the base), and sums the light the air scatters towards the camera: the sun's (by a Henyey-Greenstein
//    phase, zero in a hill's shadow) and the ambient. It writes {scattered light, opacity} and the distance. The
//    fog comes in past the camera's focus (Range), so the ground being looked at stays clear: it shows in the
//    distance and in the valleys, as aerial perspective does.
//  - `AtmosphereCompositeVS`/`PS` blur those over 4x4 samples, weighted by how close their distance is, and blend
//    them over the colour (alpha blending: colour * (1 - opacity) + scattered light; alpha untouched).
// The opacity is capped (Ambient.w), so the fog never hides units.
//
// The scene depth is the depth target bound when the dispatch runs (`GpuBindings::readBoundDepth`), at t6; on
// Vulkan that is binding 10.

namespace moho
{
  inline constexpr char kAtmosphereShaderSource[] = R"hlsl(
cbuffer AtmosphereConstants : register(b0)
{
    row_major float4x4 InverseViewProjection;
    float4 ViewRect;   // origin and size of the view, in target pixels
    float4 BufferSize; // samples across and down, then their reciprocals
    float4 Eye;        // camera position, then the farthest the march goes (the sky)
    float4 Sun;        // direction towards the sun, then the shafts' strength (0: no sun scattering)
    float4 SunColor;   // the sun's light, then the phase function's g
    float4 Ambient;    // the ambient light, then the most opacity a pixel takes
    float4 Fog;        // density per world unit at the base, base height, height over which it falls to 1/e, top of the layer
    float4 Grid;       // heightfield width and depth, field cells per sun-height cell, the map's height range
    float4 GridSize;   // sun-height cells across and down, water surface height (-1e9: none), steps per pixel
    float4 Range;      // distance from the camera where the fog starts, the distance over which it comes in, unused
};

RWStructuredBuffer<float4> AtmosphereTerms : register(u0); // two per sample: {light, opacity}, {distance, 0, 0, 0}
RWStructuredBuffer<float> SunHeightOut : register(u1);
StructuredBuffer<float4> AtmosphereInput : register(t0);
StructuredBuffer<uint> TerrainHeights : register(t1); // two 16-bit samples per element, row by row
StructuredBuffer<float> SunHeight : register(t2);
#ifdef __spirv__
[[vk::binding(10, 0)]]
#endif
Texture2D<float> SceneDepth : register(t6);

float3 WorldPosition(int2 pixel, float depth)
{
    const float2 local = (float2(pixel) + 0.5 - ViewRect.xy) / ViewRect.zw;
    const float4 world = mul(float4(local.x * 2.0 - 1.0, 1.0 - local.y * 2.0, depth, 1.0), InverseViewProjection);
    return world.xyz / world.w;
}

// The sim's heightfield: one sample per world unit, raw heights in 1/128 units.
float FieldHeight(int2 cell)
{
    cell = clamp(cell, int2(0, 0), int2(Grid.xy) - 1);
    const uint index = (uint)cell.y * (uint)Grid.x + (uint)cell.x;
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

// A point (xz, h) sees the sun when for every t > 0, h + Sun.y * t clears the ground at xz + Sun.xz * t: the
// lowest such h is the highest of (ground there - Sun.y * t). The march stops once the sun has risen past the
// map's whole height range.
[numthreads(8, 8, 1)]
void SunHeightCS(uint3 id : SV_DispatchThreadID)
{
    if (id.x >= (uint)GridSize.x || id.y >= (uint)GridSize.y) {
        return;
    }
    const float2 xz = (float2(id.xy) + 0.5) * Grid.z;
    float top = FieldHeightAt(xz);
    if (Sun.y <= 0.01) {
        top = 1.0e6; // the sun is down: everything is in shadow
    } else if (dot(Sun.xz, Sun.xz) > 1.0e-8) {
        float t = 0.5;
        [loop]
        for (int i = 0; i < 256; ++i) {
            t += 0.5 + t * 0.03;
            const float2 q = xz + Sun.xz * t;
            if (q.x < 0.0 || q.y < 0.0 || q.x > Grid.x - 1.0 || q.y > Grid.y - 1.0 || Sun.y * t > Grid.w) {
                break;
            }
            top = max(top, FieldHeightAt(q) - Sun.y * t);
        }
    }
    SunHeightOut[id.y * (uint)GridSize.x + id.x] = top;
}

float SunHeightAt(float2 xz)
{
    const float2 at = xz / Grid.z - 0.5;
    const float2 base = floor(at);
    const float2 f = at - base;
    const int2 size = int2(GridSize.xy);
    const int2 c0 = clamp(int2(base), int2(0, 0), size - 1);
    const int2 c1 = clamp(int2(base) + 1, int2(0, 0), size - 1);
    return lerp(lerp(SunHeight[c0.y * size.x + c0.x], SunHeight[c0.y * size.x + c1.x], f.x),
                lerp(SunHeight[c1.y * size.x + c0.x], SunHeight[c1.y * size.x + c1.x], f.x), f.y);
}

[numthreads(8, 8, 1)]
void AtmosphereCS(uint3 id : SV_DispatchThreadID)
{
    if (id.x >= (uint)BufferSize.x || id.y >= (uint)BufferSize.y) {
        return;
    }
    const uint index = id.y * (uint)BufferSize.x + id.x;
    const int2 pixel = int2(ViewRect.xy) + int2(id.xy) * 2;
    const float depth = SceneDepth.Load(int3(pixel, 0));

    // Cleared depth is the sky; 0 is what a backend without a readable depth target returns.
    const bool sky = depth <= 0.0 || depth >= 1.0;
    const float3 target = WorldPosition(pixel, sky ? 0.5 : depth);
    const float3 toTarget = target - Eye.xyz;
    const float3 dir = normalize(toTarget);
    float tEnd = sky ? Eye.w : min(length(toTarget), Eye.w);
    if (GridSize.z > -1.0e8 && dir.y < -1.0e-4 && Eye.y > GridSize.z) {
        tEnd = min(tEnd, (GridSize.z - Eye.y) / dir.y); // the water's surface hides what lies under it
    }
    // Only the layer under Fog.w holds fog worth marching.
    float tStart = 0.0;
    if (Eye.y > Fog.w) {
        tStart = (dir.y < -1.0e-4) ? (Fog.w - Eye.y) / dir.y : tEnd;
    } else if (dir.y > 1.0e-4) {
        tEnd = min(tEnd, (Fog.w - Eye.y) / dir.y);
    }
    tStart = max(tStart, Range.x);
    const float distance = sky ? 1.0e9 : length(toTarget);
    if (tStart >= tEnd) {
        AtmosphereTerms[index * 2] = float4(0.0, 0.0, 0.0, 0.0);
        AtmosphereTerms[index * 2 + 1] = float4(distance, 0.0, 0.0, 0.0);
        return;
    }

    // Henyey-Greenstein, scaled so its mean over the sphere is 1: light travels along -Sun and leaves along -dir.
    const float g = SunColor.w;
    const float c = dot(Sun.xyz, dir);
    const float phase = (1.0 - g * g) / pow(max(1.0 + g * g - 2.0 * g * c, 1.0e-4), 1.5);

    // Interleaved gradient noise offsets the steps per sample; the composite blur averages it out.
    const float jitter = frac(52.9829189 * frac(dot(float2(id.xy), float2(0.06711056, 0.00583715))));
    const int steps = (int)GridSize.w;
    const float dt = (tEnd - tStart) / steps;
    float transmittance = 1.0;
    float3 light = 0.0;
    [loop]
    for (int i = 0; i < steps; ++i) {
        const float3 p = Eye.xyz + dir * (tStart + (i + jitter) * dt);
        const float t = tStart + (i + jitter) * dt;
        // Off the map the fog fades out over 20 units, so the dark border stays dark.
        const float inside = min(min(p.x, p.z), min(Grid.x - 1.0 - p.x, Grid.y - 1.0 - p.z));
        const float density = Fog.x * exp(-max(p.y - Fog.y, 0.0) / Fog.z) * saturate((t - Range.x) / Range.y) * saturate(1.0 + inside / 20.0);
        const float lit = (Sun.w > 0.0) ? saturate((p.y - SunHeightAt(p.xz)) * 0.5 + 0.5) : 0.0;
        const float absorbed = 1.0 - exp(-density * dt);
        light += transmittance * absorbed * (Ambient.rgb + SunColor.rgb * (phase * lit * Sun.w));
        transmittance *= 1.0 - absorbed;
    }
    const float opacity = 1.0 - transmittance;
    const float capped = min(opacity, Ambient.w);
    light *= (opacity > 1.0e-5) ? capped / opacity : 0.0;
    AtmosphereTerms[index * 2] = float4(light, capped);
    AtmosphereTerms[index * 2 + 1] = float4(distance, 0.0, 0.0, 0.0);
}

float4 AtmosphereCompositeVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 AtmosphereCompositePS(float4 position : SV_Position) : SV_Target
{
    const int2 size = int2(BufferSize.xy);
    const float2 local = floor(position.xy) - ViewRect.xy;
    const float2 at = local * 0.5;
    const int2 nearest = clamp(int2(at), int2(0, 0), size - 1);
    const float reference = AtmosphereInput[(nearest.y * size.x + nearest.x) * 2 + 1].x;

    float4 total = 0.0;
    float weight = 0.0;
    [unroll]
    for (int y = -1; y <= 2; ++y) {
        [unroll]
        for (int x = -1; x <= 2; ++x) {
            const int2 cell = clamp(int2(floor(at)) + int2(x, y), int2(0, 0), size - 1);
            const uint slot = (cell.y * size.x + cell.x) * 2;
            const float4 term = AtmosphereInput[slot];
            const float far = AtmosphereInput[slot + 1].x;
            const float2 d = at - float2(cell);
            const float near = saturate(1.0 - abs(far - reference) / (min(reference, 1.0e6) * 0.03 + 0.05));
            const float w = exp(-0.5 * dot(d, d)) * near + 1.0e-4;
            total += term * w;
            weight += w;
        }
    }
    const float4 sum = total / weight;
    if (sum.a <= 1.0e-4) {
        discard;
    }
    // Alpha blending gives colour * (1 - a) + rgb * a: the scattered light is rgb * a.
    return float4(saturate(sum.rgb / sum.a), sum.a);
}
)hlsl";
} // namespace moho
