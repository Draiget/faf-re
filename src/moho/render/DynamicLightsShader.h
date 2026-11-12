#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_DynamicLights` (DynamicLights.cpp). `LightsCS` runs at half resolution: each sample rebuilds its
// world position from the bound depth (`SceneDepth`, as AmbientOcclusionShader.h does) and its normal from the
// neighbouring depths, sums the lights that reach it (a smooth falloff to the light's radius, softened by the angle
// to the surface) and writes {light, camera distance}. `LightsCompositePS` blurs those samples with a depth-aware
// 4x4 filter and outputs the light, which the composite's blend (GpuBlend::Brighten) turns into colour * (1 + light).

namespace moho
{
  inline constexpr int kDynamicLightSlots = 96;

  inline constexpr char kDynamicLightsShaderSource[] = R"hlsl(
cbuffer LightConstants : register(b0)
{
    row_major float4x4 InverseViewProjection;
    float4 ViewRect;   // origin and size of the view, in target pixels
    float4 BufferSize; // samples across and down, then their reciprocals
    float4 Eye;        // camera position, then the number of lights
    float4 Params;     // the brightest a pixel gets (1 + this), a test light's radius at the view's centre (0: none), unused, unused
    float4 Lights[192]; // per light: position and radius; colour times intensity, unused
};

RWStructuredBuffer<float4> LightTerms : register(u0);
StructuredBuffer<float4> LightInput : register(t0);
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

[numthreads(8, 8, 1)]
void LightsCS(uint3 id : SV_DispatchThreadID)
{
    if (id.x >= (uint)BufferSize.x || id.y >= (uint)BufferSize.y) {
        return;
    }
    const uint index = id.y * (uint)BufferSize.x + id.x;
    const int2 pixel = int2(ViewRect.xy) + int2(id.xy) * 2;
    const float depth = SceneDepth.Load(int3(pixel, 0));
    if (depth <= 0.0 || depth >= 1.0) {
        LightTerms[index] = float4(0.0, 0.0, 0.0, 1.0e9);
        return;
    }
    const float3 center = WorldPosition(pixel, depth);
    const float3 across = cross(Tangent(center, pixel, int2(2, 0)), Tangent(center, pixel, int2(0, 2)));
    float3 normal = (dot(across, across) > 1.0e-20) ? normalize(across) : float3(0.0, 1.0, 0.0);
    if (dot(normal, Eye.xyz - center) < 0.0) {
        normal = -normal;
    }
    float3 sum = 0.0;
    if (Params.y > 0.0) {
        // ren_DynamicLightTest: a white light on whatever the view's centre shows.
        const int2 middle = int2(ViewRect.xy + ViewRect.zw * 0.5);
        const float3 test = WorldPositionAt(middle) + float3(0.0, 2.0, 0.0);
        const float d = length(test - center);
        if (d < Params.y) {
            const float falloff = 1.0 - d / Params.y;
            sum += falloff * falloff;
        }
    }
    const int count = min((int)Eye.w, 96);
    [loop]
    for (int i = 0; i < count; ++i) {
        const float4 light = Lights[i * 2];
        const float3 toLight = light.xyz - center;
        const float d2 = dot(toLight, toLight);
        const float r2 = light.w * light.w;
        if (d2 >= r2) {
            continue;
        }
        const float d = sqrt(d2);
        float falloff = 1.0 - d / light.w;
        falloff *= falloff;
        // Facing the light gets it all, facing away a quarter (the flash fills the air around it).
        const float facing = saturate(dot(normal, toLight / max(d, 0.001))) * 0.75 + 0.25;
        sum += Lights[i * 2 + 1].rgb * falloff * facing;
    }
    LightTerms[index] = float4(sum, length(center - Eye.xyz));
}

float4 LightsCompositeVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 LightsCompositePS(float4 position : SV_Position) : SV_Target
{
    const int2 size = int2(BufferSize.xy);
    const float2 local = floor(position.xy) - ViewRect.xy;
    const float2 at = local * 0.5;
    const int2 nearest = clamp(int2(at), int2(0, 0), size - 1);
    const float reference = LightInput[nearest.y * size.x + nearest.x].w;

    float3 total = 0.0;
    float weight = 0.0;
    [unroll]
    for (int y = -1; y <= 2; ++y) {
        [unroll]
        for (int x = -1; x <= 2; ++x) {
            const int2 cell = clamp(int2(floor(at)) + int2(x, y), int2(0, 0), size - 1);
            const float4 term = LightInput[cell.y * size.x + cell.x];
            const float2 d = at - float2(cell);
            const float near = saturate(1.0 - abs(term.w - reference) / (reference * 0.03 + 0.05));
            const float w = exp(-0.5 * dot(d, d)) * near + 1.0e-4;
            total += term.rgb * w;
            weight += w;
        }
    }
    // The blend makes it colour * light + colour; the target clamps the output to 0..1, so the brightest
    // a pixel gets is twice its colour.
    const float3 light = min(total / weight, Params.x);
    return float4(light, 1.0);
}
)hlsl";
} // namespace moho
