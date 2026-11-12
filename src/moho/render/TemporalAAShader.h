#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_Taa`, TemporalAA.h): temporal anti-aliasing. The world is drawn with its projection moved by
// a sub-pixel offset that changes every frame (8 steps of a Halton (2, 3) sequence); `TaaCS` rebuilds each pixel's
// world point from the depth and this frame's camera, finds where it was in the last frame's (unshifted) view, reads
// the history there (bilinear), clips it to the colour range of the pixel's 3x3 neighbourhood this frame (mean +-
// 1.25 standard deviations, in YCoCg) so a unit that moved doesn't leave a trail, and blends it in. The result is the
// new history and, through `TaaCompositeVS`/`PS`, the frame. Alpha (the glow amount and the water mask) is left.
//
// The copy of the frame is read at t4, the scene depth at t6 (Vulkan binding 10).

namespace moho
{
  inline constexpr char kTemporalAAShaderSource[] = R"hlsl(
cbuffer TaaConstants : register(b0)
{
    row_major float4x4 InverseViewProjection; // this frame's camera (unshifted: a still point maps to a pixel centre)
    row_major float4x4 PrevViewProjection;    // the last frame's camera (unshifted)
    float4 ViewRect;  // origin and size of the view, in target pixels
    float4 Params;    // history weight, 1 when the history is valid, unused, unused
};

RWStructuredBuffer<float4> HistoryOut : register(u0);
StructuredBuffer<float4> HistoryIn : register(t0);
Texture2D<float4> Frame : register(t4);
#ifdef __spirv__
[[vk::binding(10, 0)]]
#endif
Texture2D<float> SceneDepth : register(t6);

float3 ToYCoCg(float3 c)
{
    return float3(dot(c, float3(0.25, 0.5, 0.25)), dot(c, float3(0.5, 0.0, -0.5)), dot(c, float3(-0.25, 0.5, -0.25)));
}

float3 FromYCoCg(float3 c)
{
    return float3(c.x + c.y - c.z, c.x + c.z, c.x - c.y - c.z);
}

float3 HistoryAt(int2 cell)
{
    const int2 size = int2(ViewRect.zw);
    cell = clamp(cell, int2(0, 0), size - 1);
    return HistoryIn[cell.y * size.x + cell.x].rgb;
}

[numthreads(8, 8, 1)]
void TaaCS(uint3 id : SV_DispatchThreadID)
{
    const int2 size = int2(ViewRect.zw);
    if (id.x >= (uint)size.x || id.y >= (uint)size.y) {
        return;
    }
    const int2 low = int2(ViewRect.xy);
    const int2 high = low + size - 1;
    const int2 pixel = low + int2(id.xy);
    const float3 current = Frame.Load(int3(pixel, 0)).rgb;

    // The neighbourhood's colour range this frame.
    float3 m1 = 0.0;
    float3 m2 = 0.0;
    [unroll]
    for (int y = -1; y <= 1; ++y) {
        [unroll]
        for (int x = -1; x <= 1; ++x) {
            const float3 s = ToYCoCg(Frame.Load(int3(clamp(pixel + int2(x, y), low, high), 0)).rgb);
            m1 += s;
            m2 += s * s;
        }
    }
    const float3 mean = m1 / 9.0;
    const float3 sigma = sqrt(max(m2 / 9.0 - mean * mean, 0.0));
    const float3 boxMin = mean - 1.25 * sigma;
    const float3 boxMax = mean + 1.25 * sigma;

    float3 result = current;
    const float depth = SceneDepth.Load(int3(pixel, 0));
    if (Params.y > 0.0 && depth > 0.0) {
        // Where this pixel's point was in the last frame's view.
        const float2 local = (float2(pixel) + 0.5 - ViewRect.xy) / ViewRect.zw;
        const float4 world = mul(float4(local.x * 2.0 - 1.0, 1.0 - local.y * 2.0, min(depth, 1.0), 1.0), InverseViewProjection);
        const float4 previous = mul(float4(world.xyz / world.w, 1.0), PrevViewProjection);
        if (previous.w > 0.0) {
            const float2 ndc = previous.xy / previous.w;
            const float2 at = float2(ndc.x * 0.5 + 0.5, 0.5 - ndc.y * 0.5) * ViewRect.zw - 0.5;
            if (all(at >= -0.5) && all(at <= ViewRect.zw - 0.5)) {
                const float2 base = floor(at);
                const float2 f = at - base;
                const int2 c = int2(base);
                const float3 history = lerp(lerp(HistoryAt(c), HistoryAt(c + int2(1, 0)), f.x),
                                            lerp(HistoryAt(c + int2(0, 1)), HistoryAt(c + int2(1, 1)), f.x), f.y);
                const float3 clipped = FromYCoCg(clamp(ToYCoCg(history), boxMin, boxMax));
                result = lerp(current, clipped, Params.x);
            }
        }
    }
    HistoryOut[id.y * (uint)size.x + id.x] = float4(result, 1.0);
}

float4 TaaCompositeVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 TaaCompositePS(float4 position : SV_Position) : SV_Target
{
    const int2 size = int2(ViewRect.zw);
    const int2 cell = clamp(int2(floor(position.xy) - ViewRect.xy), int2(0, 0), size - 1);
    return float4(HistoryIn[cell.y * size.x + cell.x].rgb, 1.0);
}
)hlsl";
} // namespace moho
