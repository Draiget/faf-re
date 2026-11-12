#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_Taa`, TemporalAA.h): temporal anti-aliasing. The world is drawn with its projection moved by
// a sub-pixel offset that changes every frame (8 steps of a Halton (2, 3) sequence); `TaaCS` rebuilds each pixel's
// world point from the depth and this frame's camera, finds where it was in the last frame's (unshifted) view, reads
// the history there (bilinear), clips it to the colour range of the pixel's 3x3 neighbourhood this frame (mean +-
// 1.25 standard deviations, in YCoCg) so a unit that moved doesn't leave a trail, and blends it in. The result is the
// new history and, through `TaaCompositeVS`/`PS`, the frame. Alpha (the glow amount and the water mask) is left,
// except with `ren_RenderScale` under 1: the world is then drawn into a smaller area and this pass rebuilds the full
// view from it (temporal upscaling), alpha taken from the nearest drawn sample.
//
// The history follows the camera only (no per-unit motion), so it also keeps each pixel's distance along the view
// (clip w). Where the point a pixel shows now was at another distance in the last frame - a unit moved away from it,
// or onto it - the history there belongs to something else and is dropped (`ren_TaaReject`), so units leave no trail.
//
// The copy of the frame is read at t4, the scene depth at t6 (Vulkan binding 10).

namespace moho
{
  inline constexpr char kTemporalAAShaderSource[] = R"hlsl(
cbuffer TaaConstants : register(b0)
{
    row_major float4x4 InverseViewProjection; // this frame's camera (unshifted: a still point maps to a pixel centre)
    row_major float4x4 PrevViewProjection;    // the last frame's camera (unshifted)
    float4 ViewRect;  // origin and size of the view (the output), in target pixels
    float4 Params;    // history weight, 1 when the history is valid, 1 when alpha is written, unused
    float4 LowRect;   // origin and size of the area the world was drawn into (ren_RenderScale; the view at 1)
    float4 Jitter;    // this frame's offset in drawn pixels (x right, y down), 1 to drop history at another distance, unused
    float4 ViewW;     // this frame's view-projection w column (unshifted): a world point's distance along the view
};

RWStructuredBuffer<float4> HistoryOut : register(u0);
RWStructuredBuffer<float> HistoryDistanceOut : register(u1);
StructuredBuffer<float4> HistoryIn : register(t0);
StructuredBuffer<float> HistoryDistanceIn : register(t1);
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

// How far the last frame's distance at `cell` lies outside [`nearest`, `farthest`], relative to it.
float OutsideRange(int2 cell, float nearest, float farthest)
{
    const int2 size = int2(ViewRect.zw);
    cell = clamp(cell, int2(0, 0), size - 1);
    const float stored = HistoryDistanceIn[cell.y * size.x + cell.x];
    return max(max(nearest - stored, stored - farthest), 0.0) / max(stored, 1.0e-3);
}

// Each output pixel takes the drawn sample nearest to it (the drawn area can be smaller than the view: temporal
// upscaling), weighted by how far that sample's unshifted position lies from the pixel's centre, and the history
// reprojected from the last frame, clipped to the colour range of the sample's 3x3 neighbourhood this frame.
[numthreads(8, 8, 1)]
void TaaCS(uint3 id : SV_DispatchThreadID)
{
    const int2 size = int2(ViewRect.zw);
    if (id.x >= (uint)size.x || id.y >= (uint)size.y) {
        return;
    }
    const float2 scale = LowRect.zw / ViewRect.zw; // drawn pixels per output pixel
    const int2 lowSize = int2(LowRect.zw);
    const int2 lowOrigin = int2(LowRect.xy);
    // The output pixel's centre in drawn pixels; the drawn image is shifted by the offset.
    const float2 centre = (float2(id.xy) + 0.5) * scale;
    // At full scale (Params.z 0) the pixel's own sample with full weight: the plain TAA blend.
    const bool upscaling = Params.z > 0.0;
    const int2 nearest = upscaling ? clamp(int2(floor(centre + Jitter.xy)), int2(0, 0), lowSize - 1) : int2(id.xy);
    const float4 drawn = Frame.Load(int3(lowOrigin + nearest, 0));
    const float2 offset = (float2(nearest) + 0.5 - Jitter.xy - centre) / scale; // in output pixels
    const float closeness = upscaling ? exp(-dot(offset, offset) / (2.0 * 0.5 * 0.5)) : 1.0;

    float3 m1 = 0.0;
    float3 m2 = 0.0;
    // The neighbourhood's nearest and farthest point along the last frame's view: an edge pixel, whose sample lands on
    // the unit one frame and on the ground behind it the next, keeps a history at either distance.
    float nearestBefore = 1.0e30;
    float farthestBefore = 0.0;
    [unroll]
    for (int y = -1; y <= 1; ++y) {
        [unroll]
        for (int x = -1; x <= 1; ++x) {
            const int2 neighbour = clamp(nearest + int2(x, y), int2(0, 0), lowSize - 1);
            const float3 s = ToYCoCg(Frame.Load(int3(lowOrigin + neighbour, 0)).rgb);
            m1 += s;
            m2 += s * s;
            const float2 at = (float2(neighbour) + 0.5) / LowRect.zw;
            const float4 around = mul(float4(at.x * 2.0 - 1.0, 1.0 - at.y * 2.0, saturate(SceneDepth.Load(int3(lowOrigin + neighbour, 0))), 1.0), InverseViewProjection);
            const float before = mul(float4(around.xyz / around.w, 1.0), PrevViewProjection).w;
            nearestBefore = min(nearestBefore, before);
            farthestBefore = max(farthestBefore, before);
        }
    }
    const float3 mean = m1 / 9.0;
    const float3 sigma = sqrt(max(m2 / 9.0 - mean * mean, 0.0));
    const float3 boxMin = mean - 1.25 * sigma;
    const float3 boxMax = mean + 1.25 * sigma;

    float3 result = drawn.rgb;
    const float depth = SceneDepth.Load(int3(lowOrigin + nearest, 0));
    // This pixel's point in the world, and its distance along this frame's view (kept for the next frame).
    const float2 local = (float2(id.xy) + 0.5) / ViewRect.zw;
    const float4 world = mul(float4(local.x * 2.0 - 1.0, 1.0 - local.y * 2.0, saturate(depth), 1.0), InverseViewProjection);
    const float3 seen = world.xyz / world.w;
    const float distance = dot(float4(seen, 1.0), ViewW);
    if (Params.y > 0.0 && depth > 0.0) {
        // Where this pixel's point was in the last frame's view.
        const float4 previous = mul(float4(seen, 1.0), PrevViewProjection);
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
                // The history there showed a point at a distance none of the neighbourhood has (a unit that moved
                // away, or one that arrived): none of it. The closest of the four samples decides; 3 % covers the
                // sub-pixel offset and the bilinear step.
                const float mismatch = min(min(OutsideRange(c, nearestBefore, farthestBefore), OutsideRange(c + int2(1, 0), nearestBefore, farthestBefore)),
                                           min(OutsideRange(c + int2(0, 1), nearestBefore, farthestBefore), OutsideRange(c + int2(1, 1), nearestBefore, farthestBefore)));
                const float keep = (Jitter.z > 0.0) ? saturate(1.0 - (mismatch - 0.03) / 0.03) : 1.0;
                const float weight = Params.x * keep;
                const float current = (1.0 - Params.x) * closeness;
                // No history kept and a far sample: the drawn colour as it is.
                result = (weight + current > 1.0e-4) ? (clipped * weight + drawn.rgb * current) / (weight + current) : drawn.rgb;
            }
        }
    }
    HistoryOut[id.y * (uint)size.x + id.x] = float4(result, drawn.a);
    HistoryDistanceOut[id.y * (uint)size.x + id.x] = distance;
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
    // Alpha (the glow amount, the water mask) is the drawn sample's, written only when the world was drawn smaller.
    return HistoryIn[cell.y * size.x + cell.x];
}
)hlsl";
} // namespace moho
