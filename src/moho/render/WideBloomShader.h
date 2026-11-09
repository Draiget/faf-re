#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_BloomWide` (WideBloomRenderer): the glow the original bloom pass made (half the head's size, already
// blurred by frame.fx), above a threshold, is halved four times (a 4x4 box from four bilinear taps), then each level
// is added into the
// next larger one through a 3x3 tent, and the largest is added onto the head. The sum of the levels is a glow that
// falls off smoothly over a large part of the screen, around lights, explosions and shields, where the original
// blur reaches a few pixels.

namespace moho
{
  inline constexpr char kWideBloomShaderSource[] = R"hlsl(
cbuffer WideBloomConstants : register(b0)
{
    float4 Source; // 1 / width, 1 / height, width, height of the texture read
    float4 Target; // 1 / width, 1 / height, width, height of the target drawn
    float4 Params; // x: weight of the added glow; y: threshold of the first halving (0 on the others)
};

Texture2D<float4> Glow : register(t4);
SamplerState Linear : register(s0);

float3 Tap(float2 uv)
{
    return Glow.SampleLevel(Linear, uv, 0).rgb;
}

float4 WideVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 DownPS(float4 position : SV_Position) : SV_Target
{
    const float2 uv = position.xy * Target.xy;
    const float2 d = Source.xy;
    float3 sum = (Tap(uv + float2(-d.x, -d.y)) + Tap(uv + float2(d.x, -d.y)) + Tap(uv + float2(-d.x, d.y))
        + Tap(uv + float2(d.x, d.y))) * 0.25;
    if (Params.y > 0.0) {
        // The bloom's glow also holds a faint copy of the whole scene (the map's bloom bias in frame.fx's
        // CopyGlowingPS); only what stands above it, ramped in over one threshold's width, spreads wide. Measured on
        // the weakest channel, so near-white glow (lights, explosion cores, the map border) spreads and strongly
        // coloured glow (green build ghosts and markers) keeps only the original bloom.
        const float whiteness = min(min(sum.r, sum.g), sum.b);
        sum *= saturate((whiteness - Params.y) / Params.y);
    }
    return float4(sum, 1.0);
}

float4 UpPS(float4 position : SV_Position) : SV_Target
{
    const float2 uv = position.xy * Target.xy;
    const float2 d = Source.xy;
    float3 sum = Tap(uv) * 4.0;
    sum += (Tap(uv + float2(-d.x, 0.0)) + Tap(uv + float2(d.x, 0.0)) + Tap(uv + float2(0.0, -d.y)) + Tap(uv + float2(0.0, d.y))) * 2.0;
    sum += Tap(uv + float2(-d.x, -d.y)) + Tap(uv + float2(d.x, -d.y)) + Tap(uv + float2(-d.x, d.y)) + Tap(uv + float2(d.x, d.y));
    return float4(sum / 16.0, Params.x);
}
)hlsl";
} // namespace moho
