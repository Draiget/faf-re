#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_Sharpen` and `ren_Grade` (PostRenderer), one pass over a copy of the finished world image, after
// FXAA and before the interface:
// - Sharpening: contrast-adaptive sharpening after AMD FidelityFX CAS (MIT licence). Each pixel is pushed away from
//   its four neighbours, less where the 3x3 block already spans most of the range, so edges FXAA softened and
//   texture detail come back without halos on hard outlines.
// - Grading: vibrance (raises the saturation of dull colours and leaves already strong ones, such as team colours,
//   nearly alone) and a gentle S-curve on contrast.
// Alpha holds the glow amount the bloom pass reads next, and the program doesn't write it.

namespace moho
{
  inline constexpr char kPostShaderSource[] = R"hlsl(
cbuffer PostConstants : register(b0)
{
    float4 Size;   // 1 / width, 1 / height, width, height of the copy
    float4 Params; // sharpening 0..1 (negative: off), vibrance, contrast, unused
};

Texture2D<float4> Frame : register(t4);
SamplerState Linear : register(s0);

float3 Tap(float2 uv)
{
    return Frame.SampleLevel(Linear, uv, 0).rgb;
}

float4 PostVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 PostPS(float4 position : SV_Position) : SV_Target
{
    const float2 texel = Size.xy;
    const float2 uv = position.xy * texel;
    float3 colour = Tap(uv);

    if (Params.x >= 0.0) {
        const float3 n = Tap(uv + float2(0.0, -texel.y));
        const float3 s = Tap(uv + float2(0.0, texel.y));
        const float3 e = Tap(uv + float2(texel.x, 0.0));
        const float3 w = Tap(uv + float2(-texel.x, 0.0));
        const float3 nw = Tap(uv + float2(-texel.x, -texel.y));
        const float3 ne = Tap(uv + float2(texel.x, -texel.y));
        const float3 sw = Tap(uv + float2(-texel.x, texel.y));
        const float3 se = Tap(uv + float2(texel.x, texel.y));

        // CAS: the cross and the whole block's minimum and maximum, added, so the amount is softer than the cross
        // alone would give.
        float3 low = min(min(min(n, s), min(e, w)), colour);
        float3 high = max(max(max(n, s), max(e, w)), colour);
        low += min(low, min(min(nw, ne), min(sw, se)));
        high += max(high, max(max(nw, ne), max(sw, se)));
        const float3 amount = sqrt(saturate(min(low, 2.0 - high) / max(high, 1.0e-5)));
        const float peak = -1.0 / lerp(8.0, 5.0, saturate(Params.x));
        const float3 weight = amount * peak;
        colour = saturate(((n + s + e + w) * weight + colour) / (1.0 + 4.0 * weight));
    }

    if (Params.y != 0.0 || Params.z != 0.0) {
        const float luma = dot(colour, float3(0.299, 0.587, 0.114));
        const float saturation = max(max(colour.r, colour.g), colour.b) - min(min(colour.r, colour.g), colour.b);
        colour = saturate(lerp(luma.xxx, colour, 1.0 + Params.y * (1.0 - saturation)));
        colour = lerp(colour, colour * colour * (3.0 - 2.0 * colour), Params.z);
    }
    return float4(colour, 1.0);
}
)hlsl";
} // namespace moho
