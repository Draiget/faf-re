#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_Fxaa` (FxaaRenderer): fast approximate anti-aliasing (after
// Lottes' FXAA 3.11, the search of quality preset 29 and its "high quality" edge thresholds, with a third of its
// usual sub-pixel smoothing) over a copy of the finished world image.
// Direct3D 12 and Vulkan have no multisampled back buffer, so this is their
// anti-aliasing. Luma comes from RGB: alpha holds the glow amount the bloom pass
// reads next, and the program doesn't write it.

namespace moho
{
  inline constexpr char kFxaaShaderSource[] = R"hlsl(
cbuffer FxaaConstants : register(b0)
{
    float4 Size; // 1 / width, 1 / height, width, height of the copy
};

Texture2D<float4> Frame : register(t4);
SamplerState Linear : register(s0);

float Luma(float2 uv)
{
    return dot(Frame.SampleLevel(Linear, uv, 0).rgb, float3(0.299, 0.587, 0.114));
}

float4 FxaaVS(uint vertexId : SV_VertexID) : SV_Position
{
    const float2 corner = float2((vertexId << 1) & 2, vertexId & 2);
    return float4(corner * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
}

float4 FxaaPS(float4 position : SV_Position) : SV_Target
{
    const float2 texel = Size.xy;
    float2 uv = position.xy * texel;
    const float3 colour = Frame.SampleLevel(Linear, uv, 0).rgb;
    const float lumaM = dot(colour, float3(0.299, 0.587, 0.114));
    float lumaN = Luma(uv + float2(0.0, -texel.y));
    float lumaS = Luma(uv + float2(0.0, texel.y));
    const float lumaE = Luma(uv + float2(texel.x, 0.0));
    const float lumaW = Luma(uv + float2(-texel.x, 0.0));

    const float lumaMax = max(max(max(lumaN, lumaS), max(lumaE, lumaW)), lumaM);
    const float lumaMin = min(min(min(lumaN, lumaS), min(lumaE, lumaW)), lumaM);
    const float range = lumaMax - lumaMin;
    // FXAA 3.11's "high quality" thresholds: units against similar ground are smoothed too, while faint texture
    // detail (under 1/16 of full range) is left alone.
    if (range < max(0.0625, lumaMax * 0.125)) {
        return float4(colour, 1.0);
    }

    const float lumaNW = Luma(uv + float2(-texel.x, -texel.y));
    const float lumaNE = Luma(uv + float2(texel.x, -texel.y));
    const float lumaSW = Luma(uv + float2(-texel.x, texel.y));
    const float lumaSE = Luma(uv + float2(texel.x, texel.y));

    const float edgeVertical = abs(0.25 * lumaNW - 0.5 * lumaN + 0.25 * lumaNE) + abs(0.5 * lumaW - lumaM + 0.5 * lumaE)
        + abs(0.25 * lumaSW - 0.5 * lumaS + 0.25 * lumaSE);
    const float edgeHorizontal = abs(0.25 * lumaNW - 0.5 * lumaW + 0.25 * lumaSW) + abs(0.5 * lumaN - lumaM + 0.5 * lumaS)
        + abs(0.25 * lumaNE - 0.5 * lumaE + 0.25 * lumaSE);
    const bool horizontal = edgeHorizontal >= edgeVertical;

    // Sub-pixel aliasing: how far the centre stands out from its 3x3 average.
    const float average = (2.0 * (lumaN + lumaS + lumaE + lumaW) + lumaNW + lumaNE + lumaSW + lumaSE) / 12.0;
    const float subpixel = saturate(abs(average - lumaM) / range);
    const float subpixelBlend = (-2.0 * subpixel + 3.0) * subpixel * subpixel;
    // 0.25 of FXAA's sub-pixel smoothing (its sharpest usual setting): at 0.5 the speckle of rock and ground
    // textures softened visibly, which edge smoothing doesn't need.
    const float subpixelOffset = subpixelBlend * subpixelBlend * 0.25;

    if (!horizontal) {
        lumaN = lumaW;
        lumaS = lumaE;
    }
    float stepLength = horizontal ? texel.y : texel.x;
    const float gradientN = abs(lumaN - lumaM);
    const float gradientS = abs(lumaS - lumaM);
    const bool towardsN = gradientN >= gradientS;
    const float gradient = max(gradientN, gradientS);
    if (towardsN) {
        stepLength = -stepLength;
    }
    const float lumaEdge = 0.5 * (lumaM + (towardsN ? lumaN : lumaS));

    float2 edge = uv;
    if (horizontal) {
        edge.y += stepLength * 0.5;
    } else {
        edge.x += stepLength * 0.5;
    }
    const float2 along = horizontal ? float2(texel.x, 0.0) : float2(0.0, texel.y);
    const float threshold = gradient * 0.25;
    const bool centreBelow = lumaM - lumaEdge < 0.0;

    float2 negative = edge - along;
    float2 positive = edge + along;
    float endN = Luma(negative) - lumaEdge;
    float endP = Luma(positive) - lumaEdge;
    bool doneN = abs(endN) >= threshold;
    bool doneP = abs(endP) >= threshold;
    // Preset 29's steps: long, nearly level edges (hulls, buildings, the shore) find their ends and blend in a
    // smooth ramp instead of in short stairs.
    const float steps[11] = { 1.5, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 4.0, 8.0 };
    [unroll]
    for (int i = 0; i < 11; ++i) {
        if (doneN && doneP) {
            break;
        }
        if (!doneN) {
            negative -= along * steps[i];
            endN = Luma(negative) - lumaEdge;
            doneN = abs(endN) >= threshold;
        }
        if (!doneP) {
            positive += along * steps[i];
            endP = Luma(positive) - lumaEdge;
            doneP = abs(endP) >= threshold;
        }
    }

    const float distanceN = horizontal ? uv.x - negative.x : uv.y - negative.y;
    const float distanceP = horizontal ? positive.x - uv.x : positive.y - uv.y;
    const bool nearerN = distanceN < distanceP;
    const float nearest = min(distanceN, distanceP);
    const float span = distanceN + distanceP;
    const bool goodSpan = ((nearerN ? endN : endP) < 0.0) != centreBelow;
    const float edgeOffset = goodSpan ? 0.5 - nearest / span : 0.0;
    const float offset = max(edgeOffset, subpixelOffset);
    if (horizontal) {
        uv.y += offset * stepLength;
    } else {
        uv.x += offset * stepLength;
    }
    return float4(Frame.SampleLevel(Linear, uv, 0).rgb, 1.0);
}
)hlsl";
} // namespace moho
