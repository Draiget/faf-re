#pragma once

// Engine-owned HLSL for the GPU-driven strategic icons (StrategicIconRenderer).
//
// One instance per icon, 24 vertices per instance: up to four screen quads
// stacked in the order the CPU path draws them (identified underlay, base
// icon, paused overlay, stunned overlay). The vertex shader pulls the icon
// record and the atlas slot of each layer from structured buffers and builds
// the same corners, UVs and colours `CD3DPrimBatcher` builds on the CPU for
// `DrawQuad` (TStrategicIcon). A layer without a texture collapses to a
// zero-area quad. The pixel shader reproduces the TStrategicIcon pass: point
// sample, and replace the texel's colour with the vertex colour where the texel
// is close to mid grey; alpha from the texture; blended src-alpha/inv-src-alpha
// into RGB only, no depth.
//
// Bindings follow gpg/gal/GpuDriven.h (b0, t0..t3 buffers, t4 texture, s0),
// so DXC builds the same source for D3D12 (DXIL) and Vulkan (SPIR-V).

namespace moho
{
  inline constexpr char kStrategicIconShaderSource[] = R"hlsl(
cbuffer StrategicIconConstants : register(b0)
{
    row_major float4x4 Composite; // CD3DPrimBatcher's view * projection
};

struct IconInstance
{
    uint position; // x in the low 16 bits, y in the high 16 bits, signed, whole pixels
    uint color;    // ARGB tint of the base icon
    uint layers01; // atlas slots of the underlay (low) and base icon (high); 0xFFFF = none
    uint layers23; // atlas slots of the paused (low) and stunned (high) overlays
};

struct IconSlot
{
    float4 uv;       // atlas origin (xy) and extent (zw), as CD3DPrimBatcher::SetTexture keeps them
    float2 halfSize; // the texture's width >> 1 and height >> 1
    float2 unused;
};

StructuredBuffer<IconInstance> Instances : register(t0);
StructuredBuffer<IconSlot> Slots : register(t1);
Texture2D Atlas : register(t4);
SamplerState PointSampler : register(s0);

struct IconVertex
{
    float4 position : SV_Position;
    float4 color : COLOR0;
    float2 uv : TEXCOORD0;
};

float4 UnpackArgb(uint argb)
{
    return float4((argb >> 16) & 0xFF, (argb >> 8) & 0xFF, argb & 0xFF, argb >> 24) / 255.0;
}

IconVertex StrategicIconVS(uint vertexId : SV_VertexID, uint instanceId : SV_InstanceID)
{
    // DrawQuad's two triangles: corners 0,1,2 and 2,3,0 (top left, top right,
    // bottom right, bottom left).
    static const uint kCornerOfVertex[6] = { 0, 1, 2, 2, 3, 0 };

    IconInstance icon = Instances[instanceId];
    uint layer = vertexId / 6;
    uint corner = kCornerOfVertex[vertexId % 6];
    uint packed = layer < 2 ? icon.layers01 : icon.layers23;
    uint slotIndex = (packed >> ((layer & 1) * 16)) & 0xFFFF;

    IconVertex output;
    if (slotIndex == 0xFFFF)
    {
        output.position = float4(0.0, 0.0, 0.0, 1.0);
        output.color = float4(0.0, 0.0, 0.0, 0.0);
        output.uv = float2(0.0, 0.0);
        return output;
    }

    IconSlot slot = Slots[slotIndex];
    float2 center = float2((int)(icon.position << 16) >> 16, (int)icon.position >> 16);
    float2 unitUv = float2(corner == 1 || corner == 2 ? 1.0 : 0.0, corner >= 2 ? 1.0 : 0.0);
    float2 halfSize = slot.halfSize;
    float2 screen = float2(unitUv.x != 0.0 ? center.x + halfSize.x : center.x - halfSize.x,
                           unitUv.y != 0.0 ? center.y + halfSize.y : center.y - halfSize.y);

    output.position = mul(float4(screen, 0.0, 1.0), Composite);
    // Only the base icon (layer 1) is tinted; the others draw at 0xFFFFFFFF.
    output.color = UnpackArgb(layer == 1 ? icon.color : 0xFFFFFFFF);
    output.uv = slot.uv.xy + slot.uv.zw * unitUv;
    return output;
}

float4 StrategicIconPS(IconVertex input) : SV_Target
{
    float4 color = Atlas.Sample(PointSampler, input.uv);
    float3 d = (color.rgb - float3(0.5, 0.5, 0.5)) * (color.rgb - float3(0.5, 0.5, 0.5));
    if (dot(d, float3(1.0, 1.0, 1.0)) < 0.25)
    {
        color.rgb = input.color.rgb;
    }
    return color;
}
)hlsl";
} // namespace moho
