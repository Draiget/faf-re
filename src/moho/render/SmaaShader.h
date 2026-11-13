#pragma once

// Engine addition, not in the shipped binary.
//
// HLSL for `ren_Fxaa 2` (SmaaRenderer): SMAA 1x (Jimenez et al. 2012) in three passes over a copy of the finished world
// image, through the GPU-driven program model of GpuDriven.h (Direct3D 11, 12 and Vulkan): one full-screen triangle
// vertex shader `SmaaVS`, explicit registers (`t4` the source, `t5` the second input, `s0` linear clamp), no constant
// buffer. Texel fetches use `Load` with the pixel position (`SV_Position`) and the size of the source texture, so a
// world view that draws into a part of the head reads and writes the pixels of its own rectangle.
//
// - SmaaEdgePS: luma edge detection with local contrast adaptation (threshold 0.1, factor 2) into (left edge, top edge)
//   of every pixel.
// - SmaaWeightsPS: for every pixel on an edge, a search along the edge (point fetches, up to 16 pixels each way) finds
//   the two ends of the line (an end the search does not reach counts as straight and fades the weight out towards the
//   limit) and the edges that cross it there (up, down, both or none); the coverage the line leaves in the pixel and in
//   its neighbour comes from the crossing pattern and the pixel's place in the line, evaluated in closed form (the area
//   table of the paper is a pre-integrated form of the same trapezoid; here it is computed per pixel, so no lookup
//   texture is needed).
// - SmaaBlendPS: neighbourhood blending: the pixel is blended with the neighbour on the other side of its strongest
//   edge by one bilinear fetch.
// Not in this version: the diagonal pattern search and the corner rounding of the reference implementation, so it is a
// lightweight SMAA. Alpha holds the glow amount the bloom pass reads next, and the blend pass doesn't write it.

namespace moho
{
  inline constexpr char kSmaaShaderSource[] = R"hlsl(
struct SmaaVertex { float4 position : SV_Position; float2 uv : TEXCOORD0; };
SmaaVertex SmaaVS(uint id : SV_VertexID)
{
    SmaaVertex o;
    float2 p = float2((id << 1) & 2, id & 2);
    o.position = float4(p * float2(2, -2) + float2(-1, 1), 0, 1);
    o.uv = p;
    return o;
}
Texture2D<float4> Frame : register(t4);
Texture2D<float4> Aux : register(t5);
SamplerState Linear : register(s0);

#define SMAA_THRESHOLD 0.1
#define SMAA_CONTRAST 2.0
#define SMAA_STEPS 16

int2 SmaaSize()
{
    uint w, h;
    Frame.GetDimensions(w, h);
    return int2(w, h);
}

float SmaaLuma(float3 c) { return dot(c, float3(0.2126, 0.7152, 0.0722)); }

float4 SmaaColour(int2 p, int2 size)
{
    return Frame.Load(int3(clamp(p, int2(0, 0), size - 1), 0));
}

// ---- pass 1: edges --------------------------------------------------------------------------------------------------------------------

float4 SmaaEdgePS(SmaaVertex v) : SV_Target0
{
    int2 size = SmaaSize();
    int2 p = int2(v.position.xy);
    float l = SmaaLuma(SmaaColour(p, size).rgb);
    float lLeft = SmaaLuma(SmaaColour(p + int2(-1, 0), size).rgb);
    float lTop = SmaaLuma(SmaaColour(p + int2(0, -1), size).rgb);
    float2 delta = abs(l - float2(lLeft, lTop));
    float2 edges = step(SMAA_THRESHOLD, delta);
    if (dot(edges, float2(1.0, 1.0)) == 0.0)
        return float4(0, 0, 0, 0);

    float lRight = SmaaLuma(SmaaColour(p + int2(1, 0), size).rgb);
    float lBottom = SmaaLuma(SmaaColour(p + int2(0, 1), size).rgb);
    float lLeftLeft = SmaaLuma(SmaaColour(p + int2(-2, 0), size).rgb);
    float lTopTop = SmaaLuma(SmaaColour(p + int2(0, -2), size).rgb);
    float2 maxDelta = max(delta, abs(l - float2(lRight, lBottom)));
    maxDelta = max(maxDelta, abs(float2(lLeft, lTop) - float2(lLeftLeft, lTopTop)));
    float finalDelta = max(maxDelta.x, maxDelta.y);
    // Local contrast adaptation: an edge counts only when it is at least half the strongest one around it.
    edges *= step(finalDelta, SMAA_CONTRAST * delta);
    return float4(edges, 0, 0);
}

// ---- pass 2: blend weights ------------------------------------------------------------------------------------------------------------

// (left edge, top edge) of a pixel; nothing outside the image.
float2 SmaaEdge(int2 p, int2 size)
{
    if (p.x < 0 || p.y < 0 || p.x >= size.x || p.y >= size.y)
        return float2(0, 0);
    return Frame.Load(int3(p, 0)).rg;
}

// The area on either side of zero of a line that goes from height a to height b across one pixel: (above, below).
float2 SmaaTrapezoid(float a, float b)
{
    if (a * b >= 0.0)
    {
        float m = 0.5 * (a + b);
        return m >= 0.0 ? float2(m, 0.0) : float2(0.0, -m);
    }
    float t = a / (a - b);
    return a > 0.0 ? float2(0.5 * t * a, 0.5 * (1.0 - t) * (-b)) : float2(0.5 * (1.0 - t) * b, 0.5 * t * (-a));
}

// The coverage of the pixel that is `before` pixels from the start of a line `before + after + 1` long, whose ends sit at heights hStart and
// hEnd (+-0.5 where an edge crosses the line there, going up or down; 0 where none or both do): (above the edge, below the edge).
// A line that bends the same way at both ends (the edge of a box, a notch) is blended only when short: the weight fades out between 1 and 9 pixels.
float2 SmaaCoverage(float hStart, float hEnd, float before, float after, bool unknownStart, bool unknownEnd)
{
    // A search that ran out of steps did not find the end of the line: it is unknown, and counts as straight (height 0). The weight tapers
    // to nothing as the known end gets as far away as the search reaches, so the blend does not jump where the search gives up.
    float taper = 1.0;
    if (unknownStart && unknownEnd)
        return float2(0.0, 0.0);
    if (unknownStart)
        taper = 1.0 - smoothstep(0.0, float(SMAA_STEPS), after);
    if (unknownEnd)
        taper = 1.0 - smoothstep(0.0, float(SMAA_STEPS), before);
    float d = before + after + 1.0;
    if (hStart * hEnd > 0.0)
    {
        // Two tents: the end height at each end, falling to zero in the middle of the line, taken at the pixel's centre.
        float mid = 0.5 * d;
        float x = before + 0.5;
        float h = (x < mid) ? hStart * (1.0 - x / mid) : hEnd * ((x - mid) / mid);
        return SmaaTrapezoid(h, h) * (1.0 - smoothstep(1.0, 9.0, d));
    }
    float a = lerp(hStart, hEnd, before / d);
    float b = lerp(hStart, hEnd, (before + 1.0) / d);
    return SmaaTrapezoid(a, b) * taper;
}

float4 SmaaWeightsPS(SmaaVertex v) : SV_Target0
{
    int2 size = SmaaSize();
    int2 p = int2(v.position.xy);
    float2 e = SmaaEdge(p, size);
    float4 weights = float4(0, 0, 0, 0);

    if (e.y > 0.5)
    {
        // The edge on the top of the pixel: walk left and right along it. The crossing edges at an end are the left edges of the pixel
        // above (up) and of the pixel itself (down) at the left end, and the same one pixel further right at the right end.
        int xl = p.x;
        float lu = 0.0, ld = 0.0;
        bool leftEnded = false;
        [loop] for (int i = 0; i < SMAA_STEPS && !leftEnded; i++)
        {
            lu = SmaaEdge(int2(xl, p.y - 1), size).x;
            ld = SmaaEdge(int2(xl, p.y), size).x;
            if (lu + ld > 0.5 || SmaaEdge(int2(xl - 1, p.y), size).y < 0.5)
                leftEnded = true;
            else
                xl--;
        }
        int xr = p.x;
        float ru = 0.0, rd = 0.0;
        bool rightEnded = false;
        [loop] for (int j = 0; j < SMAA_STEPS && !rightEnded; j++)
        {
            ru = SmaaEdge(int2(xr + 1, p.y - 1), size).x;
            rd = SmaaEdge(int2(xr + 1, p.y), size).x;
            if (ru + rd > 0.5 || SmaaEdge(int2(xr + 1, p.y), size).y < 0.5)
                rightEnded = true;
            else
                xr++;
        }
        float2 area = SmaaCoverage(0.5 * (lu - ld), 0.5 * (ru - rd), float(p.x - xl), float(xr - p.x), !leftEnded, !rightEnded);
        // above the edge: the pixel above takes some of this one's colour (y); below: this pixel takes some of the one above (x)
        weights.x = area.y;
        weights.y = area.x;
    }

    if (e.x > 0.5)
    {
        // The edge on the left of the pixel: walk up and down. The crossing edges at an end are the top edges of the pixel to the left (left)
        // and of the pixel itself (right) at the upper end, and the same one pixel further down at the lower end.
        int yt = p.y;
        float tl = 0.0, tr = 0.0;
        bool topEnded = false;
        [loop] for (int i = 0; i < SMAA_STEPS && !topEnded; i++)
        {
            tl = SmaaEdge(int2(p.x - 1, yt), size).y;
            tr = SmaaEdge(int2(p.x, yt), size).y;
            if (tl + tr > 0.5 || SmaaEdge(int2(p.x, yt - 1), size).x < 0.5)
                topEnded = true;
            else
                yt--;
        }
        int yb = p.y;
        float bl = 0.0, br = 0.0;
        bool bottomEnded = false;
        [loop] for (int j = 0; j < SMAA_STEPS && !bottomEnded; j++)
        {
            bl = SmaaEdge(int2(p.x - 1, yb + 1), size).y;
            br = SmaaEdge(int2(p.x, yb + 1), size).y;
            if (bl + br > 0.5 || SmaaEdge(int2(p.x, yb + 1), size).x < 0.5)
                bottomEnded = true;
            else
                yb++;
        }
        float2 area = SmaaCoverage(0.5 * (tr - tl), 0.5 * (br - bl), float(p.y - yt), float(yb - p.y), !topEnded, !bottomEnded);
        // to the right of the edge (x): this pixel takes some of the left one's colour (z); to the left: the left pixel takes some of this one's (w)
        weights.z = area.x;
        weights.w = area.y;
    }
    return weights;
}

// ---- pass 3: neighbourhood blending -----------------------------------------------------------------------------------------------------

float4 SmaaBlendPS(SmaaVertex v) : SV_Target0
{
    int2 size = SmaaSize();
    int2 p = int2(v.position.xy);
    float4 centre = Frame.Load(int3(p, 0));
    float4 own = Aux.Load(int3(p, 0));
    float rightWeight = Aux.Load(int3(min(p + int2(1, 0), size - 1), 0)).w;
    float bottomWeight = Aux.Load(int3(min(p + int2(0, 1), size - 1), 0)).y;
    // right, down, left, up
    float4 a = float4(rightWeight, bottomWeight, own.z, own.x);
    if (dot(a, float4(1, 1, 1, 1)) < 1.0e-5)
        return centre;
    bool horizontal = max(a.x, a.z) > max(a.y, a.w);
    float2 pos = v.position.xy;
    float2 offsetOne = horizontal ? float2(a.x, 0.0) : float2(0.0, a.y);
    float2 offsetTwo = horizontal ? float2(-a.z, 0.0) : float2(0.0, -a.w);
    float2 weight = horizontal ? a.xz : a.yw;
    weight /= weight.x + weight.y;
    float2 rcpSize = 1.0 / float2(size);
    float4 colour = weight.x * Frame.SampleLevel(Linear, (pos + offsetOne) * rcpSize, 0);
    colour += weight.y * Frame.SampleLevel(Linear, (pos + offsetTwo) * rcpSize, 0);
    return float4(colour.rgb, 1.0);
}

)hlsl";
} // namespace moho
