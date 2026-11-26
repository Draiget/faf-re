#pragma once

// HLSL shared by the water simulation shader (compute), the patched water effect (pixel) and the headless lab
// (tools/watersimlab), so that the lab renders the foam with the very code of the game. Plain HLSL: no effect-file
// syntax, no samplers.
namespace moho::water
{
  // Hash-based value noise: smooth, no texture, no periodicity (a sum of sines shows as regular chevrons).
  constexpr char kWaterNoiseHlsl[] = R"HLSL(
// float-only hash of a lattice point (Dave Hoskins, "hash without sine"): the effect compiler of the shipped water shader has no integer ops
float FafNoiseCorner(float2 i)
{
    float3 p3 = frac(float3(i.x, i.y, i.x) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return frac((p3.x + p3.y) * p3.z);
}

// 0 .. 1, smooth
float FafNoise2(float2 p)
{
    float2 f = floor(p);
    float2 u = p - f;
    u = u * u * (3.0 - 2.0 * u);
    float a = FafNoiseCorner(f);
    float b = FafNoiseCorner(f + float2(1.0, 0.0));
    float c = FafNoiseCorner(f + float2(0.0, 1.0));
    float d = FafNoiseCorner(f + float2(1.0, 1.0));
    return lerp(lerp(a, b, u.x), lerp(c, d, u.x), u.y);
}
)HLSL";

  // Gradient noise (Perlin): -0.5 .. 0.5 around 0.5 after the shift, and unlike the value noise above it has no lattice
  // aligned look: used with a turned domain it is what the foam is made of (value noise ridges run along the lattice
  // and the foam showed them as a grid).
  constexpr char kWaterGradientNoiseHlsl[] = R"HLSL(
float2 FafGradDir(float2 i)
{
    float a = 6.2831853 * FafNoiseCorner(i + float2(5.3, 11.7));
    return float2(cos(a), sin(a));
}

// 0 .. 1 (about 0.1 .. 0.9), smooth, C2
float FafGradNoise(float2 p)
{
    float2 f = floor(p);
    float2 u = p - f;
    float2 q = u * u * u * (u * (u * 6.0 - 15.0) + 10.0);
    float a = dot(FafGradDir(f), u);
    float b = dot(FafGradDir(f + float2(1.0, 0.0)), u - float2(1.0, 0.0));
    float c = dot(FafGradDir(f + float2(0.0, 1.0)), u - float2(0.0, 1.0));
    float d = dot(FafGradDir(f + float2(1.0, 1.0)), u - float2(1.0, 1.0));
    return saturate(0.5 + 1.1 * lerp(lerp(a, b, q.x), lerp(c, d, q.x), q.y));
}

// the domain turned by 33 degrees: the next octave of a sum must not share the axes of the last
float2 FafTurn(float2 p)
{
    return float2(0.8387 * p.x - 0.5446 * p.y, 0.5446 * p.x + 0.8387 * p.y);
}
)HLSL";

  // The foam of the water surface: `foam` is what the simulation holds (0 .. 1.5, filtered), `xz` the world position,
  // `sumA` the alpha of the shipped wave crest texture. Returns how much of the water pixel is foam.
  //
  // Real foam is a network: thin white walls around cells of dark water, the walls thickening with the amount of foam
  // until the cells close up. It is drawn as the distance between the nearest and the second nearest point of a
  // weighted Voronoi pattern (small near a wall). Cells vary in size (a weight per cell), the walls in thickness (a
  // slow noise and a value per cell), the whole pattern is warped by noise several cells wide, and the layers (coarse
  // to fine, each turned and offset) join in as the foam gets denser: a trace of foam is a few coarse walls, a thick
  // wash a fine lace.
  constexpr char kWaterFoamLookHlsl[] = R"HLSL(
float FafFoamHash(float2 c, float s)
{
    return FafNoiseCorner(c + float2(s * 17.31, s * 5.77));
}

// x: the distance between the nearest and the second nearest point (0 on a wall), y: a value of the nearest cell (0 .. 1), z: the distance to the
// nearest point (0 in the middle of a cell: round bubbles)
float3 FafFoamCells(float2 p, float4 rot, float seed)
{
    float2 r = float2(p.x * rot.x - p.y * rot.y + rot.z, p.x * rot.y + p.y * rot.x + rot.w);
    float2 ci = floor(r);
    float d1 = 99.0;
    float d2 = 99.0;
    float id = 0.0;
    [unroll] for (int j = -1; j <= 1; ++j)
    {
        [unroll] for (int i = -1; i <= 1; ++i)
        {
            float2 c = ci + float2((float)i, (float)j);
            float2 pt = c + 0.1 + 0.8 * float2(FafFoamHash(c, seed), FafFoamHash(c, seed + 1.0));
            float wt = 0.7 + 0.6 * FafFoamHash(c, seed + 2.0);
            float q = length(pt - r) / wt;
            if (q < d1)
            {
                d2 = d1;
                d1 = q;
                id = FafFoamHash(c, seed + 3.0);
            }
            else if (q < d2)
            {
                d2 = q;
            }
        }
    }
    return float3(d2 - d1, id, d1);
}

float FafFoamFbm(float2 p, float s)
{
    return 0.5 * FafNoise2(p + float2(s, 0.0)) + 0.25 * FafNoise2(p * 2.03 + float2(5.0, 3.0 + s)) + 0.125 * FafNoise2(p * 4.1 + float2(9.0 + s, 1.0));
}

float FafFoamAmount(float foam, float2 xz, float sumA)
{
    // (the size of a pixel on the water in world units, taken before any branch: the cells of the lattice are never smaller than a few pixels, a finer one
    // than that is only noise on the screen; closer to the water the lattice gets finer, to the limit of the first mockup's sixteenth)
    float pix = max(max(fwidth(xz.x), fwidth(xz.y)), 0.004);
    float f = foam / (1.0 + 0.9 * foam) + (saturate(sumA * 0.5) - 0.5) * 0.15;
    if (f < 0.02)
    {
        return 0.0;
    }
    float2 p = xz * 0.2;
    float patch = FafFoamFbm(xz * 0.05 + float2(3.0, 8.0), 1.0);
    float den = saturate(f * 1.9 * (0.6 + 0.8 * patch));
    float2 warp = float2(FafFoamFbm(p * 0.09 + float2(1.3, 4.1), 11.0), FafFoamFbm(p * 0.09 + float2(8.2, 0.4), 12.0)) - 0.5;
    float2 fine = float2(FafFoamFbm(p * 0.5 + float2(2.2, 9.1), 13.0), FafFoamFbm(p * 0.5 + float2(6.6, 3.3), 14.0)) - 0.5;
    // the cells are a sixteenth of the size they were in the first mockup: the warp is still measured in the old units
    float cell0 = max(0.272, 5.0 * pix);                      // the coarse cells: 0.27 units, or five pixels
    float2 q = (p + warp * 5.0 + fine * 0.6) * (16.0 * 0.272 / cell0);
    float vis1 = saturate((cell0 / 2.35 / pix - 2.5) / 3.0);   // the finer layers join in when their cells are wide enough to be seen
    float vis2 = saturate((cell0 / 5.48 / pix - 2.5) / 3.0);
    float vary = 0.45 + 1.1 * FafFoamFbm(p * 0.3 + float2(7.0, 2.0), 15.0);
    float w = lerp(0.04, 0.85, smoothstep(0.05, 0.75, den)) * vary;
    // the walls are soft (a range of the whole wall width), not a hard line
    float3 a = FafFoamCells(q * 1.15, float4(0.8, 0.6, 13.1, 7.7), 21.0);
    float t0 = 0.55 + 0.9 * a.y;
    float cover = 1.0 - smoothstep(0.0, w * t0, a.x);
    if (den > 0.07 && vis1 > 0.0)
    {
        float3 b = FafFoamCells(q * 2.7, float4(0.6, -0.8, 4.3, 19.9), 31.0);
        float t1 = 0.55 + 0.9 * b.y;
        cover = max(cover, 0.9 * (1.0 - smoothstep(0.0, w * 0.85 * t1, b.x)) * smoothstep(0.07, 0.30, den) * vis1);
    }
    if (den > 0.16 && vis2 > 0.0)
    {
        float3 c = FafFoamCells(q * 6.3, float4(0.99, 0.14, 31.7, 2.3), 41.0);
        float t2 = 0.55 + 0.9 * c.y;
        cover = max(cover, 0.7 * (1.0 - smoothstep(0.0, w * 0.7 * t2, c.x)) * smoothstep(0.16, 0.5, den) * vis2);
    }
    // a veil between the walls: thin foam, not a clear window of water
    cover = max(cover, 0.3 * smoothstep(0.3, 0.9, den) * (0.6 + 0.4 * FafFoamFbm(q * 0.4, 5.0)));
    // round bubbles: cut-outs of the sheet, a few in a cell lattice of their own (only the cells with a high value have one)
    if (den > 0.25)
    {
        float3 h1 = FafFoamCells(q * 0.8 + float2(7.0, 3.0), float4(0.7, 0.7, 5.1, 9.3), 51.0);
        float r1 = 0.14 + 0.22 * h1.y;
        float hole1 = (h1.y > 0.45 ? 1.0 : 0.0) * (1.0 - smoothstep(r1 * 0.55, r1, h1.z));
        float3 h2 = FafFoamCells(q * 2.0 + float2(2.0, 11.0), float4(0.5, 0.86, 17.2, 4.4), 61.0);
        float r2 = 0.12 + 0.18 * h2.y;
        float hole2 = (h2.y > 0.55 ? 1.0 : 0.0) * (1.0 - smoothstep(r2 * 0.55, r2, h2.z));
        cover *= 1.0 - 0.9 * max(hole1, hole2) * smoothstep(0.25, 0.6, den);
    }
    return saturate(cover) * smoothstep(0.03, 0.12, den);
}
)HLSL";
} // namespace moho::water
