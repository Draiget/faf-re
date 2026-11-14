// Gradient noise for the generator kernels (gen_*.hlsl). The same noise as the CPU ops (EdFieldCore.cpp / EdFieldUtil.h): the same lattice hash, the same 8 / 64 gradient directions,
// the same quintic fade, so a GPU result matches the CPU result up to float rounding.
//
// POSITIONS. The CPU ops compute the lattice position in double from the world position. A float cannot hold ox + x * cell at 4096 samples without losing the fine octaves, so the host
// (EdGpuGen.cpp) does that part in double and hands the kernel, per octave, an AFFINE MAP from the sample index (x, z) to the lattice: u = u0 + a x + b z, v = v0 + c x + d z, with u0 / v0
// split into an integer part (exact in float below 2^24) and a fraction. LatticePoint() turns that into the integer cell and the fraction inside it: the float error is then relative
// to the size of the field in lattice units, not to the distance from the world origin.
//
// Octave record in the float table `oct` (16 floats per octave, kernels use what they need): 0 iu0, 1 iv0, 2 fu0, 3 fv0, 4 a, 5 b, 6 c, 7 d (the map), 8 amplitude, 9 and up per kernel.
#ifndef GPU_GEN_NOISE_HLSLI
#define GPU_GEN_NOISE_HLSLI

#include "common.hlsli"

// Lattice hash of the cell (ix, iz): bit exact the CPU's Hash2.
FN uint Hash2i(int ix, int iz, uint seed)
{
    return Hash32(uint(ix) * 0x9E3779B1u ^ Hash32(uint(iz) + seed * 0x85EBCA6Bu + 0x165667B1u));
}

// The 64 evenly spread gradient directions of the CPU's Gradients64() (angle (k + 0.5) * pi / 32).
FN float2 Grad64(uint h)
{
    float a = (float(h & 63u) + 0.5f) * 0.09817477042468103f;
    float s = 0.0f;
    float c = 1.0f;
    sincos(a, s, c);
    return float2(c, s);
}

// The classic 8 directions of the CPU's kGrad table: (1,0) (-1,0) (0,1) (0,-1) and the four diagonals.
FN float2 Grad8(uint h)
{
    uint k = h & 7u;
    if (k < 2u) return float2(k == 0u ? 1.0f : -1.0f, 0.0f);
    if (k < 4u) return float2(0.0f, k == 2u ? 1.0f : -1.0f);
    float q = 0.70710678f;
    return float2((k & 1u) == 0u ? q : -q, (k & 2u) == 0u ? q : -q);
}

FN float2 GradOf(uint h, uint fine)
{
    if (fine != 0u) return Grad64(h);
    return Grad8(h);
}

FN float Fade(float t)
{
    return t * t * t * (t * (t * 6.0f - 15.0f) + 10.0f);
}

FN float FadeD(float t)
{
    return 30.0f * t * t * (t - 1.0f) * (t - 1.0f);
}

// Integer cell and fraction of sample (x, z) for the affine map in the octave record.
FN void LatticePoint(float iu0, float iv0, float fu0, float fv0, float a, float b, float c, float d, float x, float z, OUT(int) ix, OUT(int) iz, OUT(float) fx, OUT(float) fz)
{
    float u = fu0 + a * x + b * z;
    float v = fv0 + c * x + d * z;
    float fu = floor(u);
    float fv = floor(v);
    ix = int(iu0) + int(fu);
    iz = int(iv0) + int(fv);
    fx = u - fu;
    fz = v - fv;
}

// Gradient noise about -1..1 with its analytic derivative per lattice unit (EdFieldUtil.h PerlinD). fine: 64 directions, else 8.
FN float PerlinD(int ix, int iz, float fx, float fz, uint seed, uint fine, OUT(float) dnx, OUT(float) dnz)
{
    float u = Fade(fx);
    float v = Fade(fz);
    float du = FadeD(fx);
    float dv = FadeD(fz);
    float2 ga = GradOf(Hash2i(ix, iz, seed), fine);
    float2 gb = GradOf(Hash2i(ix + 1, iz, seed), fine);
    float2 gc = GradOf(Hash2i(ix, iz + 1, seed), fine);
    float2 gd = GradOf(Hash2i(ix + 1, iz + 1, seed), fine);
    float va = ga.x * fx + ga.y * fz;
    float vb = gb.x * (fx - 1.0f) + gb.y * fz;
    float vc = gc.x * fx + gc.y * (fz - 1.0f);
    float vd = gd.x * (fx - 1.0f) + gd.y * (fz - 1.0f);
    float k = va - vb - vc + vd;
    float n = va + u * (vb - va) + v * (vc - va) + u * v * k;
    float s = 1.41421356f;
    dnx = s * (ga.x + u * (gb.x - ga.x) + v * (gc.x - ga.x) + u * v * (ga.x - gb.x - gc.x + gd.x) + du * (vb - va + v * k));
    dnz = s * (ga.y + u * (gb.y - ga.y) + v * (gc.y - ga.y) + u * v * (ga.y - gb.y - gc.y + gd.y) + dv * (vc - va + u * k));
    return n * s;
}

// Value only.
FN float Perlin(int ix, int iz, float fx, float fz, uint seed, uint fine)
{
    float dx = 0.0f;
    float dz = 0.0f;
    return PerlinD(ix, iz, fx, fz, seed, fine, dx, dz);
}

// 2D simplex noise about -1..1 (EdFieldCore.cpp Simplex). (ix, iz, fx, fz) is the position in the SKEWED lattice (the host skews the affine map): ix, iz the simplex cell, fx, fz inside it.
FN float Simplex(int i, int j, float sx, float sz, uint seed, uint fine)
{
    float g2 = 0.21132486540518713f;
    float t = (sx + sz) * g2;
    float x0 = sx - t;
    float y0 = sz - t;
    int i1 = x0 > y0 ? 1 : 0;
    int j1 = x0 > y0 ? 0 : 1;
    float x1 = x0 - float(i1) + g2;
    float y1 = y0 - float(j1) + g2;
    float x2 = x0 - 1.0f + 2.0f * g2;
    float y2 = y0 - 1.0f + 2.0f * g2;
    float n = 0.0f;
    float t0 = 0.5f - x0 * x0 - y0 * y0;
    if (t0 > 0.0f)
    {
        t0 *= t0;
        float2 g = GradOf(Hash2i(i, j, seed), fine);
        n += t0 * t0 * (g.x * x0 + g.y * y0);
    }
    float t1 = 0.5f - x1 * x1 - y1 * y1;
    if (t1 > 0.0f)
    {
        t1 *= t1;
        float2 g = GradOf(Hash2i(i + i1, j + j1, seed), fine);
        n += t1 * t1 * (g.x * x1 + g.y * y1);
    }
    float t2 = 0.5f - x2 * x2 - y2 * y2;
    if (t2 > 0.0f)
    {
        t2 *= t2;
        float2 g = GradOf(Hash2i(i + 1, j + 1, seed), fine);
        n += t2 * t2 * (g.x * x2 + g.y * y2);
    }
    return n * 99.2f;
}

// The CPU's Fbm01 (EdFieldUtil.h): fractal sum of classic 8 direction Perlin, 0..1, octaves doubling in frequency, every octave its own seed. (iu, iv, fu, fv) is the lattice position at octave 0
// (cell + fraction); octave o sees it multiplied by 2^o (exact).
FN float Fbm01(int iu, int iv, float fu, float fv, uint seed, uint octaves, float persistence)
{
    float sum = 0.0f;
    float norm = 0.0f;
    float amp = 1.0f;
    float m = 1.0f;
    int mi = 1;
    LOOP for (uint o = 0u; o < octaves; ++o)
    {
        uint s = Hash32(seed * 131u + o * 7919u + 17u);
        float fU = fu * m;
        float fV = fv * m;
        float fl = floor(fU);
        float fm = floor(fV);
        float n = Perlin(iu * mi + int(fl), iv * mi + int(fm), fU - fl, fV - fm, s, 0u);
        n = max(-1.0f, min(1.0f, n));
        sum += n * amp;
        norm += amp;
        amp *= persistence;
        m *= 2.0f;
        mi *= 2;
    }
    return saturate(0.5f + 0.5f * sum / norm * 1.4f);
}

#endif
