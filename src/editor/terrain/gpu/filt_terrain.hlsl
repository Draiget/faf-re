// Ops slope (modes degrees and gradient), curvature, aspect and hillshade (EdFieldCore.cpp OpSlope / OpCurvature / OpAspect, EdFieldFilt.cpp OpHillshade): stencils over the height field, a few
// operations per sample. The arithmetic is the CPU's, in the same order. They only pay off on big fields (the host op sends small ones to the CPU): see EdGpuGenFilt.cpp.
#include "filt_common.hlsli"
#include "filt_terrain_params.hlsli"

CBUFFER(TerrainParams, P, 0)
SRV_BUFFER(float, src, 1)
UAV_BUFFER(float, dst, 0)

DEFINE_BILINEAR_C(src)
DEFINE_GRADIENT_AT(src)

// Central difference over +-n samples with clamped edges (the slope and aspect ops).
FN void GradientN(int x, int z, OUT(float) gx, OUT(float) gz)
{
    int n = int(P.n);
    int x0 = max(0, x - n);
    int x1 = min(int(P.w) - 1, x + n);
    int z0 = max(0, z - n);
    int z1 = min(int(P.h) - 1, z + n);
    gx = 0.0f;
    gz = 0.0f;
    if (x1 > x0) gx = (src[uint(z) * P.w + uint(x1)] - src[uint(z) * P.w + uint(x0)]) / (float(x1 - x0) * P.cell);
    if (z1 > z0) gz = (src[uint(z1) * P.w + uint(x)] - src[uint(z0) * P.w + uint(x)]) / (float(z1 - z0) * P.cell);
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    uint idx = uint(z) * P.w + uint(x);
    float r = 0.0f;
    if (P.op == 0u)
    {
        float gx = 0.0f;
        float gz = 0.0f;
        GradientN(x, z, gx, gz);
        float g = sqrt(gx * gx + gz * gz);
        r = P.mode == 0u ? atan(g) * P.degK : g;
    }
    else if (P.op == 1u)
    {
        int n = int(P.n);
        float c = src[idx];
        float lap = (src[uint(z) * P.w + uint(max(0, x - n))] + src[uint(z) * P.w + uint(min(int(P.w) - 1, x + n))] + src[uint(max(0, z - n)) * P.w + uint(x)] +
                     src[uint(min(int(P.h) - 1, z + n)) * P.w + uint(x)] - 4.0f * c) / P.d2;
        r = P.mode == 1u ? -lap : saturate(0.5f - P.gain * lap);
    }
    else if (P.op == 2u)
    {
        float gx = 0.0f;
        float gz = 0.0f;
        GradientN(x, z, gx, gz);
        float g = sqrt(gx * gx + gz * gz);
        if (P.mode == 1u)
        {
            r = 0.0f;
            if (g > 0.000000001f)
            {
                r = atan2(-gz, -gx) * P.degK;
                if (r < 0.0f) r += 360.0f;
            }
        }
        else
        {
            r = 0.5f;
            if (g > 0.000000001f)
            {
                float c = (-gx * P.dirx - gz * P.dirz) / g;
                r = 0.5f + 0.5f * c * min(1.0f, g / P.flatK);
            }
        }
    }
    else
    {
        float gx = 0.0f;
        float gz = 0.0f;
        GradientAt(x, z, gx, gz);
        gx *= P.zf;
        gz *= P.zf;
        float inv = 1.0f / sqrt(gx * gx + gz * gz + 1.0f);
        float ndl = (-gx * P.lx + P.ly - gz * P.lz) * inv;
        float lighted = ndl > 0.0f ? 1.0f : 0.0f;
        if (P.shadows != 0u)
        {
            float h0 = src[idx];
            float t = 1.0f;
            float shade = 1.0f;
            LOOP while (t < P.len)
            {
                float hs = BilinearC(float(x) + P.dirx * t, float(z) + P.dirz * t);
                float ray = h0 + t * P.cell * P.tanAlt;
                if (hs > ray + 0.01f)
                {
                    shade = 0.0f;
                    break;
                }
                t += 1.0f + t * 0.12f;
            }
            lighted *= shade;
            if (P.mode == 2u) r = 1.0f - shade;
            else if (P.mode == 1u) r = lighted * SmoothStep(0.0f, 0.25f, ndl);
            else r = saturate(P.ambient + (1.0f - P.ambient) * max(0.0f, ndl) * shade);
        }
        else
        {
            r = saturate(P.ambient + (1.0f - P.ambient) * max(0.0f, ndl));
        }
    }
    dst[idx] = r;
}
