// Op morph (EdFieldFilt.cpp MorphPass): one grey scale dilation (isMax) or erosion over the window of the structuring element. The square element is two separable passes (shape 0 = along x,
// then shape 1 = along z); disc, diamond and cross read the window directly. A window that leaves the field only reads the samples inside it. Window maximum and minimum are exact, so
// the result is bit equal to the CPU op's.
#include "common.hlsli"
#include "field_morph_params.hlsli"

CBUFFER(MorphParams, P, 0)
SRV_BUFFER(float, src, 0)
UAV_BUFFER(float, dst, 0)

FN float Better(float v, float best)
{
    if (P.isMax != 0u) return v > best ? v : best;
    return v < best ? v : best;
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    int w = int(P.w);
    int h = int(P.h);
    int r = int(P.rad);
    float best = src[uint(z) * P.w + uint(x)];
    if (P.shape == 0u || P.shape == 4u)
    {
        int x0 = max(0, x - r);
        int x1 = min(w - 1, x + r);
        LOOP for (int xx = x0; xx <= x1; ++xx) best = Better(src[uint(z) * P.w + uint(xx)], best);
    }
    if (P.shape == 1u || P.shape == 4u)
    {
        int z0 = max(0, z - r);
        int z1 = min(h - 1, z + r);
        LOOP for (int zz = z0; zz <= z1; ++zz) best = Better(src[uint(zz) * P.w + uint(x)], best);
    }
    if (P.shape == 2u || P.shape == 3u)
    {
        int z0 = max(0, z - r);
        int z1 = min(h - 1, z + r);
        LOOP for (int zz = z0; zz <= z1; ++zz)
        {
            int dz = zz - z;
            // diamond: |dx| <= r - |dz|; disc: dx^2 + dz^2 <= r^2 (the window of the row is symmetric, so the extent is found by the condition)
            int ext = r;
            if (P.shape == 3u) ext = r - abs(dz);
            int x0 = max(0, x - ext);
            int x1 = min(w - 1, x + ext);
            LOOP for (int xx = x0; xx <= x1; ++xx)
            {
                int dx = xx - x;
                if (P.shape == 2u && dx * dx + dz * dz > r * r) continue;
                best = Better(src[uint(zz) * P.w + uint(xx)], best);
            }
        }
    }
    dst[uint(z) * P.w + uint(x)] = best;
}
