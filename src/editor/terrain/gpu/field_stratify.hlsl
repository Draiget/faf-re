// Op stratify (EdFieldFilt.cpp OpStratify): rock layering. The height (plus tilt and optional noise warp) is looked up in a table of layer boundaries (4097 floats `tab`, followed by the 4096
// hardness values), the sample is pushed towards the shelf of its layer: out = h + strength * slopeFade * mask * (shelf - hh). The warp noise is the CPU's Fbm01 (3 octaves, `warpSize` world
// units); oct (t3) holds the affine map of the sample index to its lattice (see gen_noise.hlsli).
#include "filt_common.hlsli"
#include "gen_noise.hlsli"
#include "field_stratify_params.hlsli"

CBUFFER(StratifyParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, mask, 1)
SRV_BUFFER(float, tab, 2)
SRV_BUFFER(float, oct, 3)
UAV_BUFFER(float, dst, 0)

DEFINE_GRADIENT_AT(src)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    uint i = uint(z) * P.w + uint(x);
    float hgt = src[i];
    float hh = hgt + P.tiltX * (P.ox + float(x) * P.cell) + P.tiltZ * (P.oz + float(z) * P.cell);
    if (P.warpOn != 0u)
    {
        int ix;
        int iz;
        float fx;
        float fz;
        LatticePoint(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7], float(x), float(z), ix, iz, fx, fz);
        hh += P.warp * (2.0f * Fbm01(ix, iz, fx, fz, P.seed, 3u, 0.5f) - 1.0f);
    }
    // std::upper_bound over the 4097 boundaries: the first one above hh (13 halvings)
    int lo = 0;
    int hi = 4097;
    UNROLL for (int step = 0; step < 13; ++step)
    {
        if (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (tab[mid] <= hh) lo = mid + 1;
            else hi = mid;
        }
    }
    int layer = max(0, min(4095, lo - 1));
    float b0 = tab[layer];
    float b1 = tab[layer + 1];
    float f = saturate((hh - b0) / max(1e-6f, b1 - b0));
    float c = tab[4097 + layer];
    float shelf = SmoothStep(c - P.wdt, c + P.wdt, f);
    float hs = b0 + (b1 - b0) * shelf;
    float m = P.strength;
    if (P.slopeOn != 0u)
    {
        float gx;
        float gz;
        GradientAt(x, z, gx, gz);
        m *= SmoothStep(P.slopeLo, P.slopeHi, sqrt(gx * gx + gz * gz));
    }
    if (P.hasMask != 0u) m *= saturate(mask[i]);
    dst[i] = hgt + m * (hs - hh);
}
