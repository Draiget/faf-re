// Op rockiness (EdFieldFilt.cpp OpRockiness): where bare rock shows. A weighted sum of three terms, divided by the sum of the weights, plus a little breakup noise, clamped to 0..1:
//   steep ground (smoothstep of the slope in degrees), convex ground (the laplacian over +-n samples, smoothstep of 0.5 - gain * lap) and thin soil (1 - smoothstep(0, soilFull, soil)).
// The noise is the CPU's Fbm01 at 14 world units, 3 octaves; oct (t2) holds the affine map of the sample index to its lattice (see gen_noise.hlsli).
#include "filt_common.hlsli"
#include "gen_noise.hlsli"
#include "field_rockiness_params.hlsli"

CBUFFER(RockinessParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, soil, 1)
SRV_BUFFER(float, oct, 2)
UAV_BUFFER(float, dst, 0)

DEFINE_GRADIENT_AT(src)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    int w = int(P.w);
    int h = int(P.h);
    int n = int(P.n);
    uint i = uint(z) * P.w + uint(x);
    float gx;
    float gz;
    GradientAt(x, z, gx, gz);
    float deg = atan(sqrt(gx * gx + gz * gz)) * P.degK;
    float c = src[i];
    float lap = (src[uint(z) * P.w + uint(max(0, x - n))] + src[uint(z) * P.w + uint(min(w - 1, x + n))] + src[uint(max(0, z - n)) * P.w + uint(x)] +
                 src[uint(min(h - 1, z + n)) * P.w + uint(x)] - 4.0f * c) / P.d2;
    float convex = saturate(0.5f - P.gain * lap);
    float v = P.wSlope * SmoothStep(P.slopeLo, P.slopeHi, deg) + P.wConvex * SmoothStep(0.5f, 1.0f, convex);
    if (P.hasSoil != 0u) v += P.wSoil * (1.0f - SmoothStep(0.0f, P.soilFull, soil[i]));
    v /= P.norm;
    if (P.noiseOn != 0u)
    {
        int ix;
        int iz;
        float fx;
        float fz;
        LatticePoint(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7], float(x), float(z), ix, iz, fx, fz);
        v += P.breakup * (Fbm01(ix, iz, fx, fz, P.seed, 3u, 0.5f) - 0.5f) * 2.0f;
    }
    dst[i] = saturate(v);
}
