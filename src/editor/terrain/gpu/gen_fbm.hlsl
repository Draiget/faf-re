// Ops perlin, simplex, ridged, billow (EdFieldCore.cpp OpNoise / Fbm): fractal sum of gradient noise, 0..1, one thread per sample. The octave table (see gen_noise.hlsli) holds, per octave, the
// affine map from the sample index to the octave's lattice (rotated and shifted when `rotate` is on, skewed for simplex) and the amplitude; the seeds are in a uint table.
#include "gen_noise.hlsli"
#include "gen_fbm_params.hlsli"

CBUFFER(FbmParams, P, 0)
SRV_BUFFER(float, oct, 1)
SRV_BUFFER(uint, octSeed, 2)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    float sum = 0.0f;
    LOOP for (uint o = 0u; o < P.octaves; ++o)
    {
        uint b = o * 16u;
        int ix = 0;
        int iz = 0;
        float fx = 0.0f;
        float fz = 0.0f;
        LatticePoint(oct[b], oct[b + 1u], oct[b + 2u], oct[b + 3u], oct[b + 4u], oct[b + 5u], oct[b + 6u], oct[b + 7u], x, z, ix, iz, fx, fz);
        float s = 0.0f;
        if (P.basis == 0u)
        {
            s = Perlin(ix, iz, fx, fz, octSeed[o], P.fine);
        }
        else
        {
            s = Simplex(ix, iz, fx, fz, octSeed[o], P.fine);
        }
        s = max(-1.0f, min(1.0f, s));
        float u = 0.5f * s + 0.5f;
        if (P.kind == 1u)
        {
            u = 1.0f - abs(s);
            u *= u;
        }
        else if (P.kind == 2u)
        {
            u = abs(s);
        }
        sum += u * oct[b + 8u];
    }
    dst[row * P.w + dtid.x] = saturate(sum / P.norm);
}
