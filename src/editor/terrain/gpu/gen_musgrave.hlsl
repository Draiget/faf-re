// Op musgrave (EdFieldGen.cpp OpMusgrave): Musgrave multifractals ridged / hybrid / hetero, 0..1. Octave table as in gen_fbm.hlsl (amplitude in field 8 = lacunarity^(-h * o)).
#include "gen_noise.hlsli"
#include "gen_musgrave_params.hlsli"

CBUFFER(MusgraveParams, P, 0)
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
    float result = 0.0f;
    float weight = 1.0f;
    LOOP for (uint o = 0u; o < P.octaves; ++o)
    {
        uint b = o * 16u;
        int ix = 0;
        int iz = 0;
        float fx = 0.0f;
        float fz = 0.0f;
        LatticePoint(oct[b], oct[b + 1u], oct[b + 2u], oct[b + 3u], oct[b + 4u], oct[b + 5u], oct[b + 6u], oct[b + 7u], x, z, ix, iz, fx, fz);
        float n = Perlin(ix, iz, fx, fz, octSeed[o], P.fine);
        n = max(-1.0f, min(1.0f, n));
        float amp = oct[b + 8u];
        if (P.kind == 0u)
        {
            float sig = P.offset - abs(n);
            sig *= sig;
            sig *= weight;
            weight = saturate(sig * P.gain);
            result += sig * amp;
        }
        else if (P.kind == 1u)
        {
            float sig = (n + P.offset) * amp;
            if (o == 0u)
            {
                result = sig;
                weight = result;
            }
            else
            {
                weight = min(weight, 1.0f);
                result += weight * sig;
                weight *= sig;
            }
        }
        else
        {
            if (o == 0u)
            {
                result = P.offset + n;
            }
            else
            {
                result += (n + P.offset) * amp * result;
            }
        }
    }
    dst[row * P.w + dtid.x] = saturate(result / P.divisor);
}
