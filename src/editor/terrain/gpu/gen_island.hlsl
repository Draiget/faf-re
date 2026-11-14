// Op island (EdFieldGen.cpp OpIsland): island height / mask / distance from a ragged disc. oct record 0 = map of the Fbm01 noise that makes the coast ragged.
#include "gen_noise.hlsli"
#include "gen_island_params.hlsli"

CBUFFER(IslandParams, P, 0)
SRV_BUFFER(float, oct, 1)
UAV_BUFFER(float, dst, 0)

FN float SmoothStep(float e0, float e1, float v)
{
    if (e1 == e0) return v < e0 ? 0.0f : 1.0f;
    float t = saturate((v - e0) / (e1 - e0));
    return t * t * (3.0f - 2.0f * t);
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    float u = P.u0 + P.ua * x + P.ub * z;
    float v = P.v0 + P.va * x + P.vb * z;
    float q = sqrt(u * u + v * v) / P.radius;
    int ix = 0;
    int iz = 0;
    float fx = 0.0f;
    float fz = 0.0f;
    LatticePoint(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7], x, z, ix, iz, fx, fz);
    float n = Fbm01(ix, iz, fx, fz, P.seed, 5u, 0.5f);
    q += P.rough * (n - 0.5f) * 2.0f * (0.3f + 0.7f * min(1.0f, q));
    float r = 0.0f;
    if (P.outKind == 1u)
    {
        r = 1.0f - SmoothStep(1.0f - P.edge, 1.0f, q);
    }
    else if (P.outKind == 2u)
    {
        r = saturate(1.0f - q);
    }
    else
    {
        float land = 1.0f - SmoothStep(1.0f - P.edge, 1.0f, q);
        r = land * pow(saturate(1.0f - q * 0.9f), P.power);
    }
    dst[row * P.w + dtid.x] = r;
}
