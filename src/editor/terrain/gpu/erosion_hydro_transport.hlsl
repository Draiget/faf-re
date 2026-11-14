// Hydraulic erosion, pass C: the suspended sediment travels with the water through the same eight pipes (upwind and conservative: what leaves a cell arrives in its neighbours, or leaves the map
// over an open edge), then the water evaporates. s' = sn * (1 - out / dOld) + sum over the neighbours of sn_j * flux(j -> i) / dOld_j.
#include "common.hlsli"
#include "erosion_hydro_params.hlsli"
#include "erosion_common.hlsli"

CBUFFER(ErodeHydroParams, P, 0)
SRV_BUFFER(float, Fa, 0)
SRV_BUFFER(float, Fb, 1)
SRV_BUFFER(float, SN, 2)
SRV_BUFFER(float, DO, 3)
UAV_BUFFER(float, S, 0)
UAV_BUFFER(float, D, 1)

FN float FluxOf(uint cellIndex, uint n, int k)
{
    if (k < 4) return Fa[uint(k) * n + cellIndex];
    return Fb[uint(k - 4) * n + cellIndex];
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint n = P.w * P.h;
    uint i = dtid.y * P.w + dtid.x;
    bool pinned = (P.flags & 8u) != 0u && (x == 0 || z == 0 || x == w - 1 || z == h - 1);
    if (pinned)
    {
        S[i] = 0.0f;
        D[i] = 0.0f;
        return;
    }
    float sn = SN[i];
    float v = sn;
    float dOld = DO[i];
    if (dOld > 0.0f)
    {
        float outSum = 0.0f;
        UNROLL for (int k = 0; k < 8; ++k) outSum += FluxOf(i, n, k);
        v -= sn * outSum / dOld;
    }
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kDirX[k];
        int nz = z + kDirZ[k];
        if (nx >= 0 && nz >= 0 && nx < w && nz < h)
        {
            uint j = uint(nz) * P.w + uint(nx);
            float dj = DO[j];
            if (dj > 0.0f) v += SN[j] * FluxOf(j, n, kDirOpp[k]) / dj;
        }
    }
    if (v < 1e-9f) v = 0.0f;
    S[i] = v;
    float dn = D[i] * (1.0f - P.evap);
    if (dn < 1e-9f) dn = 0.0f;
    D[i] = dn;
}
