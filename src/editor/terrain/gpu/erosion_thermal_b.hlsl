// Thermal slides, pass B: next = ground - what the cell gave away + what its higher neighbours give it (the CPU ThermalImpl, second loop).
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"
#include "erosion_common.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
SRV_BUFFER(float, t, 0)
SRV_BUFFER(float, share, 1)
SRV_BUFFER(float, moved, 2)
UAV_BUFFER(float, next, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint i = dtid.y * P.w + dtid.x;
    int loX = int(P.pinSides & 1u);
    int hiX = int((P.pinSides >> 1) & 1u);
    int loZ = int((P.pinSides >> 2) & 1u);
    int hiZ = int((P.pinSides >> 3) & 1u);
    float c = t[i];
    if (x < loX || z < loZ || x >= w - hiX || z >= h - hiZ)
    {
        next[i] = c;
        return;
    }
    float gained = 0.0f;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kDirX[k];
        int nz = z + kDirZ[k];
        if (nx >= loX && nz >= loZ && nx < w - hiX && nz < h - hiZ)
        {
            uint j = uint(nz) * P.w + uint(nx);
            float thr = P.tAxis;
            if (k >= 4) thr = P.tDiag;
            float ex = (t[j] - c) - thr;
            if (ex > 0.0f) gained += share[j] * ex;
        }
    }
    next[i] = c - moved[i] + gained;
}
