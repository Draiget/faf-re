// Thermal slides, pass A (the CPU ThermalImpl of EdErosion.cpp, first loop): for every cell that stands more than the talus above some of its eight neighbours, the share of the excess it gives
// away (rate * 0.5 * largest excess / sum of the excesses, spread over the lower neighbours in proportion to their excess) and the amount it moves in total. Pass B collects.
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"
#include "erosion_common.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
SRV_BUFFER(float, t, 0)
SRV_BUFFER(float, mask, 1)
UAV_BUFFER(float, share, 0)
UAV_BUFFER(float, moved, 1)

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
    share[i] = 0.0f;
    moved[i] = 0.0f;
    if (x < loX || z < loZ || x >= w - hiX || z >= h - hiZ) return;
    float c = t[i];
    float maxEx = 0.0f;
    float sumEx = 0.0f;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kDirX[k];
        int nz = z + kDirZ[k];
        if (nx >= loX && nz >= loZ && nx < w - hiX && nz < h - hiZ)
        {
            float thr = P.tAxis;
            if (k >= 4) thr = P.tDiag;
            float ex = (c - t[uint(nz) * P.w + uint(nx)]) - thr;
            if (ex > 0.0f)
            {
                sumEx += ex;
                maxEx = max(maxEx, ex);
            }
        }
    }
    if (sumEx > 0.0f)
    {
        float r = P.rate;
        if (P.hasMask != 0u) r *= saturate(mask[i]);
        float s = r * 0.5f * maxEx / sumEx;
        share[i] = s;
        moved[i] = s * sumEx;
    }
}
