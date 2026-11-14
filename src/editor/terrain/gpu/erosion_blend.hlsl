// out = t + k * (smoothed change - change), the end of the creep and cell noise filter passes: k = amount, times the per cell factor when there is one (rock for the creep, nothing for the filter);
// `blendNext` blends the next smoothing pass in (a fractional number of creep passes); edgeKeep leaves the outer ring with its own change.
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
SRV_BUFFER(float, t, 0)
SRV_BUFFER(float, d, 1)
SRV_BUFFER(float, sm, 2)
SRV_BUFFER(float, sm2, 3)
SRV_BUFFER(float, mask, 4)
UAV_BUFFER(float, outT, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    uint i = dtid.y * P.w + dtid.x;
    float k = P.amount;
    if (P.hasMask != 0u) k *= saturate(mask[i]);
    if (P.edgeKeep != 0u && (x == 0 || z == 0 || x == int(P.w) - 1 || z == int(P.h) - 1)) k = 0.0f;
    float s = sm[i];
    if (P.blendNext > 0.0f) s += P.blendNext * (sm2[i] - s);
    outT[i] = t[i] + k * (s - d[i]);
}
