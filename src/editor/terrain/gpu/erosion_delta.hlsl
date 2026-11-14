// d = t - t0 (the change a run made so far): the input of the creep / delta filter passes.
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
SRV_BUFFER(float, t, 0)
SRV_BUFFER(float, t0, 1)
UAV_BUFFER(float, d, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    d[i] = t[i] - t0[i];
}
