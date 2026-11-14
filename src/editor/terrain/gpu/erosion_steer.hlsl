// The droplets' steering surface follows the ground between full refreshes (the pit filling itself is a priority flood on the CPU): where the ground went down since the round started, the
// surface goes down with it (a valley dug through a filled basin's rim stays a valley); where the ground came up above the surface, the surface comes up. hs = max(hs + min(now - before, 0), now).
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
SRV_BUFFER(float, before, 0)
SRV_BUFFER(float, now, 1)
UAV_BUFFER(float, hs, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    float c = now[i];
    hs[i] = max(hs[i] + min(c - before[i], 0.0f), c);
}
