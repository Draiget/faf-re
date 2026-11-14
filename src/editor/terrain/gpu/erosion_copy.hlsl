// copyTo = copyFrom, over a w x h field (2D dispatch: a field can have more samples than 65535 groups of a 1D kernel cover).
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
SRV_BUFFER(float, copyFrom, 0)
UAV_BUFFER(float, copyTo, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    copyTo[i] = copyFrom[i];
}
