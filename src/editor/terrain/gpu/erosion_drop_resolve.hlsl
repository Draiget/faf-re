// Between droplet rounds: adds the accumulated integer changes to the float fields and clears them. t += dq / scale, wear += wq / scale, dep += pq / scale, flow += fq / flowscale.
#include "common.hlsli"
#include "erosion_thermal_params.hlsli"
#include "erosion_drop_params.hlsli"

CBUFFER(ErodeThermalParams, P, 0)
UAV_BUFFER(float, t, 0)
UAV_BUFFER(int, dq, 1)
UAV_BUFFER(float, wearF, 2)
UAV_BUFFER(int, wq, 3)
UAV_BUFFER(float, depF, 4)
UAV_BUFFER(int, pq, 5)
UAV_BUFFER(float, flowF, 6)
UAV_BUFFER(int, fq, 7)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    t[i] += float(dq[i]) * (1.0f / EROSION_DROP_SCALE);
    dq[i] = 0;
    if ((P.flags & 8u) != 0u)
    {
        wearF[i] += float(wq[i]) * (1.0f / EROSION_DROP_SCALE);
        depF[i] += float(pq[i]) * (1.0f / EROSION_DROP_SCALE);
        flowF[i] += float(fq[i]) * (1.0f / EROSION_FLOW_SCALE);
        wq[i] = 0;
        pq[i] = 0;
        fq[i] = 0;
    }
}
