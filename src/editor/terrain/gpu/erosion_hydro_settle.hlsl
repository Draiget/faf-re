// End of the hydraulic run: the sediment still in suspension settles where it is (conserves mass). T, S and dep are read and written in place, one cell per thread.
#include "common.hlsli"
#include "erosion_hydro_params.hlsli"

CBUFFER(ErodeHydroParams, P, 0)
UAV_BUFFER(float, T, 0)
UAV_BUFFER(float, S, 1)
UAV_BUFFER(float, dep, 2)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    uint i = dtid.y * P.w + dtid.x;
    bool pinned = (P.flags & 8u) != 0u && (x == 0 || z == 0 || x == int(P.w) - 1 || z == int(P.h) - 1);
    if (pinned) return;
    float s = S[i];
    T[i] += s;
    if ((P.flags & 16u) != 0u) dep[i] += s;
    S[i] = 0.0f;
}
