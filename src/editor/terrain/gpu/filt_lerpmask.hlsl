// dst = orig + (filtered - orig) * saturate(mask): the mask blend at the end of ops blur and box (EdFieldCore.cpp OpBlurImpl: Lerp(src, out, Clamp01(mask))).
#include "filt_lerpmask_params.hlsli"

CBUFFER(LerpMaskParams, P, 0)
SRV_BUFFER(float, orig, 0)
SRV_BUFFER(float, filtered, 1)
SRV_BUFFER(float, mask, 2)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    float o = orig[i];
    dst[i] = o + (filtered[i] - o) * saturate(mask[i]);
}
