// dst = x - y, sample by sample (the gradient, top hat and bottom hat of op morph).
#include "field_sub_params.hlsli"

CBUFFER(SubParams, P, 0)
SRV_BUFFER(float, xs, 0)
SRV_BUFFER(float, ys, 1)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    dst[i] = xs[i] - ys[i];
}
