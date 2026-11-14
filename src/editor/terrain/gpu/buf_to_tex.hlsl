// Copies a field (structured buffer, row major) into an R32_FLOAT texture of the same size: the way a field gets its texture view (hardware bilinear sampling).
#include "field_params.hlsli"

CBUFFER(FieldParams, P, 0)
SRV_BUFFER(float, src, 0)
UAV_TEX(dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    dst[uint2(dtid.x, dtid.y)] = src[dtid.y * P.w + dtid.x];
}
