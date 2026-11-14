// Op unsharp (EdFieldFilt.cpp OpUnsharp), the point pass after the blur: out = c + amount * (c - blur) * smoothstep(0, thr, |c - blur|) * mask. The blur itself is the foundation's blur_pass.
#include "filt_common.hlsli"
#include "field_unsharp_params.hlsli"

CBUFFER(UnsharpParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, blurred, 1)
SRV_BUFFER(float, mask, 2)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    float c = src[i];
    float d = c - blurred[i];
    float amt = P.amount;
    if (P.thr > 0.0f) amt *= SmoothStep(0.0f, P.thr, abs(d));
    if (P.hasMask != 0u) amt *= saturate(mask[i]);
    dst[i] = c + amt * d;
}
