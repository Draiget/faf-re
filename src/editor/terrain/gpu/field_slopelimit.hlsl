// Op slope_limit (EdFieldSc.cpp OpSlopeLimit), the last step: out = src + (r - src) * strength * mask, r = the lower envelope `lo` (cut peaks), the upper envelope (fill valleys; `up` holds the
// lower envelope of the negated field, so it is negated back here) or their blend hi + (lo - hi) * balance.
#include "field_slopelimit_params.hlsli"

CBUFFER(SlopeLimitParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, lo, 1)
SRV_BUFFER(float, up, 2)
SRV_BUFFER(float, mask, 3)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    float c = src[i];
    float r = c;
    if (P.mode == 0u)
    {
        r = lo[i];
    }
    else if (P.mode == 1u)
    {
        r = -up[i];
    }
    else
    {
        float hi = -up[i];
        r = hi + (lo[i] - hi) * P.balance;
    }
    float s = P.strength;
    if (P.hasMask != 0u) s *= saturate(mask[i]);
    dst[i] = c + (r - c) * s;
}
