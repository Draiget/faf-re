// Op erode_snow (EdFieldEro2.cpp OpSnow), the snow that falls before it slumps: amount * smoothstep(snowline - band, snowline + band, ground) * (1 - smoothstep(steepLo, steepHi, slope)) * mask.
#include "filt_common.hlsli"
#include "field_snowinit_params.hlsli"

CBUFFER(SnowInitParams, P, 0)
SRV_BUFFER(float, ground, 0)
SRV_BUFFER(float, mask, 1)
UAV_BUFFER(float, snow, 0)

DEFINE_GRADIENT_AT(ground)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    uint i = dtid.y * P.w + dtid.x;
    float gx;
    float gz;
    GradientAt(x, z, gx, gz);
    float s = P.amount * SmoothStep(P.lineLo, P.lineHi, ground[i]) * (1.0f - SmoothStep(P.steepLo, P.steepHi, sqrt(gx * gx + gz * gz)));
    if (P.hasMask != 0u) s *= saturate(mask[i]);
    snow[i] = s;
}
