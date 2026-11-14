// Op blur_slope (EdFieldFilt.cpp OpBlurSlope), the blend after the blur: the blurred value replaces the ground where the slope (central difference) is below lo..hi (flat) or above it (steep).
#include "filt_common.hlsli"
#include "field_blurslope_params.hlsli"

CBUFFER(BlurSlopeParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, blurred, 1)
SRV_BUFFER(float, mask, 2)
UAV_BUFFER(float, dst, 0)

DEFINE_GRADIENT_AT(src)

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
    float s = sqrt(gx * gx + gz * gz);
    float wgt = P.flat != 0u ? 1.0f - SmoothStep(P.lo, P.hi, s) : SmoothStep(P.lo, P.hi, s);
    wgt *= P.amount;
    if (P.hasMask != 0u) wgt *= saturate(mask[i]);
    float c = src[i];
    dst[i] = c + (blurred[i] - c) * wgt;
}
