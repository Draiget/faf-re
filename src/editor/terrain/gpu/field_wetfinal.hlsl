// Op wetness (EdFieldFilt.cpp OpWetness), the point passes. stage 0: topographic wetness index ln(specific catchment / tan slope) from the catchment `area` and the height (gradient
// floored at 0.005). stage 1: the op's output from the (smoothed) index `t`: mode 1 the index itself, 2 the catchment on a log scale (log2 / 14), else smoothstep(lo, hi, index).
#include "filt_common.hlsli"
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, hgt, 0)
SRV_BUFFER(float, area, 1)
SRV_BUFFER(float, tw, 2)
UAV_BUFFER(float, dst, 0)

DEFINE_GRADIENT_AT(hgt)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    uint i = dtid.y * P.w + dtid.x;
    if (P.stage == 0u)
    {
        float gx;
        float gz;
        GradientAt(x, z, gx, gz);
        float tb = max(0.005f, sqrt(gx * gx + gz * gz));
        float sca = area[i] * P.cell;
        dst[i] = log(sca / tb);
    }
    else if (P.mode == 1u)
    {
        dst[i] = tw[i];
    }
    else if (P.mode == 2u)
    {
        dst[i] = saturate(log2(area[i]) / 14.0f);
    }
    else
    {
        dst[i] = SmoothStep(P.lo, P.hi, tw[i]);
    }
}
