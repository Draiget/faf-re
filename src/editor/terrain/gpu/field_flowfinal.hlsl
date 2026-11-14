// Op flow (EdFieldCore.cpp OpFlow), the output from the catchment (cells): mode 0 the count of cells, 1 the area in world units squared, 2 the log scale clamp01(ln(area) / ln(range)).
// hi = cell * cell, lo = 1 / ln(range).
#include "common.hlsli"
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, cells, 0)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    float c = cells[i];
    float area = c * P.hi;
    float r = c;
    if (P.mode == 1u) r = area;
    else if (P.mode == 2u) r = saturate(log(area) * P.lo);
    dst[i] = r;
}
