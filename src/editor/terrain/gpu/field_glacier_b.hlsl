// Op erode_glacier (EdFieldEro2.cpp OpGlacier), the second pass of a step: the time step dt = min(dtMax, 0.2 cell^2 / largest D), the ice flux divergence plus the mass balance (accumulation above
// the equilibrium line, ablation below, both limited), the new ice thickness, and the bed cut under thick fast ice.
#include "common.hlsli"
#include "field_glacier_params.hlsli"

CBUFFER(GlacierParams, P, 0)
SRV_BUFFER(float, bed, 0)
SRV_BUFFER(float, ice, 1)
SRV_BUFFER(float, dif, 2)
SRV_BUFFER(float, gsl, 3)
SRV_BUFFER(float, acc, 4)
SRV_BUFFER(uint, dmaxBits, 5)
UAV_BUFFER(float, nxt, 0)
UAV_BUFFER(float, cut, 1)

FN float Surf(uint j)
{
    return bed[j] + ice[j];
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint i = dtid.y * P.w + dtid.x;
    float dmax = asfloat(dmaxBits[0]);
    float dt = P.dtMax;
    if (dmax > 0.0f) dt = min(P.dtMax, 0.2f * P.cc / dmax);
    float s = Surf(i);
    float dv = 0.0f;
    if (x > 0) dv += 0.5f * (dif[i] + dif[i - 1u]) * (Surf(i - 1u) - s) / P.cc;
    if (x < w - 1) dv += 0.5f * (dif[i] + dif[i + 1u]) * (Surf(i + 1u) - s) / P.cc;
    if (z > 0) dv += 0.5f * (dif[i] + dif[i - P.w]) * (Surf(i - P.w) - s) / P.cc;
    if (z < h - 1) dv += 0.5f * (dif[i] + dif[i + P.w]) * (Surf(i + P.w) - s) / P.cc;
    float b = P.grad * (s - P.ela);
    float accLimit = P.accMax;
    if (P.hasAcc != 0u) accLimit = P.accMax * saturate(acc[i]);
    b = max(-P.ablMax, min(accLimit, b));
    float nh = max(0.0f, min(P.maxIce, ice[i] + dt * (dv + b)));
    nxt[i] = nh;
    if (nh > 0.0f && P.erode > 0.0f && ice[i] > 0.0f)
    {
        float v = ice[i] * gsl[i];
        float p = v;
        if (P.powKind == 2u) p = v * v;
        else if (P.powKind == 3u) p = v * sqrt(v);
        else if (P.powKind == 0u) p = pow(v, P.erodePow);
        cut[i] = min(P.maxCut, cut[i] + dt * (P.erode * p));
    }
}
