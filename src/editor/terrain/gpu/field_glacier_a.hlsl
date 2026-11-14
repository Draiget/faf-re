// Op erode_glacier (EdFieldEro2.cpp OpGlacier), the first pass of a step (shallow ice approximation): from the ice surface (bed + ice) the ice diffusivity D = flow * H^5 * |grad s|^2 (n = 3)
// and the surface slope, and the largest D of the field (for the time step): one maximum per group of 256 cells, then one atomic maximum per group on `dmaxCur` (a non negative float
// compares like its bits). `dmaxNext` is zeroed for the next step, which uses it as its `dmaxCur` (the two buffers alternate, so no extra clearing dispatch is needed).
#include "field_glacier_params.hlsli"

CBUFFER(GlacierParams, P, 0)
SRV_BUFFER(float, bed, 0)
SRV_BUFFER(float, ice, 1)
UAV_BUFFER(float, dif, 0)
UAV_BUFFER(float, gsl, 1)
UAV_BUFFER(uint, dmaxCur, 2)
UAV_BUFFER(uint, dmaxNext, 3)
GROUPSHARED(float, sh, 256)

// ice surface at sample (x, z) (a macro: a kernel with barriers has no early exit, not even in a helper)
#define SURF(x, z) (bed[uint(z) * P.w + uint(x)] + ice[uint(z) * P.w + uint(x)])

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    PHASES_BEGIN
    float dv = 0.0f;
    if (dtid.x < P.w && dtid.y < P.h)
    {
        int x = int(dtid.x);
        int z = int(dtid.y);
        int w = int(P.w);
        int h = int(P.h);
        uint i = dtid.y * P.w + dtid.x;
        int xl = max(0, x - 1);
        int xr = min(w - 1, x + 1);
        int zu = max(0, z - 1);
        int zd = min(h - 1, z + 1);
        float gx = (SURF(xr, z) - SURF(xl, z)) / (2.0f * P.cell);
        float gz = (SURF(x, zd) - SURF(x, zu)) / (2.0f * P.cell);
        float s2 = gx * gx + gz * gz;
        float hh = ice[i];
        float h2 = hh * hh;
        float d = P.flow * h2 * h2 * hh * s2;
        dif[i] = d;
        gsl[i] = sqrt(s2);
        dv = d;
        if (i == 0u) dmaxNext[0] = 0u;
    }
    sh[gidx] = dv;
    BARRIER(0);
    if (gidx < 128u) sh[gidx] = max(sh[gidx], sh[gidx + 128u]);
    BARRIER(0);
    if (gidx < 64u) sh[gidx] = max(sh[gidx], sh[gidx + 64u]);
    BARRIER(0);
    if (gidx < 32u) sh[gidx] = max(sh[gidx], sh[gidx + 32u]);
    BARRIER(0);
    if (gidx < 16u) sh[gidx] = max(sh[gidx], sh[gidx + 16u]);
    BARRIER(0);
    if (gidx < 8u) sh[gidx] = max(sh[gidx], sh[gidx + 8u]);
    BARRIER(0);
    if (gidx < 4u) sh[gidx] = max(sh[gidx], sh[gidx + 4u]);
    BARRIER(0);
    if (gidx < 2u) sh[gidx] = max(sh[gidx], sh[gidx + 2u]);
    BARRIER(0);
    if (gidx == 0u) InterlockedMax(dmaxCur[0], asuint(max(sh[0], sh[1])));
    PHASES_END
}
