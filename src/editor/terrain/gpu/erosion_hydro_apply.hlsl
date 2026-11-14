// Hydraulic erosion, ground update: T' = T - ((1 - spread) * dT + spread * the 3 x 3 binomial average of dT), edges clamped. The sum of the change is kept (what is dissolved in a cell is taken
// from its neighbourhood), but a channel is no longer one cell wide: the cell scale combs of a grid solver (every cell digs for itself, 1 cell grooves along the axes) turn into grooves 2 - 3 cells
// wide, as the brush of the droplets does. A pinned cell keeps its ground.
#include "common.hlsli"
#include "erosion_hydro_params.hlsli"

CBUFFER(ErodeHydroParams, P, 0)
SRV_BUFFER(float, T, 0)
SRV_BUFFER(float, dT, 1)
UAV_BUFFER(float, Tn, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint i = dtid.y * P.w + dtid.x;
    bool pinned = (P.flags & 8u) != 0u && (x == 0 || z == 0 || x == w - 1 || z == h - 1);
    if (pinned)
    {
        Tn[i] = T[i];
        return;
    }
    float c = dT[i];
    float avg = c;
    if (P.spread > 0.0f)
    {
        // symmetric weights (the binomial 3 x 3), a neighbour that is off the map or pinned gives its weight to the centre: what a cell dissolves is all taken from the cells that can lose it
        float sum = 0.0f;
        for (int dz = -1; dz <= 1; ++dz)
        {
            for (int dx = -1; dx <= 1; ++dx)
            {
                int xx = x + dx;
                int zz = z + dz;
                float wt = (dx == 0 ? 0.5f : 0.25f) * (dz == 0 ? 0.5f : 0.25f);
                bool usable = xx >= 0 && zz >= 0 && xx < w && zz < h;
                if (usable && (P.flags & 8u) != 0u && (xx == 0 || zz == 0 || xx == w - 1 || zz == h - 1)) usable = false;
                if (dx == 0 && dz == 0) usable = true;
                if (usable) sum += wt * dT[uint(zz) * P.w + uint(xx)];
                else sum += wt * c;
            }
        }
        avg = sum;
    }
    Tn[i] = T[i] - ((1.0f - P.spread) * c + P.spread * avg);
}
