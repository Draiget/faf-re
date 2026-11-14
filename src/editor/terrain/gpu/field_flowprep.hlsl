// Op flow (EdFieldCore.cpp OpFlow, D8 flow accumulation), step 1: the steepest lower neighbour of every cell (the first of the eight in the CPU op's order wins a tie): its index, or
// 0xFFFFFFFF for a cell with no lower neighbour (a pit or an edge cell: it keeps what it collects).
#include "common.hlsli"
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, hgt, 0)
UAV_BUFFER(uint, target, 0)

static const int kFlowDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kFlowDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint i = dtid.y * P.w + dtid.x;
    float c = hgt[i];
    float best = 0.0f;
    uint tgt = 0xFFFFFFFFu;
    UNROLL for (int d = 0; d < 8; ++d)
    {
        int nx = x + kFlowDx[d];
        int nz = z + kFlowDz[d];
        if (nx >= 0 && nz >= 0 && nx < w && nz < h)
        {
            uint j = uint(nz) * P.w + uint(nx);
            float dist = 1.41421356f;
            if (d < 4) dist = 1.0f;
            float drop = (c - hgt[j]) / dist;
            if (drop > best)
            {
                best = drop;
                tgt = j;
            }
        }
    }
    target[i] = tgt;
}
