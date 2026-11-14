// Op flow, step 3: one sweep of the D8 flow accumulation, tiled like field_wetsweep.hlsl (one thread per tile of 32 x 32 samples, cells in height order from field_wetrank, what flows between
// tiles is taken from the result of the previous sweep). Every cell passes everything it collected to its steepest lower neighbour; the sums are whole numbers, so the fixed point is the
// CPU op's result exactly.
#include "common.hlsli"
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, hgt, 0)
SRV_BUFFER(uint, target, 1)
SRV_BUFFER(uint, order, 2)
SRV_BUFFER(float, prev, 3)
UAV_BUFFER(float, nxt, 0)
UAV_BUFFER(uint, changed, 1)

static const int kFlowDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kFlowDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

NUMTHREADS(64, 1, 1)
void CSMain(KERNEL_IDS)
{
    uint tile = dtid.x;
    if (tile >= P.tilesX * P.tilesZ) return;
    int tx = int(tile % P.tilesX);
    int tz = int(tile / P.tilesX);
    int w = int(P.w);
    int h = int(P.h);
    float acc[1024];
    LOOP for (int q = 0; q < 1024; ++q) acc[q] = 0.0f;
    uint flag = 0u;
    LOOP for (uint r = 0u; r < 1024u; ++r)
    {
        uint li = order[tile * 1024u + r];
        int x = tx * 32 + int(li & 31u);
        int z = tz * 32 + int(li >> 5u);
        if (x >= w || z >= h) break;
        uint i = uint(z) * P.w + uint(x);
        float a = 1.0f + acc[li];
        UNROLL for (int k = 0; k < 8; ++k)
        {
            int nx = x + kFlowDx[k];
            int nz = z + kFlowDz[k];
            if (nx >= 0 && nz >= 0 && nx < w && nz < h && ((nx >> 5) != tx || (nz >> 5) != tz))
            {
                uint j = uint(nz) * P.w + uint(nx);
                if (target[j] == i) a += prev[j];
            }
        }
        nxt[i] = a;
        if (a != prev[i]) flag = 1u;
        uint t = target[i];
        if (t != 0xFFFFFFFFu)
        {
            int tx2 = int(t % P.w);
            int tz2 = int(t / P.w);
            if ((tx2 >> 5) == tx && (tz2 >> 5) == tz) acc[(tz2 & 31) * 32 + (tx2 & 31)] += a;
        }
    }
    if (flag != 0u) InterlockedOr(changed[0], 1u);
}
