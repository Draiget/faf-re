// Op wetness, step 3: one sweep of the flow accumulation (multiple flow direction: a cell gives its catchment, 1 + everything above it, to its lower neighbours in proportion to
// (drop / distance)^pf). The CPU op visits the cells from the highest down in one sequential pass. Here the field is cut into tiles of 32 x 32 samples, one THREAD per tile works
// through its cells in the order of field_wetrank (highest first), keeping what flows inside the tile in a private array; what flows in from the neighbouring tiles is read from the
// result of the previous sweep (`prev`). Sweep n is exact for every cell whose upstream paths cross at most n - 1 tile borders, and the fixed point is the CPU op's result, so the
// host sweeps until nothing changes (`changed`). The sums are added in another order than the CPU's: equal to about 1e-6 relative.
#include "common.hlsli"
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, hgt, 0)
SRV_BUFFER(float, inv, 1)
SRV_BUFFER(uint, order, 2)
SRV_BUFFER(float, prev, 3)
UAV_BUFFER(float, nxt, 0)
UAV_BUFFER(uint, changed, 1)

static const int kWetDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kWetDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

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
        float c = hgt[i];
        float a = 1.0f + acc[li];
        UNROLL for (int k = 0; k < 8; ++k)
        {
            int nx = x + kWetDx[k];
            int nz = z + kWetDz[k];
            if (nx >= 0 && nz >= 0 && nx < w && nz < h && ((nx >> 5) != tx || (nz >> 5) != tz))
            {
                uint j = uint(nz) * P.w + uint(nx);
                float drop = hgt[j] - c;
                if (drop > 0.0f)
                {
                    float dist = 1.41421356f;
                    if (k < 4) dist = 1.0f;
                    float wk = drop / dist;
                    if (P.pf != 1.0f) wk = pow(wk, P.pf);
                    a += prev[j] * inv[j] * wk;
                }
            }
        }
        nxt[i] = a;
        if (a != prev[i]) flag = 1u;
        float give = a * inv[i];
        if (give > 0.0f)
        {
            UNROLL for (int k2 = 0; k2 < 8; ++k2)
            {
                int nx2 = x + kWetDx[k2];
                int nz2 = z + kWetDz[k2];
                if (nx2 >= 0 && nz2 >= 0 && nx2 < w && nz2 < h && (nx2 >> 5) == tx && (nz2 >> 5) == tz)
                {
                    float drop2 = c - hgt[uint(nz2) * P.w + uint(nx2)];
                    if (drop2 > 0.0f)
                    {
                        float dist2 = 1.41421356f;
                        if (k2 < 4) dist2 = 1.0f;
                        float wk2 = drop2 / dist2;
                        if (P.pf != 1.0f) wk2 = pow(wk2, P.pf);
                        acc[(nz2 & 31) * 32 + (nx2 & 31)] += give * wk2;
                    }
                }
            }
        }
    }
    if (flag != 0u) InterlockedOr(changed[0], 1u);
}
