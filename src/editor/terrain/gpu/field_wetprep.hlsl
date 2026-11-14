// Op wetness (EdFieldFilt.cpp OpWetness), step 1: for every cell the inverse of the sum of the flow weights to its lower neighbours (eight of them, weight (drop / distance)^pf; 0 for a cell
// that has no lower neighbour). A cell with area A gives A * weight_k * inv to the neighbour k.
#include "common.hlsli"
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, hgt, 0)
UAV_BUFFER(float, inv, 0)

static const int kWetDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kWetDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

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
    float sum = 0.0f;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kWetDx[k];
        int nz = z + kWetDz[k];
        if (nx >= 0 && nz >= 0 && nx < w && nz < h)
        {
            float drop = c - hgt[uint(nz) * P.w + uint(nx)];
            if (drop > 0.0f)
            {
                float dist = 1.41421356f;
                if (k < 4) dist = 1.0f;
                float wk = drop / dist;
                if (P.pf != 1.0f) wk = pow(wk, P.pf);
                sum += wk;
            }
        }
    }
    inv[i] = sum > 0.0f ? 1.0f / sum : 0.0f;
}
