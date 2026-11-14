// Slides of a loose layer, pass B (EdFieldEro2.cpp SlideT, second loop): next = loose - what the cell gave away + what its higher neighbours give it; `gain` / `lost` (optional) add what
// arrived / left.
#include "common.hlsli"
#include "field_slide_params.hlsli"

CBUFFER(SlideParams, P, 0)
SRV_BUFFER(float, loose, 0)
SRV_BUFFER(float, rock, 1)
SRV_BUFFER(float, tmap, 2)
SRV_BUFFER(float, share, 3)
SRV_BUFFER(float, moved, 4)
UAV_BUFFER(float, nxt, 0)
UAV_BUFFER(float, gain, 1)
UAV_BUFFER(float, lost, 2)

static const int kSlideDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kSlideDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

FN float Surf(uint j)
{
    if (P.hasRock != 0u) return rock[j] + loose[j];
    return loose[j];
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
    float c = Surf(i);
    float got = 0.0f;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kSlideDx[k];
        int nz = z + kSlideDz[k];
        if (nx >= 0 && nz >= 0 && nx < w && nz < h)
        {
            uint j = uint(nz) * P.w + uint(nx);
            float tj = P.talus;
            if (P.hasMap != 0u) tj = tmap[j];
            float f = 1.0f;
            if (k >= 4) f = 1.41421356f;
            float ex = (Surf(j) - c) - tj * P.cell * f;
            if (ex > 0.0f) got += share[j] * ex;
        }
    }
    nxt[i] = loose[i] - moved[i] + got;
    if (P.hasGain != 0u) gain[i] = gain[i] + got;
    if (P.hasLost != 0u) lost[i] = lost[i] + moved[i];
}
