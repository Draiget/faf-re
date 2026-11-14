// Slides of a loose layer, pass A (EdFieldEro2.cpp SlideT, first loop): for every cell, the share of its excess over the talus that slides to each lower neighbour (rate * 0.5 * largest
// excess / sum of the excesses; the drop to a neighbour above the talus of the cell it leaves, rise per run, times cell or cell * sqrt(2)) and the amount that leaves in total. A cell on
// a rock layer never gives more than its loose layer holds. Pass B collects. The border: a missing neighbour never gives or takes.
#include "common.hlsli"
#include "field_slide_params.hlsli"

CBUFFER(SlideParams, P, 0)
SRV_BUFFER(float, loose, 0)
SRV_BUFFER(float, rock, 1)
SRV_BUFFER(float, tmap, 2)
SRV_BUFFER(float, rmask, 3)
UAV_BUFFER(float, share, 0)
UAV_BUFFER(float, moved, 1)

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
    float talus = P.talus;
    if (P.hasMap != 0u) talus = tmap[i];
    float c = Surf(i);
    float tA = talus * P.cell;
    float tD = talus * P.cell * 1.41421356f;
    float maxEx = 0.0f;
    float sumEx = 0.0f;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kSlideDx[k];
        int nz = z + kSlideDz[k];
        if (nx >= 0 && nz >= 0 && nx < w && nz < h)
        {
            float thr = tA;
            if (k >= 4) thr = tD;
            float ex = (c - Surf(uint(nz) * P.w + uint(nx))) - thr;
            if (ex > 0.0f)
            {
                sumEx += ex;
                maxEx = max(maxEx, ex);
            }
        }
    }
    float s = 0.0f;
    float mv = 0.0f;
    if (sumEx > 0.0f)
    {
        float r = P.rate;
        if (P.hasMask != 0u) r *= saturate(rmask[i]);
        s = r * 0.5f * maxEx / sumEx;
        mv = s * sumEx;
        if (P.hasRock != 0u && mv > loose[i])
        {
            float f = 0.0f;
            if (loose[i] > 0.0f) f = loose[i] / mv;
            s *= f;
            mv = loose[i];
        }
    }
    share[i] = s;
    moved[i] = mv;
}
