// Hydraulic erosion, pass A: the outflow of every cell through its eight pipes (pipe model, Mei et al.). F += gain * (water surface difference), never negative, scaled so a cell gives away no more
// than the water it has (including this iteration's rain). The flux persists between iterations (momentum); each thread reads and writes only its own pipes, the neighbours' ground and water only
// through T and D, which this pass does not write. An open edge sees a dry ghost cell whose ground continues the slope of the edge cell; a closed edge has no pipe; a pinned cell has no pipes.
#include "common.hlsli"
#include "erosion_hydro_params.hlsli"
#include "erosion_common.hlsli"

CBUFFER(ErodeHydroParams, P, 0)
SRV_BUFFER(float, T, 0)
SRV_BUFFER(float, D, 1)
SRV_BUFFER(float, rainMap, 2)
UAV_BUFFER(float, Fa, 0)
UAV_BUFFER(float, Fb, 1)

FN float RainOf(uint i)
{
    float m = 1.0f;
    if ((P.flags & 1u) != 0u) m = rainMap[i];
    return RainAmount(i, m, P.rain, P.rainNoise, P.seed, P.iter);
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint n = P.w * P.h;
    uint i = dtid.y * P.w + dtid.x;
    bool pinned = (P.flags & 8u) != 0u && (x == 0 || z == 0 || x == w - 1 || z == h - 1);
    bool openEdge = (P.flags & 4u) != 0u;
    float a[8];
    UNROLL for (int k = 0; k < 8; ++k) a[k] = 0.0f;
    if (!pinned)
    {
        float ti = T[i];
        float di = D[i] + RainOf(i);
        float hi = ti + di;
        float sum = 0.0f;
        UNROLL for (int k = 0; k < 8; ++k)
        {
            int nx = x + kDirX[k];
            int nz = z + kDirZ[k];
            float gk = P.gain;
            if (k >= 4) gk = 0.25f * P.gain;
            float old = 0.0f;
            if (k < 4) old = Fa[uint(k) * n + i];
            else old = Fb[uint(k - 4) * n + i];
            old *= 1.0f - P.damp;
            bool inside = nx >= 0 && nz >= 0 && nx < w && nz < h;
            float v = 0.0f;
            if (inside)
            {
                uint j = uint(nz) * P.w + uint(nx);
                v = max(0.0f, old + gk * (hi - (T[j] + D[j] + RainOf(j))));
            }
            else if (openEdge)
            {
                int ox = x - kDirX[k];
                int oz = z - kDirZ[k];
                float to = ti;
                if (ox >= 0 && oz >= 0 && ox < w && oz < h) to = T[uint(oz) * P.w + uint(ox)];
                v = max(0.0f, old + gk * (hi - (ti + min(0.0f, ti - to))));
            }
            a[k] = v;
            sum += v;
        }
        if (sum > di)
        {
            float s = 0.0f;
            if (sum > 0.0f) s = di / sum;
            UNROLL for (int k = 0; k < 8; ++k) a[k] *= s;
        }
        UNROLL for (int k = 0; k < 8; ++k)
        {
            if (a[k] < 1e-9f) a[k] = 0.0f;
        }
    }
    UNROLL for (int k = 0; k < 4; ++k)
    {
        Fa[uint(k) * n + i] = a[k];
        Fb[uint(k) * n + i] = a[k + 4];
    }
}
