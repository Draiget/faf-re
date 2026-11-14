// Op edge (EdFieldFilt.cpp OpEdge): sobel / prewitt gradient magnitude, laplacian (all on the 3 x 3 neighbourhood, edges clamped) or the difference of two gaussian blurs (mode 3: src and
// `other` are the two blurred fields). The smoothing in front of sobel / prewitt / laplace is a blur pass of its own (the host blurs first). The result is clamped to 0..1.
#include "common.hlsli"
#include "field_edge_params.hlsli"

CBUFFER(EdgeParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, other, 1)
UAV_BUFFER(float, dst, 0)

FN float At(int x, int z)
{
    return src[uint(ClampIndex(z, int(P.h))) * P.w + uint(ClampIndex(x, int(P.w)))];
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    uint i = uint(z) * P.w + uint(x);
    float res = 0.0f;
    if (P.mode == 3u)
    {
        float d = (src[i] - other[i]) * P.gain;
        res = P.sgn != 0u ? saturate(0.5f + d) : saturate(abs(d));
    }
    else if (P.mode == 2u)
    {
        float lap = (At(x - 1, z) + At(x + 1, z) + At(x, z - 1) + At(x, z + 1) - 4.0f * At(x, z)) / P.cell2;
        res = P.sgn != 0u ? saturate(0.5f + P.gain * lap) : saturate(abs(lap) * P.gain);
    }
    else
    {
        float wc = P.wc;
        float gx = ((At(x + 1, z - 1) + wc * At(x + 1, z) + At(x + 1, z + 1)) - (At(x - 1, z - 1) + wc * At(x - 1, z) + At(x - 1, z + 1))) / P.denom;
        float gz = ((At(x - 1, z + 1) + wc * At(x, z + 1) + At(x + 1, z + 1)) - (At(x - 1, z - 1) + wc * At(x, z - 1) + At(x + 1, z - 1))) / P.denom;
        res = saturate(sqrt(gx * gx + gz * gz) * P.gain);
    }
    dst[i] = res;
}
