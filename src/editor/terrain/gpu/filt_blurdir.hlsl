// Op blur_dir (EdFieldFilt.cpp OpBlurDir): directional blur, a weighted line of bilinear taps along (ux, uz). wt: the 2 * taps + 1 weights.
#include "filt_common.hlsli"
#include "filt_blurdir_params.hlsli"

CBUFFER(BlurDirParams, P, 0)
SRV_BUFFER(float, wt, 1)
SRV_BUFFER(float, src, 2)
SRV_BUFFER(float, mask, 3)
UAV_BUFFER(float, dst, 0)

DEFINE_BILINEAR_C(src)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    int taps = int(P.taps);
    float acc = 0.0f;
    LOOP for (int i = -taps; i <= taps; ++i)
    {
        acc += wt[i + taps] * BilinearC(x + P.ux * float(i), z + P.uz * float(i));
    }
    float res = acc / P.wsum;
    uint idx = row * P.w + dtid.x;
    if (P.hasMask != 0u)
    {
        float c = src[idx];
        res = c + (res - c) * saturate(mask[idx]);
    }
    dst[idx] = res;
}
