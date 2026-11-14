// One pass of the separable blur (ops `blur` and `box`): dst(x, z) = k0 * src(x, z) + sum over i = 1..r of k[i] * (src(x - i) + src(x + i)) along x (or z), edges clamped.
// The order of the additions is the CPU op's (EdFieldCore.cpp ConvolveH / ConvolveV), so the result matches it to the last bit when the compiler does not fuse multiply and add.
// The template for stencil kernels: global memory in, other global memory out (ping-pong), explicit indexing, no group shared memory.
#include "common.hlsli"
#include "blur_params.hlsli"

CBUFFER(BlurParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, weights, 1)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    int r = int(P.radius);
    float sum = weights[0] * src[z * w + x];
    LOOP for (int i = 1; i <= r; ++i)
    {
        int xa = x;
        int xb = x;
        int za = z;
        int zb = z;
        if (P.vertical == 0u)
        {
            xa = ClampIndex(x - i, w);
            xb = ClampIndex(x + i, w);
        }
        else
        {
            za = ClampIndex(z - i, h);
            zb = ClampIndex(z + i, h);
        }
        sum += weights[i] * (src[za * w + xa] + src[zb * w + xb]);
    }
    dst[z * w + x] = sum;
}
