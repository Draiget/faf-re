// dst[i] = src[i] * scale + offset. The smallest possible kernel: the template for point operations and the kernel of ed_gpu_selftest.
#include "scale_params.hlsli"

CBUFFER(ScaleParams, P, 0)
SRV_BUFFER(float, src, 0)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(64, 1, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.count) return;
    dst[dtid.x] = src[dtid.x] * P.scale + P.offset;
}
