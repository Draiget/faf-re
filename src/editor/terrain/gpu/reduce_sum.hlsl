// dst[group] = sum of the 256 values src[group * 256 .. group * 256 + 255] (values past `count` are 0). The template for kernels with group shared memory and barriers
// (PHASES_BEGIN / BARRIER / PHASES_END, see the GPU_COMPUTE.md "group shared memory" rule), and a selftest of the barrier emulation.
#include "reduce_params.hlsli"

CBUFFER(ReduceParams, P, 0)
SRV_BUFFER(float, src, 0)
UAV_BUFFER(float, dst, 0)
GROUPSHARED(float, sh, 128)

NUMTHREADS(128, 1, 1)
void CSMain(KERNEL_IDS)
{
    PHASES_BEGIN
    uint a = gid.x * 256u + gtid.x;
    uint b = a + 128u;
    float va = 0.0f;
    float vb = 0.0f;
    if (a < P.count) va = src[a];
    if (b < P.count) vb = src[b];
    sh[gtid.x] = va + vb;
    BARRIER(0);
    if (gtid.x < 64u) sh[gtid.x] = sh[gtid.x] + sh[gtid.x + 64u];
    BARRIER(0);
    if (gtid.x < 32u) sh[gtid.x] = sh[gtid.x] + sh[gtid.x + 32u];
    BARRIER(0);
    if (gtid.x < 16u) sh[gtid.x] = sh[gtid.x] + sh[gtid.x + 16u];
    BARRIER(0);
    if (gtid.x < 8u) sh[gtid.x] = sh[gtid.x] + sh[gtid.x + 8u];
    BARRIER(0);
    if (gtid.x < 4u) sh[gtid.x] = sh[gtid.x] + sh[gtid.x + 4u];
    BARRIER(0);
    if (gtid.x < 2u) sh[gtid.x] = sh[gtid.x] + sh[gtid.x + 2u];
    BARRIER(0);
    if (gtid.x == 0u) dst[gid.x] = sh[0] + sh[1];
    PHASES_END
}
