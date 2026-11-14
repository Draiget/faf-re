// Op normal_map (EdFieldFilt.cpp OpNormalMap): the engine's map normal (left - right, 1, top - bottom) normalised, as three fields: x -> u0 (the op's result), y -> u1, z -> u2.
#include "filt_common.hlsli"
#include "filt_normal_params.hlsli"

CBUFFER(NormalParams, P, 0)
SRV_BUFFER(float, src, 1)
UAV_BUFFER(float, dstX, 0)
UAV_BUFFER(float, dstY, 1)
UAV_BUFFER(float, dstZ, 2)

DEFINE_BILINEAR_C(src)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float fx = float(dtid.x) + P.shift;
    float fz = float(row) + P.shift;
    float left = BilinearC(fx - P.taps, fz);
    float right = BilinearC(fx + P.taps, fz);
    float top = BilinearC(fx, fz - P.taps);
    float bottom = BilinearC(fx, fz + P.taps);
    float nx = (left - right) * P.scale;
    float nz = (top - bottom) * P.scale;
    float inv = 1.0f / sqrt(nx * nx + 1.0f + nz * nz);
    float ex = nx * inv;
    float ey = inv;
    float ez = nz * inv;
    uint idx = row * P.w + dtid.x;
    dstX[idx] = P.raw != 0u ? ex : ex * 0.5f + 0.5f;
    dstY[idx] = P.raw != 0u ? ey : ey * 0.5f + 0.5f;
    dstZ[idx] = P.raw != 0u ? ez : ez * 0.5f + 0.5f;
}
