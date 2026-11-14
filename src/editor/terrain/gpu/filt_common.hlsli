// Helpers of the filter kernels (filt_*.hlsl). Every filter kernel has a constant buffer P that starts with  uint w, h, z0, rows;  (field size, first row and number of rows of this dispatch) and
// reads the source field from a structured buffer. Functions that read a buffer cannot take it as an argument in the kernel subset, so they are macros that define a function for the buffer
// whose name is given (the function reads P.w / P.h, so define it after the CBUFFER).
#ifndef GPU_FILT_COMMON_HLSLI
#define GPU_FILT_COMMON_HLSLI

#include "common.hlsli"

// EdFieldUtil.h SmoothStep (an empty edge range is a step).
FN float SmoothStep(float e0, float e1, float v)
{
    if (e1 == e0) return v < e0 ? 0.0f : 1.0f;
    float t = saturate((v - e0) / (e1 - e0));
    return t * t * (3.0f - 2.0f * t);
}

// BilinearC(gx, gz): bilinear sample of buffer BUF at fractional sample coordinates, clamped edges (EdFieldUtil.h BilinearC).
#define DEFINE_BILINEAR_C(BUF)                                                                  \
    FN float BilinearC(float gx, float gz)                                                      \
    {                                                                                           \
        float mx = float(P.w - 1u);                                                             \
        float mz = float(P.h - 1u);                                                             \
        float cx = gx < 0.0f ? 0.0f : (gx > mx ? mx : gx);                                      \
        float cz = gz < 0.0f ? 0.0f : (gz > mz ? mz : gz);                                      \
        int ix = int(cx);                                                                       \
        int iz = int(cz);                                                                       \
        if (ix >= int(P.w) - 1) ix = max(0, int(P.w) - 2);                                      \
        if (iz >= int(P.h) - 1) iz = max(0, int(P.h) - 2);                                      \
        float tx = cx - float(ix);                                                              \
        float tz = cz - float(iz);                                                              \
        int ix1 = min(int(P.w) - 1, ix + 1);                                                    \
        int iz1 = min(int(P.h) - 1, iz + 1);                                                    \
        uint r0 = uint(iz) * P.w;                                                               \
        uint r1 = uint(iz1) * P.w;                                                              \
        float a0 = BUF[r0 + uint(ix)];                                                          \
        float a1 = BUF[r0 + uint(ix1)];                                                         \
        float b0 = BUF[r1 + uint(ix)];                                                          \
        float b1 = BUF[r1 + uint(ix1)];                                                         \
        float top = a0 + (a1 - a0) * tx;                                                        \
        float bottom = b0 + (b1 - b0) * tx;                                                     \
        return top + (bottom - top) * tz;                                                       \
    }

// GradientAt(x, z, gx, gz): central difference gradient (rise per run, P.cell world units per sample) with clamped edges (EdFieldUtil.h GradientAt).
#define DEFINE_GRADIENT_AT(BUF)                                                                 \
    FN void GradientAt(int x, int z, OUT(float) gx, OUT(float) gz)                              \
    {                                                                                           \
        int x0 = max(0, x - 1);                                                                 \
        int x1 = min(int(P.w) - 1, x + 1);                                                      \
        int z0 = max(0, z - 1);                                                                 \
        int z1 = min(int(P.h) - 1, z + 1);                                                      \
        gx = 0.0f;                                                                              \
        gz = 0.0f;                                                                              \
        if (x1 > x0) gx = (BUF[uint(z) * P.w + uint(x1)] - BUF[uint(z) * P.w + uint(x0)]) / (float(x1 - x0) * P.cell); \
        if (z1 > z0) gz = (BUF[uint(z1) * P.w + uint(x)] - BUF[uint(z0) * P.w + uint(x)]) / (float(z1 - z0) * P.cell); \
    }

#endif
