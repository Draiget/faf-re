// Constant buffer of blur_pass.hlsl. The host (EdGpuOps.cpp) includes this very file, so the layout cannot drift.
#ifndef GPU_BLUR_PARAMS_HLSLI
#define GPU_BLUR_PARAMS_HLSLI

struct BlurParams
{
    uint w;           // field width
    uint h;           // field height
    uint radius;      // kernel radius in samples; weights[0..r] is the one-sided kernel
    uint vertical;    // 0 = blur along x, 1 = along z
};

#endif
