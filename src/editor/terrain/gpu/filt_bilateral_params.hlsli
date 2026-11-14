// Constant buffer of filt_bilateral.hlsl (op bilateral).
#ifndef GPU_FILT_BILATERAL_PARAMS_HLSLI
#define GPU_FILT_BILATERAL_PARAMS_HLSLI

struct BilateralParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint rad;        // window radius in samples
    uint hasMask;
    uint pad0;
    uint pad1;
    float inv;       // 1 / sigma_r^2
    float pad2;
    float pad3;
    float pad4;
};

#endif
