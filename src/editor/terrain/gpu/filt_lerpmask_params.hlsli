// Constant buffer of filt_lerpmask.hlsl (the mask of ops blur and box).
#ifndef GPU_FILT_LERPMASK_PARAMS_HLSLI
#define GPU_FILT_LERPMASK_PARAMS_HLSLI

struct LerpMaskParams
{
    uint w;
    uint h;
    uint pad0;
    uint pad1;
};

#endif
