// Constant buffer of filt_blurdir.hlsl (op blur_dir).
#ifndef GPU_FILT_BLURDIR_PARAMS_HLSLI
#define GPU_FILT_BLURDIR_PARAMS_HLSLI

struct BlurDirParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint taps;       // taps each side of the centre
    uint hasMask;
    uint pad0;
    uint pad1;
    float ux;
    float uz;
    float wsum;
    float pad2;
};

#endif
