// Constant buffer of the texture kernels (buf_to_tex.hlsl, tex_resample.hlsl).
#ifndef GPU_FIELD_PARAMS_HLSLI
#define GPU_FIELD_PARAMS_HLSLI

struct FieldParams
{
    uint w;       // size of the destination
    uint h;
    uint srcW;    // size of the source
    uint srcH;
};

#endif
