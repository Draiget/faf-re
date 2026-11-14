// Constant buffer of scale_offset.hlsl (and the layout rule every constant buffer struct follows: only uint / int / float members, a multiple of four members in total,
// so the C++ struct and the HLSL cbuffer have the same bytes).
#ifndef GPU_SCALE_PARAMS_HLSLI
#define GPU_SCALE_PARAMS_HLSLI

struct ScaleParams
{
    uint count;
    float scale;
    float offset;
    uint pad0;
};

#endif
