// Constant buffer of field_blurslope.hlsl (op blur_slope).
#ifndef GPU_FIELD_BLURSLOPE_PARAMS_HLSLI
#define GPU_FIELD_BLURSLOPE_PARAMS_HLSLI

struct BlurSlopeParams
{
    uint w;
    uint h;
    uint flat;       // 1 = blur where the ground is flat, 0 = where it is steep
    uint hasMask;
    float cell;
    float lo;        // soft slope limits (rise per run)
    float hi;
    float amount;
};

#endif
