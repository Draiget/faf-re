// Constant buffer of field_settle.hlsl (op settle).
#ifndef GPU_FIELD_SETTLE_PARAMS_HLSLI
#define GPU_FIELD_SETTLE_PARAMS_HLSLI

struct SettleParams
{
    uint w;
    uint h;
    uint hasMask;    // 1 = a per cell factor buffer is bound
    uint pad0;
    float rate;
    float cap;       // most a cell rises per step
    float slopeLo;   // the filling fades out between these two slopes (rise per run)
    float slopeHi;
    float cell;
    float pad1;
    float pad2;
    float pad3;
};

#endif
