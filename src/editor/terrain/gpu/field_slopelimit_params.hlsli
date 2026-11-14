// Constant buffer of field_slopelimit.hlsl (op slope_limit).
#ifndef GPU_FIELD_SLOPELIMIT_PARAMS_HLSLI
#define GPU_FIELD_SLOPELIMIT_PARAMS_HLSLI

struct SlopeLimitParams
{
    uint w;
    uint h;
    uint mode;       // 0 lower (cut peaks), 1 raise (fill valleys), 2 both
    uint hasMask;
    float balance;   // both: 0 raise .. 1 lower
    float strength;
    float pad0;
    float pad1;
};

#endif
