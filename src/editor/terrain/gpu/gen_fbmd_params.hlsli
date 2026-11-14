// Constant buffer of gen_fbmd.hlsl (op fbm_damped).
#ifndef GPU_GEN_FBMD_PARAMS_HLSLI
#define GPU_GEN_FBMD_PARAMS_HLSLI

struct FbmdParams
{
    uint w;
    uint z0;
    uint rows;
    uint octaves;
    uint fine;
    float persistence;
    float damp;
    float pad0;
};

#endif
