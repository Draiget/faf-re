// Constant buffer of gen_craters.hlsl (op craters).
#ifndef GPU_GEN_CRATERS_PARAMS_HLSLI
#define GPU_GEN_CRATERS_PARAMS_HLSLI

struct CratersParams
{
    uint w;
    uint z0;
    uint rows;
    uint seed;
    float density;
    float rmin;
    float rmax;
    float depth;
    float rim;
    float shape;
    float base;
    float pad0;
};

#endif
