// Constant buffer of gen_fractal.hlsl (op fractal).
#ifndef GPU_GEN_FRACTAL_PARAMS_HLSLI
#define GPU_GEN_FRACTAL_PARAMS_HLSLI

struct FractalParams
{
    uint w;
    uint z0;
    uint rows;
    uint octaves;
    uint kind;          // 0 fbm, 1 billow, 2 ridged
    uint style;         // 0 classic, 1 erosive
    uint warpLevels;    // 1 or 2 (only used when warp > 0)
    uint pad0;
    float warp;         // world units; 0 = no domain warp
    float slopeDetail;
    float erosion;
    float sharp;
    float norm;
    float fit;
    float invCell;      // 1 / world units per sample
    float pad1;
};

#endif
