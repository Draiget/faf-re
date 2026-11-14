// Constant buffer of filt_occlusion.hlsl (op occlusion).
#ifndef GPU_FILT_OCCLUSION_PARAMS_HLSLI
#define GPU_FILT_OCCLUSION_PARAMS_HLSLI

struct OcclusionParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint dirs;
    uint steps;
    uint mode;     // 0 cavity, 1 convex, 2 both
    uint pad0;
    float cell;
    float gain;
    float pad1;
    float pad2;
};

#endif
