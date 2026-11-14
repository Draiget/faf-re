// Constant buffer of filt_diffuse.hlsl (op diffuse).
#ifndef GPU_FILT_DIFFUSE_PARAMS_HLSLI
#define GPU_FILT_DIFFUSE_PARAMS_HLSLI

struct DiffuseParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint expo;       // 1 = exponential conductance, 0 = Lorentzian
    uint hasMask;
    uint pad0;
    uint pad1;
    float invK2;     // 1 / kappa^2
    float invCell;
    float rate;
    float pad2;
};

#endif
