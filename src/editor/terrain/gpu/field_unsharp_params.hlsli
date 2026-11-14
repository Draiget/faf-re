// Constant buffer of field_unsharp.hlsl (op unsharp).
#ifndef GPU_FIELD_UNSHARP_PARAMS_HLSLI
#define GPU_FIELD_UNSHARP_PARAMS_HLSLI

struct UnsharpParams
{
    uint w;
    uint h;
    uint hasMask;
    uint pad0;
    float amount;
    float thr;       // differences below this are left alone (smoothstep); 0 = every difference counts
    float pad1;
    float pad2;
};

#endif
