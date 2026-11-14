// Constant buffer of field_convolve.hlsl (op convolve).
#ifndef GPU_FIELD_CONVOLVE_PARAMS_HLSLI
#define GPU_FIELD_CONVOLVE_PARAMS_HLSLI

struct ConvolveParams
{
    uint w;
    uint h;
    uint z0;        // first row of this dispatch (banded dispatch)
    uint rows;
    uint n;         // the kernel is n x n (n odd)
    uint edge;      // 0 clamp, 1 wrap, 2 mirror
    uint pad0;
    uint pad1;
    float mul;      // scale (divided by the kernel sum when normalising)
    float bias;
    float pad2;
    float pad3;
};

#endif
