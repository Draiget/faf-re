// Constant buffer of filt_dwarp.hlsl (op dwarp).
#ifndef GPU_FILT_DWARP_PARAMS_HLSLI
#define GPU_FILT_DWARP_PARAMS_HLSLI

struct DWarpParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint kind;       // 0 fbm, 1 curl, 2 swirl, 3 ripple, 4 pinch
    uint iters;      // fbm: 1..3
    uint octaves;
    uint edge;       // 0 clamp, 1 wrap, 2 mirror
    uint seed;
    uint hasMask;
    uint pad0;
    uint pad1;
    float strength;
    float size;
    float invSize;
    float cell;
    float invCell;
    float e0x;       // swirl / pinch: world position of sample (0, 0) relative to the centre
    float e0z;
    float fu0;       // ripple: fraction of the phase (in wavelengths) at sample (0, 0)
    float pa;        // ripple: phase per sample in x and z
    float pb;
    float phase;
    float rx;
    float rz;
    float rotK;      // swirl: strength in radians
    float pad2;
    float pad3;
};

#endif
