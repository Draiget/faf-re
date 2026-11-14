// Constant buffer of filt_normal.hlsl (op normal_map).
#ifndef GPU_FILT_NORMAL_PARAMS_HLSLI
#define GPU_FILT_NORMAL_PARAMS_HLSLI

struct NormalParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint raw;        // 1 = -1..1 instead of 0..1
    uint pad0;
    uint pad1;
    uint pad2;
    float taps;      // samples either side of the point (span / 2 / cell)
    float scale;     // slope from a difference over the span: strength / span
    float shift;     // samples added to the position
    float cell;
};

#endif
