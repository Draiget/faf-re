// Constant buffer of field_morph.hlsl (op morph).
#ifndef GPU_FIELD_MORPH_PARAMS_HLSLI
#define GPU_FIELD_MORPH_PARAMS_HLSLI

struct MorphParams
{
    uint w;
    uint h;
    uint z0;        // first row of this dispatch (banded dispatch)
    uint rows;      // rows of this dispatch
    uint shape;     // 0 = the row window (x), 1 = the column window (z), 2 = disc, 3 = diamond, 4 = cross
    uint rad;       // radius in samples
    uint isMax;     // 1 = dilation (window maximum), 0 = erosion (window minimum)
    uint pad0;
};

#endif
