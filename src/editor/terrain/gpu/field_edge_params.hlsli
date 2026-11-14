// Constant buffer of field_edge.hlsl (op edge).
#ifndef GPU_FIELD_EDGE_PARAMS_HLSLI
#define GPU_FIELD_EDGE_PARAMS_HLSLI

struct EdgeParams
{
    uint w;
    uint h;
    uint z0;        // first row of this dispatch (banded dispatch)
    uint rows;
    uint mode;      // 0 sobel, 1 prewitt, 2 laplace, 3 difference of gaussians (src minus other)
    uint sgn;       // 1 = signed result (laplace, dog): 0.5 + value
    float gain;
    float wc;       // centre weight of the gradient kernel (sobel 2, prewitt 1)
    float denom;    // (2 + wc) * 2 * cell, computed on the host in float like the CPU op
    float cell2;    // cell * cell
    float pad0;
    float pad1;
};

#endif
