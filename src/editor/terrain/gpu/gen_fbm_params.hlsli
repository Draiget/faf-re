// Constant buffer of gen_fbm.hlsl (ops perlin, simplex, ridged, billow).
#ifndef GPU_GEN_FBM_PARAMS_HLSLI
#define GPU_GEN_FBM_PARAMS_HLSLI

struct FbmParams
{
    uint w;           // field width
    uint z0;          // first row of this dispatch (a big field is split into row bands)
    uint rows;        // rows in this dispatch
    uint octaves;
    uint kind;        // 0 fbm (rolling), 1 ridged, 2 billow
    uint basis;       // 0 perlin, 1 simplex
    uint fine;        // 64 gradient directions (the `rotate` option) instead of 8
    float norm;       // sum of the octave amplitudes
};

#endif
