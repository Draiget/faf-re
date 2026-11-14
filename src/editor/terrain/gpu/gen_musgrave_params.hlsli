// Constant buffer of gen_musgrave.hlsl (op musgrave).
#ifndef GPU_GEN_MUSGRAVE_PARAMS_HLSLI
#define GPU_GEN_MUSGRAVE_PARAMS_HLSLI

struct MusgraveParams
{
    uint w;
    uint z0;
    uint rows;
    uint octaves;
    uint kind;        // 0 ridged, 1 hybrid, 2 hetero
    uint fine;        // `rotate`: 64 gradient directions
    float offset;
    float gain;
    float divisor;    // amplitude sum times the mode's range factor
    float pad0;
    float pad1;
    float pad2;
};

#endif
