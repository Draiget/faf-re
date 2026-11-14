// Constant buffer of field_snowinit.hlsl (op erode_snow).
#ifndef GPU_FIELD_SNOWINIT_PARAMS_HLSLI
#define GPU_FIELD_SNOWINIT_PARAMS_HLSLI

struct SnowInitParams
{
    uint w;
    uint h;
    uint hasMask;
    uint pad0;
    float cell;
    float amount;     // snow depth where it lies
    float lineLo;     // snowline - band
    float lineHi;     // snowline + band
    float steepLo;    // no snow on ground steeper than steepLo .. steepHi (rise per run)
    float steepHi;
    float pad1;
    float pad2;
};

#endif
