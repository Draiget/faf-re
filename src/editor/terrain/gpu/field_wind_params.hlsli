// Constant buffer of field_wind_a.hlsl and field_wind_b.hlsl (op erode_wind).
#ifndef GPU_FIELD_WIND_PARAMS_HLSLI
#define GPU_FIELD_WIND_PARAMS_HLSLI

struct WindParams
{
    uint w;
    uint h;
    uint pad0;
    uint pad1;
    float cell;
    float windx;        // wind direction (cos, sin of the azimuth)
    float windz;
    float awx;       // |wx|, |wz|
    float awz;
    float speed;     // sand speed on level ground, cells per step
    float abrade;    // most rock abraded per step
    float drag;      // how fast uphill slows the sand
};

#endif
