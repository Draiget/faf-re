// Constant buffer of field_slide_a.hlsl and field_slide_b.hlsl (ops thermal_map, erode_rocksoil, erode_snow, erode_wind: slides of a loose layer).
#ifndef GPU_FIELD_SLIDE_PARAMS_HLSLI
#define GPU_FIELD_SLIDE_PARAMS_HLSLI

struct SlideParams
{
    uint w;
    uint h;
    uint hasRock;     // 1 = the loose layer lies on a rock layer (surface = rock + loose; a cell never gives more than its loose layer holds)
    uint hasMap;      // 1 = a talus value per cell (a buffer), 0 = the constant `talus`
    uint hasMask;     // 1 = a rate factor per cell (a buffer)
    uint hasGain;     // 1 = what arrived is added to the `gain` buffer
    uint hasLost;     // 1 = what left is added to the `lost` buffer
    uint pad0;
    float cell;
    float talus;      // rise per run
    float rate;
    float pad1;
};

#endif
