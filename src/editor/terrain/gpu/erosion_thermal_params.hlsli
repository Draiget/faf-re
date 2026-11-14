// Constant buffer of the erosion helper kernels (thermal slides, delta filter, settle, droplet resolve).
#ifndef GPU_EROSION_THERMAL_PARAMS_HLSLI
#define GPU_EROSION_THERMAL_PARAMS_HLSLI

struct ErodeThermalParams
{
    uint w;
    uint h;
    uint pinSides;     // bit 0 / 1 = the -x / +x column, bit 2 / 3 = the -z / +z row is left alone
    uint hasMask;      // 1 = a per cell factor buffer is bound
    float tAxis;       // talus * cell
    float tDiag;       // talus * cell * sqrt(2)
    float rate;        // share of the excess that slides
    float amount;      // blend factor (delta filter) / scale (resolve)
    float blendNext;   // blend of the next smoothing pass (creep with a fractional number of passes)
    uint edgeKeep;     // 1 = the outer ring keeps its own change (delta filter)
    uint flags;
    uint pad0;
};

#endif
