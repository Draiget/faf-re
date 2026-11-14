// Constant buffer of the hydraulic erosion kernels (erosion_hydro_*.hlsl). The host (EdGpuErosion.cpp) includes this very file.
#ifndef GPU_EROSION_HYDRO_PARAMS_HLSLI
#define GPU_EROSION_HYDRO_PARAMS_HLSLI

struct ErodeHydroParams
{
    uint w;              // field size
    uint h;
    uint flags;          // 1 = rain map, 2 = rock map, 4 = open edge, 8 = pinned ring, 16 = keep wear / deposit / flow
    uint iter;           // iteration number (rain noise pattern)
    float gain;          // pipe gain of the four axis pipes (the diagonal pipes get a quarter)
    float evap;          // share of the water that evaporates per iteration
    float rain;          // water depth added per iteration
    float capacity;      // sediment capacity factor
    float erosion;       // share of the missing sediment that is dissolved per iteration
    float deposition;    // share of the surplus sediment that settles per iteration
    float invDepthMax;   // 1 / depth at which the capacity saturates
    float minSlope;      // sin(slope) floor
    float slopeCap;      // sin(slope) at which the capacity stops growing (soft)
    float maxSpeed;      // cells per iteration
    float cutLimit;      // share of the drop to the lowest neighbour one step may dig (0 = unlimited)
    float cell;          // world units per sample
    float rainNoise;     // 0..1 amplitude of the white noise on the rain
    uint seed;
    float velFloor;      // smallest water depth the speed is divided by
    float damp;          // share of the old pipe flux that is lost per iteration
    float vThresh;       // speed below which nothing is dissolved
    float speedPow;      // exponent of the speed in the capacity
    float rampMax;       // the water depth factor of the capacity grows up to this many times the depth_max ramp (1 = saturates at depth_max, like the CPU op)
    float tauC;          // shear threshold: nothing is dissolved while depth factor * slope is below it
    float spread;        // share of the ground change that is spread over the 3 x 3 neighbourhood (binomial): channels at least 2 - 3 cells wide, no cell wide combs
    float pad0;
    float pad1;
    float pad2;
};

#endif
