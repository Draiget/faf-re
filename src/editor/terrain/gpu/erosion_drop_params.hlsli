// Constant buffer of the droplet erosion kernels (erosion_drop.hlsl, erosion_drop_resolve.hlsl). The host (EdGpuErosion.cpp) includes this very file.
#ifndef GPU_EROSION_DROP_PARAMS_HLSLI
#define GPU_EROSION_DROP_PARAMS_HLSLI

// fixed point scales of the integer accumulation buffers (atomic adds): the ground and the wear / deposit maps in 1/65536 world unit, the flow in 1/1024
#define EROSION_DROP_SCALE 65536.0f
#define EROSION_FLOW_SCALE 1024.0f

struct ErodeDropParams
{
    uint w;
    uint h;
    uint count;        // droplets of this dispatch
    uint gw;           // width of the dispatch grid (droplet = y * gw + x)
    uint seed;
    uint roundNo;
    uint flags;        // 1 = release probability map, 2 = rock map, 4 = hardness map (what a droplet takes up), 8 = keep wear / deposit / flow, 16 = droplets differ
    uint lifetime;
    float inertia;
    float capacity;
    float minSlope;
    float erode;
    float deposit;
    float evaporate;
    float gravity;
    float speed;
    float water;
    float roundCut;
    float accel;
    float dropVary;
    float cell;
    uint radius;
    uint maxLife;
    uint idOffset;     // the first droplet's number in its round (batches of one round)
};

#endif
