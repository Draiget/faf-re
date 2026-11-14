// Constant buffer of field_stratify.hlsl (op stratify).
#ifndef GPU_FIELD_STRATIFY_PARAMS_HLSLI
#define GPU_FIELD_STRATIFY_PARAMS_HLSLI

struct StratifyParams
{
    uint w;
    uint h;
    uint z0;          // first row of this dispatch (banded dispatch)
    uint rows;
    uint seed;        // seed + 911: the seed of the warp noise
    uint hasMask;
    uint warpOn;      // 1 = the layer boundaries are warped by noise
    uint slopeOn;     // 1 = layering only on ground steeper than slopeLo .. slopeHi
    float cell;
    float ox;         // world position of sample (0, 0)
    float oz;
    float tiltX;      // the layers dip: rise per run
    float tiltZ;
    float warp;       // warp amplitude (height units)
    float wdt;        // half width of the smoothstep of a shelf
    float strength;
    float slopeLo;
    float slopeHi;
    float pad0;
    float pad1;
};

#endif
