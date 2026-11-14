// Constant buffer of gen_island.hlsl (op island).
#ifndef GPU_GEN_ISLAND_PARAMS_HLSLI
#define GPU_GEN_ISLAND_PARAMS_HLSLI

struct IslandParams
{
    uint w;
    uint z0;
    uint rows;
    uint seed;
    uint outKind;      // 0 height, 1 mask, 2 distance
    uint pad0;
    uint pad1;
    uint pad2;
    float u0;         // position relative to the centre, turned and squashed: u = u0 + ua x + ub z, v = v0 + va x + vb z (world units)
    float ua;
    float ub;
    float v0;
    float va;
    float vb;
    float radius;
    float rough;
    float edge;
    float power;
    float pad3;
    float pad4;
};

#endif
