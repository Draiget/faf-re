// Constant buffer of filt_terrain.hlsl (ops slope, curvature, aspect, hillshade).
#ifndef GPU_FILT_TERRAIN_PARAMS_HLSLI
#define GPU_FILT_TERRAIN_PARAMS_HLSLI

struct TerrainParams
{
    uint w;
    uint h;
    uint z0;
    uint rows;
    uint op;          // 0 slope, 1 curvature, 2 aspect, 3 hillshade
    uint n;           // difference distance in samples (slope, curvature, aspect)
    uint mode;        // slope: 0 degrees 1 gradient; aspect: 0 facing 1 degrees; curvature: 1 = raw; hillshade: 0 shade 1 lit 2 shadow
    uint shadows;     // hillshade: cast shadows
    float cell;
    float gain;       // curvature gain
    float degK;       // 180 / pi
    float ambient;
    float zf;         // vertical exaggeration
    float lx;         // light direction
    float ly;
    float lz;
    float dirx;       // azimuth direction on the ground (aspect: the facing direction)
    float dirz;
    float tanAlt;
    float len;        // shadow length in samples
    float flatK;      // aspect: slope below which the facing fades
    float d2;         // curvature: (n * cell)^2
    float pad0;
    float pad1;
};

#endif
