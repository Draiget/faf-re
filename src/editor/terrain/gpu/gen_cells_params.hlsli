// Constant buffer of gen_cells.hlsl (ops voronoi, cells, cracks).
#ifndef GPU_GEN_CELLS_PARAMS_HLSLI
#define GPU_GEN_CELLS_PARAMS_HLSLI

struct CellsParams
{
    uint w;
    uint z0;
    uint rows;
    uint op;          // 0 voronoi, 1 cells, 2 cracks
    uint mode;        // voronoi: f1 f2 edge id crack; cells: f1 f2 f3 edge crack id smooth border plate facet
    uint metric;      // 0 euclid, 1 manhattan, 2 chebyshev, 3 minkowski
    uint range;       // neighbour cells searched each side (1 or 2)
    uint levels;      // cracks: networks (1..3)
    uint seed;
    uint seedA;       // seeds of the two warp noises
    uint seedB;
    uint warpOn;      // 1 = domain warp of the lattice position
    uint profile;     // cracks: 0 v, 1 u, 2 flat
    uint warpOct;     // octaves of the warp noise (3)
    uint pad0;
    uint pad1;
    float jitter;
    float pexp;       // minkowski exponent
    float ksoft;      // smooth mode sharpness
    float width;      // voronoi / cells crack thickness
    float bevel;
    float drop;
    float warp;       // world units
    float pad2;
};

#endif
