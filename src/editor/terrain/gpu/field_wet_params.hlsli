// Constant buffer of the wetness kernels (field_wetprep, field_wetrank, field_wetsweep, field_wetfinal; op wetness).
#ifndef GPU_FIELD_WET_PARAMS_HLSLI
#define GPU_FIELD_WET_PARAMS_HLSLI

struct WetParams
{
    uint w;
    uint h;
    uint tilesX;     // tiles of 32 x 32 samples: columns and rows
    uint tilesZ;
    uint tile0;      // first tile of this dispatch (banded dispatch of the rank kernel)
    uint stage;      // field_wetfinal: 0 = topographic index, 1 = the op's output
    uint mode;       // field_wetfinal: 0 wet (smoothstep lo..hi), 1 twi (raw), 2 area (log scale)
    uint pad0;
    float cell;
    float pf;        // flow exponent
    float lo;
    float hi;
};

#endif
