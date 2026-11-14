// Constant buffer of field_glacier_a.hlsl and field_glacier_b.hlsl (op erode_glacier).
#ifndef GPU_FIELD_GLACIER_PARAMS_HLSLI
#define GPU_FIELD_GLACIER_PARAMS_HLSLI

struct GlacierParams
{
    uint w;
    uint h;
    uint hasAcc;      // 1 = an accumulation factor per cell (a buffer)
    uint powKind;     // erosion power: 1 = v, 2 = v^2, 3 = v^1.5, 0 = pow(v, erodePow)
    float cell;
    float cc;         // cell * cell
    float flow;
    float ela;        // equilibrium line altitude
    float grad;       // mass balance gradient
    float accMax;
    float ablMax;
    float maxIce;
    float erode;
    float erodePow;
    float maxCut;
    float dtMax;
};

#endif
