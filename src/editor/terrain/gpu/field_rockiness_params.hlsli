// Constant buffer of field_rockiness.hlsl (op rockiness).
#ifndef GPU_FIELD_ROCKINESS_PARAMS_HLSLI
#define GPU_FIELD_ROCKINESS_PARAMS_HLSLI

struct RockinessParams
{
    uint w;
    uint h;
    uint z0;          // first row of this dispatch (banded dispatch)
    uint rows;
    uint n;           // distance of the convexity stencil in samples
    uint hasSoil;     // 1 = a soil thickness buffer is bound
    uint seed;
    uint noiseOn;     // 1 = the breakup noise is added
    float cell;
    float d2;         // (n * cell)^2
    float slopeLo;    // degrees
    float slopeHi;
    float gain;       // convexity gain
    float soilFull;   // soil thickness that hides the rock completely
    float wSlope;
    float wConvex;
    float wSoil;
    float norm;       // sum of the weights
    float breakup;    // amplitude of the noise
    float degK;       // 180 / pi
};

#endif
