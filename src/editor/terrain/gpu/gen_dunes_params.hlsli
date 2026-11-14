// Constant buffer of gen_dunes.hlsl (op dunes).
#ifndef GPU_GEN_DUNES_PARAMS_HLSLI
#define GPU_GEN_DUNES_PARAMS_HLSLI

struct DunesParams
{
    uint w;
    uint z0;
    uint rows;
    uint seed;
    float fu0;          // fraction of the crest phase at sample (0, 0), in wavelengths
    float pa;           // phase per sample in x and z
    float pb;
    float fur0;         // the same for the ripples
    float pra;
    float prb;
    float meanderK;     // phase added per unit of the meander noise (crests): warp * 2 / wavelength
    float meanderKr;    // the same for the ripples: warp * 1.5 / (wavelength * 0.12)
    float asym;
    float variation;
    float ripples;
    float pad0;
};

#endif
