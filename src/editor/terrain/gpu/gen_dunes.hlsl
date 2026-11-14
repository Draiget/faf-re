// Op dunes (EdFieldGen.cpp OpDunes): asymmetric dune ridges. The crest phase is a linear function of the sample position (kept as a fraction: only frac(phase) matters), moved by a meandering
// noise; oct records 0 and 1 are the maps of the two Fbm01 noises (meander, crest height).
#include "gen_noise.hlsli"
#include "gen_dunes_params.hlsli"

CBUFFER(DunesParams, P, 0)
SRV_BUFFER(float, oct, 1)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    int ix = 0;
    int iz = 0;
    float fx = 0.0f;
    float fz = 0.0f;
    LatticePoint(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7], x, z, ix, iz, fx, fz);
    float meander = Fbm01(ix, iz, fx, fz, P.seed + 31u, 3u, 0.5f) - 0.5f;
    float s = P.fu0 + P.pa * x + P.pb * z + P.meanderK * meander;
    float th = 6.28318530717958647692f * (s - floor(s));
    float wave = 0.5f - 0.5f * cos(th + P.asym * sin(th));
    LatticePoint(oct[16], oct[17], oct[18], oct[19], oct[20], oct[21], oct[22], oct[23], x, z, ix, iz, fx, fz);
    float crest = 1.0f - P.variation + P.variation * 2.0f * Fbm01(ix, iz, fx, fz, P.seed + 77u, 2u, 0.5f);
    float v = wave * saturate(crest);
    if (P.ripples > 0.0f)
    {
        float sr = P.fur0 + P.pra * x + P.prb * z + P.meanderKr * meander;
        float rp = 0.5f - 0.5f * cos(6.28318530717958647692f * (sr - floor(sr)) + 0.8f);
        v = v * (1.0f - P.ripples) + P.ripples * rp * (0.3f + 0.7f * wave);
    }
    dst[row * P.w + dtid.x] = saturate(v);
}
