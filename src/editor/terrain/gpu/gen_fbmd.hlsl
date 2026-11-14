// Op fbm_damped (EdFieldGen.cpp OpFbmDamped): gradient noise fBm whose octaves are damped where the accumulated slope is steep (analytic derivatives): smooth valleys, rough crests. 0..1.
// Octave table as in gen_fractal.hlsl (fields 10 / 11 = cosine and sine of the octave's frame for the gradient).
#include "gen_noise.hlsli"
#include "gen_fbmd_params.hlsli"

CBUFFER(FbmdParams, P, 0)
SRV_BUFFER(float, oct, 1)
SRV_BUFFER(uint, octSeed, 2)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    float sum = 0.0f;
    float norm = 0.0f;
    float amp = 1.0f;
    float dsx = 0.0f;
    float dsz = 0.0f;
    LOOP for (uint o = 0u; o < P.octaves; ++o)
    {
        uint b = o * 16u;
        int ix = 0;
        int iz = 0;
        float fx = 0.0f;
        float fz = 0.0f;
        LatticePoint(oct[b], oct[b + 1u], oct[b + 2u], oct[b + 3u], oct[b + 4u], oct[b + 5u], oct[b + 6u], oct[b + 7u], x, z, ix, iz, fx, fz);
        float dnx = 0.0f;
        float dnz = 0.0f;
        float n = PerlinD(ix, iz, fx, fz, octSeed[o], P.fine, dnx, dnz);
        if (P.fine != 0u)
        {
            float rc = oct[b + 10u];
            float rs = oct[b + 11u];
            float gx = rc * dnx + rs * dnz;
            float gz = -rs * dnx + rc * dnz;
            dnx = gx;
            dnz = gz;
        }
        dsx += dnx;
        dsz += dnz;
        sum += amp * n / (1.0f + P.damp * (dsx * dsx + dsz * dsz) * 0.25f);
        norm += amp;
        amp *= P.persistence;
    }
    dst[row * P.w + dtid.x] = saturate(0.5f + 0.5f * sum / norm * 1.6f);
}
