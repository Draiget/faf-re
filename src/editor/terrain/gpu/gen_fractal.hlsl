// Op fractal (EdFieldLand.cpp FractalAt): fractal gradient noise built to look like land. One thread per sample; the options and the per octave frames are the CPU op's (EdFieldFractal.h).
// fbm / billow / ridged (ridged multifractal: every octave is weighted by the one before), a domain warp by independent noise channels (1 or 2 levels), slope_detail (finer octaves louder
// where the coarse ones are steep or flat) and style erosive (finer octaves damped by the slope of the terrain so far, from the analytic derivatives of the noise).
//
// Tables. oct: 16 floats per record. Records 0..15 are the octaves (see gen_noise.hlsli for the map in 0..7; 8 amplitude, 9 share of the warp it follows, 10 / 11 cosine and sine of the frame (the
// gradient goes back to the world frame with them), 12 lattice units per feature size, 13 antialias fade); records 16..18 are the three octaves of the warp noise (map only). octSeed: 0..15 the
// octave seeds, 16 + 3 * (salt - 1) + o the seeds of warp octave o of noise channel `salt` (1..4).
#include "gen_noise.hlsli"
#include "gen_fractal_params.hlsli"

CBUFFER(FractalParams, P, 0)
SRV_BUFFER(float, oct, 1)
SRV_BUFFER(uint, octSeed, 2)
UAV_BUFFER(float, dst, 0)

// Three octave noise about -1..1 of channel `salt` at sample (x, z) moved by the world displacement (sdx, sdz) (EdFieldLand.cpp WarpNoise).
FN float WarpNoise(uint salt, float x, float z, float sdx, float sdz)
{
    float sum = 0.0f;
    float norm = 0.0f;
    float amp = 1.0f;
    UNROLL for (uint o = 0u; o < 3u; ++o)
    {
        uint b = (16u + o) * 16u;
        float du = (oct[b + 4u] * sdx + oct[b + 5u] * sdz) * P.invCell;
        float dv = (oct[b + 6u] * sdx + oct[b + 7u] * sdz) * P.invCell;
        int ix = 0;
        int iz = 0;
        float fx = 0.0f;
        float fz = 0.0f;
        LatticePoint(oct[b], oct[b + 1u], oct[b + 2u] + du, oct[b + 3u] + dv, oct[b + 4u], oct[b + 5u], oct[b + 6u], oct[b + 7u], x, z, ix, iz, fx, fz);
        float n = Perlin(ix, iz, fx, fz, octSeed[16u + (salt - 1u) * 3u + o], 1u);
        sum += amp * max(-1.0f, min(1.0f, n));
        norm += amp;
        amp *= 0.5f;
    }
    return sum / norm;
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    float warpX = 0.0f;
    float warpZ = 0.0f;
    if (P.warp > 0.0f)
    {
        warpX = WarpNoise(1u, x, z, 0.0f, 0.0f) * P.warp;
        warpZ = WarpNoise(2u, x, z, 0.0f, 0.0f) * P.warp;
        if (P.warpLevels >= 2u)
        {
            float px = warpX * 0.8f;
            float pz = warpZ * 0.8f;
            warpX = WarpNoise(3u, x, z, px, pz) * P.warp;
            warpZ = WarpNoise(4u, x, z, px, pz) * P.warp;
        }
    }
    bool erosive = P.style == 1u;
    float sum = 0.0f;
    float weight = 1.0f;
    float accX = 0.0f;
    float accZ = 0.0f;
    float accAmp = 0.0f;
    float eroX = 0.0f;
    float eroZ = 0.0f;
    float eroAmp = 0.0f;
    LOOP for (uint o = 0u; o < P.octaves; ++o)
    {
        uint b = o * 16u;
        float move = oct[b + 9u];
        float sdx = warpX * move;
        float sdz = warpZ * move;
        float du = (oct[b + 4u] * sdx + oct[b + 5u] * sdz) * P.invCell;
        float dv = (oct[b + 6u] * sdx + oct[b + 7u] * sdz) * P.invCell;
        int ix = 0;
        int iz = 0;
        float fx = 0.0f;
        float fz = 0.0f;
        LatticePoint(oct[b], oct[b + 1u], oct[b + 2u] + du, oct[b + 3u] + dv, oct[b + 4u], oct[b + 5u], oct[b + 6u], oct[b + 7u], x, z, ix, iz, fx, fz);
        float dnx = 0.0f;
        float dnz = 0.0f;
        float n = PerlinD(ix, iz, fx, fz, octSeed[o], 1u, dnx, dnz);
        n = max(-1.0f, min(1.0f, n));
        float rc = oct[b + 10u];
        float rs = oct[b + 11u];
        float gx = rc * dnx + rs * dnz;
        float gz = -rs * dnx + rc * dnz;
        float nominal = oct[b + 8u];
        float amp = nominal;
        if (P.slopeDetail != 0.0f && o > 0u && accAmp > 0.0f)
        {
            float steep = sqrt(accX * accX + accZ * accZ) / accAmp;
            float f = saturate(steep * 0.6f);
            amp *= max(0.0f, 1.0f + P.slopeDetail * (2.0f * f - 1.0f));
        }
        if (erosive && o > 0u && eroAmp > 0.0f)
        {
            float steep2 = (eroX * eroX + eroZ * eroZ) / (eroAmp * eroAmp);
            amp /= 1.0f + P.erosion * steep2;
        }
        amp *= oct[b + 13u];
        float signal = n;
        float sgx = gx;
        float sgz = gz;
        if (P.kind == 1u)
        {
            signal = 2.0f * (abs(n) - 0.25f);
            if (erosive)
            {
                float sg = n < 0.0f ? -2.0f : 2.0f;
                sgx *= sg;
                sgz *= sg;
            }
        }
        else if (P.kind == 2u)
        {
            float r0 = 1.0f - abs(n);
            float r = r0 * r0;
            if (P.sharp != 2.0f) r = pow(r0, P.sharp);
            if (erosive)
            {
                float rd = r0;
                if (P.sharp != 2.0f) rd = pow(max(r0, 0.000001f), P.sharp - 1.0f);
                float dr = -P.sharp * rd * (n < 0.0f ? -1.0f : 1.0f) * 2.0f * weight;
                sgx *= dr;
                sgz *= dr;
            }
            r *= weight;
            weight = saturate(r * 2.0f);
            signal = 2.0f * r - 1.0f;
        }
        sum += signal * amp;
        float k = oct[b + 12u];
        accX += nominal * gx * k;
        accZ += nominal * gz * k;
        accAmp += nominal;
        if (erosive)
        {
            eroX += nominal * sgx * k;
            eroZ += nominal * sgz * k;
            eroAmp += nominal;
        }
    }
    float v = sum / P.norm * P.fit;
    dst[row * P.w + dtid.x] = 0.5f + 0.5f * v / (1.0f + abs(v));
}
