// Op dwarp (EdFieldGen.cpp OpDWarp): domain warp of the field `a`: every output sample is the field read at a displaced place (bilinear, edge clamp / wrap / mirror). The displacement is
// fbm noise (once or twice: a warp of a warp), a divergence free curl flow, a swirl, ripples or a pinch / bulge; an optional mask blends the result with the input.
// oct (t1): record 0 = map of the Fbm01 noise at `size` world units, record 1 = the same shifted by (17.3, -41.9) world units (second noise channel).
#include "gen_noise.hlsli"
#include "filt_common.hlsli"
#include "filt_dwarp_params.hlsli"

CBUFFER(DWarpParams, P, 0)
SRV_BUFFER(float, oct, 1)
SRV_BUFFER(float, src, 2)
SRV_BUFFER(float, mask, 3)
UAV_BUFFER(float, dst, 0)

FN int IndexOf(int i, int n)
{
    if (P.edge == 1u)
    {
        i = i % n;
        return i < 0 ? i + n : i;
    }
    if (P.edge == 2u)
    {
        if (n == 1) return 0;
        int period = 2 * (n - 1);
        i = i % period;
        i = i < 0 ? i + period : i;
        return i < n ? i : period - i;
    }
    return i < 0 ? 0 : (i >= n ? n - 1 : i);
}

FN float Fetch(int ix, int iz)
{
    return src[uint(IndexOf(iz, int(P.h))) * P.w + uint(IndexOf(ix, int(P.w)))];
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    float dx = 0.0f;
    float dz = 0.0f;
    int ix = 0;
    int iz = 0;
    float fx = 0.0f;
    float fz = 0.0f;
    if (P.kind == 0u)
    {
        float px = 0.0f;   // where the noise is read, relative to the sample (world units)
        float pz = 0.0f;
        LOOP for (uint it = 0u; it < P.iters; ++it)
        {
            LatticePoint(oct[0], oct[1], oct[2] + px * P.invSize, oct[3] + pz * P.invSize, oct[4], oct[5], oct[6], oct[7], x, z, ix, iz, fx, fz);
            float nx = 2.0f * Fbm01(ix, iz, fx, fz, P.seed, P.octaves, 0.5f) - 1.0f;
            LatticePoint(oct[16], oct[17], oct[18] + px * P.invSize, oct[19] + pz * P.invSize, oct[20], oct[21], oct[22], oct[23], x, z, ix, iz, fx, fz);
            float nz = 2.0f * Fbm01(ix, iz, fx, fz, P.seed + 1u, P.octaves, 0.5f) - 1.0f;
            dx = nx * P.strength;
            dz = nz * P.strength;
            px = dx * 0.8f;
            pz = dz * 0.8f;
        }
    }
    else if (P.kind == 1u)
    {
        LatticePoint(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7], x, z, ix, iz, fx, fz);
        float sx = 0.0f;
        float sz = 0.0f;
        float amp = 1.0f;
        float norm = 0.0f;
        float m = 1.0f;
        int mi = 1;
        LOOP for (uint o = 0u; o < P.octaves; ++o)
        {
            uint s = Hash32(P.seed * 131u + o * 7919u + 17u);
            float fU = fx * m;
            float fV = fz * m;
            float fl = floor(fU);
            float fm = floor(fV);
            float dnx = 0.0f;
            float dnz = 0.0f;
            float n = PerlinD(ix * mi + int(fl), iz * mi + int(fm), fU - fl, fV - fm, s, 0u, dnx, dnz);
            sx += amp * dnx;
            sz += amp * dnz;
            norm += amp;
            amp *= 0.5f;
            m *= 2.0f;
            mi *= 2;
        }
        dx = P.strength * 0.5f * (sz / norm);
        dz = -P.strength * 0.5f * (sx / norm);
    }
    else if (P.kind == 2u || P.kind == 4u)
    {
        float ex = P.e0x + x * P.cell;
        float ez = P.e0z + z * P.cell;
        float d = sqrt(ex * ex + ez * ez) / P.size;
        if (P.kind == 2u)
        {
            float rot = P.rotK * exp(-d * d);
            float c = cos(rot);
            float s = sin(rot);
            dx = ex * (c - 1.0f) - ez * s;
            dz = ex * s + ez * (c - 1.0f);
        }
        else
        {
            float f = 1.0f - P.strength * exp(-d * d);
            dx = ex * (f - 1.0f);
            dz = ez * (f - 1.0f);
        }
    }
    else
    {
        float sp = P.fu0 + P.pa * x + P.pb * z;
        float wave = sin(6.28318530717958647692f * sp + P.phase);
        dx = P.rx * P.strength * wave;
        dz = P.rz * P.strength * wave;
    }
    float gx = x + dx * P.invCell;
    float gz = z + dz * P.invCell;
    float fx0 = floor(gx);
    float fz0 = floor(gz);
    float tx = gx - fx0;
    float tz = gz - fz0;
    int bx = int(fx0);
    int bz = int(fz0);
    float a = Fetch(bx, bz);
    float b = Fetch(bx + 1, bz);
    float c2 = Fetch(bx, bz + 1);
    float d2 = Fetch(bx + 1, bz + 1);
    float top = a + (b - a) * tx;
    float bottom = c2 + (d2 - c2) * tx;
    float warped = top + (bottom - top) * tz;
    uint idx = row * P.w + dtid.x;
    if (P.hasMask != 0u) warped = src[idx] + (warped - src[idx]) * saturate(mask[idx]);
    dst[idx] = warped;
}
