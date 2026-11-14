// Ops voronoi (EdFieldCore.cpp OpVoronoi), cells (EdFieldGen.cpp OpCells: metrics and ten modes) and cracks (OpCracks: networks of cracks). Cellular noise: one feature point per lattice cell,
// searched in the neighbouring cells. oct table, 16 floats per record: 0..7 the affine map of the cell lattice at the level (records 0..2: levels of cracks / the one level of the others),
// 8 scale in world units of the level, 9 crack width in units, 10 weight; records 3 and 4 hold the maps of the two warp noises (Fbm01, see gen_noise.hlsli: octave 0 map).
#include "gen_noise.hlsli"
#include "gen_cells_params.hlsli"

CBUFFER(CellsParams, P, 0)
SRV_BUFFER(float, oct, 1)
UAV_BUFFER(float, dst, 0)

FN float SmoothStep(float e0, float e1, float v)
{
    if (e1 == e0) return v < e0 ? 0.0f : 1.0f;
    float t = saturate((v - e0) / (e1 - e0));
    return t * t * (3.0f - 2.0f * t);
}

FN float Metric(float ex, float ez)
{
    if (P.metric == 1u) return abs(ex) + abs(ez);
    if (P.metric == 2u) return max(abs(ex), abs(ez));
    if (P.metric == 3u) return pow(pow(abs(ex), P.pexp) + pow(abs(ez), P.pexp), 1.0f / P.pexp);
    return sqrt(ex * ex + ez * ez);
}

FN void FeaturePoint(int cx, int cz, uint seed, OUT(float) jx, OUT(float) jz, OUT(uint) h)
{
    h = Hash2i(cx, cz, seed);
    jx = 0.5f + (HashToUnit(h) - 0.5f) * P.jitter;
    jz = 0.5f + (HashToUnit(Hash32(h ^ 0x68E31DA4u)) - 0.5f) * P.jitter;
}

// Nearest three feature points with the chosen metric (EdFieldGen.cpp Nearest).
FN void Nearest(int cx, int cz, float lx, float lz, uint seed, int rng, OUT(float) f1, OUT(float) f2, OUT(float) f3, OUT(uint) id, OUT(float) hcx, OUT(float) hcz, OUT(float) soft)
{
    f1 = 1000000000.0f;
    f2 = 1000000000.0f;
    f3 = 1000000000.0f;
    id = 0u;
    hcx = 0.0f;
    hcz = 0.0f;
    soft = 0.0f;
    LOOP for (int dz = -rng; dz <= rng; ++dz)
    {
        LOOP for (int dx = -rng; dx <= rng; ++dx)
        {
            float jx = 0.0f;
            float jz = 0.0f;
            uint h = 0u;
            FeaturePoint(cx + dx, cz + dz, seed, jx, jz, h);
            float ex = float(dx) + jx - lx;
            float ez = float(dz) + jz - lz;
            float d = Metric(ex, ez);
            soft += exp(-P.ksoft * d);
            if (d < f1)
            {
                f3 = f2;
                f2 = f1;
                f1 = d;
                id = h;
                hcx = ex;
                hcz = ez;
            }
            else if (d < f2)
            {
                f3 = f2;
                f2 = d;
            }
            else if (d < f3)
            {
                f3 = d;
            }
        }
    }
}

// Exact distance (cell units) from the sample to the border of its Voronoi cell (EdFieldGen.cpp BorderDistance).
FN float BorderDistance(int cx, int cz, float lx, float lz, uint seed, float hcx, float hcz)
{
    float best = 1000000000.0f;
    LOOP for (int dz = -2; dz <= 2; ++dz)
    {
        LOOP for (int dx = -2; dx <= 2; ++dx)
        {
            float jx = 0.0f;
            float jz = 0.0f;
            uint h = 0u;
            FeaturePoint(cx + dx, cz + dz, seed, jx, jz, h);
            float ex = float(dx) + jx - lx;
            float ez = float(dz) + jz - lz;
            float rx = ex - hcx;
            float rz = ez - hcz;
            float len = sqrt(rx * rx + rz * rz);
            if (len >= 0.00001f)
            {
                float d = (0.5f * (hcx + ex) * rx + 0.5f * (hcz + ez) * rz) / len;
                best = min(best, d);
            }
        }
    }
    return best;
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    // domain warp of the world position (cells, cracks): two Fbm01 noises
    float dwx = 0.0f;
    float dwz = 0.0f;
    if (P.warpOn != 0u)
    {
        int ix = 0;
        int iz = 0;
        float fx = 0.0f;
        float fz = 0.0f;
        LatticePoint(oct[48], oct[49], oct[50], oct[51], oct[52], oct[53], oct[54], oct[55], x, z, ix, iz, fx, fz);
        float nx = Fbm01(ix, iz, fx, fz, P.seedA, P.warpOct, 0.5f);
        LatticePoint(oct[64], oct[65], oct[66], oct[67], oct[68], oct[69], oct[70], oct[71], x, z, ix, iz, fx, fz);
        float nz = Fbm01(ix, iz, fx, fz, P.seedB, P.warpOct, 0.5f);
        dwx = P.warp * (2.0f * nx - 1.0f);
        dwz = P.warp * (2.0f * nz - 1.0f);
    }
    float result = 0.0f;
    if (P.op == 2u)
    {
        float best = 0.0f;
        LOOP for (uint lv = 0u; lv < P.levels; ++lv)
        {
            uint b = lv * 16u;
            float sc = oct[b + 8u];
            int cx = 0;
            int cz = 0;
            float lx = 0.0f;
            float lz = 0.0f;
            LatticePoint(oct[b], oct[b + 1u], oct[b + 2u] + dwx / sc, oct[b + 3u] + dwz / sc, oct[b + 4u], oct[b + 5u], oct[b + 6u], oct[b + 7u], x, z, cx, cz, lx, lz);
            uint seed = P.seed + lv * 977u;
            float f1 = 0.0f;
            float f2 = 0.0f;
            float f3 = 0.0f;
            uint id = 0u;
            float hcx = 0.0f;
            float hcz = 0.0f;
            float soft = 0.0f;
            Nearest(cx, cz, lx, lz, seed, 1, f1, f2, f3, id, hcx, hcz, soft);
            float bd = BorderDistance(cx, cz, lx, lz, seed, hcx, hcz) * sc;
            float hw = oct[b + 9u] * 0.5f;
            float c = 0.0f;
            if (P.profile == 2u) c = bd < hw ? 1.0f : 0.0f;
            else if (P.profile == 1u) c = 1.0f - SmoothStep(hw * 0.6f, hw * 1.2f, bd);
            else c = saturate(1.0f - bd / max(hw, 0.001f));
            best = max(best, c * oct[b + 10u]);
        }
        result = saturate(best);
    }
    else
    {
        int cx = 0;
        int cz = 0;
        float lx = 0.0f;
        float lz = 0.0f;
        float sc = oct[8];
        LatticePoint(oct[0], oct[1], oct[2] + dwx / sc, oct[3] + dwz / sc, oct[4], oct[5], oct[6], oct[7], x, z, cx, cz, lx, lz);
        if (P.op == 0u)
        {
            float d1 = 1000000000.0f;
            float d2 = 1000000000.0f;
            uint id = 0u;
            LOOP for (int dz = -1; dz <= 1; ++dz)
            {
                LOOP for (int dx = -1; dx <= 1; ++dx)
                {
                    float jx = 0.0f;
                    float jz = 0.0f;
                    uint h = 0u;
                    FeaturePoint(cx + dx, cz + dz, P.seed, jx, jz, h);
                    float ex = float(dx) + jx - lx;
                    float ez = float(dz) + jz - lz;
                    float d = ex * ex + ez * ez;
                    if (d < d1)
                    {
                        d2 = d1;
                        d1 = d;
                        id = h;
                    }
                    else if (d < d2)
                    {
                        d2 = d;
                    }
                }
            }
            float f1 = sqrt(d1);
            float f2 = sqrt(d2);
            if (P.mode == 1u) result = saturate(f2);
            else if (P.mode == 2u) result = saturate(f2 - f1);
            else if (P.mode == 3u) result = HashToUnit(Hash32(id ^ 0xA511E9B3u));
            else if (P.mode == 4u) result = 1.0f - SmoothStep(0.0f, P.width, f2 - f1);
            else result = saturate(f1);
        }
        else
        {
            float f1 = 0.0f;
            float f2 = 0.0f;
            float f3 = 0.0f;
            uint id = 0u;
            float hcx = 0.0f;
            float hcz = 0.0f;
            float soft = 0.0f;
            Nearest(cx, cz, lx, lz, P.seed, int(P.range), f1, f2, f3, id, hcx, hcz, soft);
            uint m = P.mode;
            if (m == 0u) result = saturate(f1);
            else if (m == 1u) result = saturate(f2 * (1.0f / 1.4f));
            else if (m == 2u) result = saturate(f3 * (1.0f / 1.7f));
            else if (m == 3u) result = saturate(f2 - f1);
            else if (m == 4u) result = 1.0f - SmoothStep(0.0f, P.width, f2 - f1);
            else if (m == 5u) result = HashToUnit(Hash32(id ^ 0xA511E9B3u));
            else if (m == 6u) result = saturate(-log(max(soft, 1.0e-20f)) / P.ksoft);
            else if (m == 7u) result = saturate(2.0f * BorderDistance(cx, cz, lx, lz, P.seed, hcx, hcz));
            else if (m == 8u)
            {
                float bd = BorderDistance(cx, cz, lx, lz, P.seed, hcx, hcz);
                float level = HashToUnit(Hash32(id ^ 0xA511E9B3u));
                result = saturate(level * (1.0f - P.drop * (1.0f - SmoothStep(0.0f, P.bevel, bd))));
            }
            else
            {
                float level = HashToUnit(Hash32(id ^ 0xA511E9B3u));
                result = saturate(0.7f * level + 0.3f * (1.0f - saturate(f1)));
            }
        }
    }
    dst[row * P.w + dtid.x] = result;
}
