// Op craters (EdFieldGen.cpp OpCraters): a scatter of impact craters (bowl + raised rim), one candidate crater per lattice cell and its eight neighbours. oct record 0 = the cell lattice map.
#include "gen_noise.hlsli"
#include "gen_craters_params.hlsli"

CBUFFER(CratersParams, P, 0)
SRV_BUFFER(float, oct, 1)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    int cx = 0;
    int cz = 0;
    float lx = 0.0f;
    float lz = 0.0f;
    LatticePoint(oct[0], oct[1], oct[2], oct[3], oct[4], oct[5], oct[6], oct[7], float(dtid.x), float(row), cx, cz, lx, lz);
    float sum = 0.0f;
    UNROLL for (int dz = -1; dz <= 1; ++dz)
    {
        UNROLL for (int dx = -1; dx <= 1; ++dx)
        {
            uint h = Hash2i(cx + dx, cz + dz, P.seed);
            if (HashToUnit(h) <= P.density)
            {
                float rr = P.rmin + (P.rmax - P.rmin) * HashToUnit(Hash32(h ^ 0x1234567u));
                float fxp = rr + (1.0f - 2.0f * rr) * HashToUnit(Hash32(h ^ 0x9E3779B9u));
                float fzp = rr + (1.0f - 2.0f * rr) * HashToUnit(Hash32(h ^ 0x7F4A7C15u));
                float ex = float(dx) + fxp - lx;
                float ez = float(dz) + fzp - lz;
                float r = sqrt(ex * ex + ez * ez) / rr;
                if (r <= 2.2f)
                {
                    float d = P.depth * (rr / P.rmax) * (0.7f + 0.3f * HashToUnit(Hash32(h ^ 0x2545F491u)));
                    float v = 0.0f;
                    if (r < 1.0f) v -= d * pow(1.0f - r * r, P.shape);
                    float t = (r - 1.0f) / 0.3f;
                    v += d * P.rim * exp(-t * t);
                    sum += v;
                }
            }
        }
    }
    dst[row * P.w + dtid.x] = saturate(P.base + sum);
}
