// Op bilateral (EdFieldFilt.cpp OpBilateral): edge preserving smooth. A window average weighted by the distance (table ws, (2r+1)^2 values) and by the height difference
// (Lorentzian 1 / (1 + (d / sigma_r)^2)). The order of the sums is the CPU's.
#include "filt_common.hlsli"
#include "filt_bilateral_params.hlsli"

CBUFFER(BilateralParams, P, 0)
SRV_BUFFER(float, ws, 1)
SRV_BUFFER(float, src, 2)
SRV_BUFFER(float, mask, 3)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    int r = int(P.rad);
    int n = 2 * r + 1;
    float c = src[uint(z) * P.w + uint(x)];
    float sum = 0.0f;
    float wsum = 0.0f;
    LOOP for (int dz = -r; dz <= r; ++dz)
    {
        int zz = z + dz;
        if (zz >= 0 && zz < int(P.h))
        {
            int x0 = max(0, x - r);
            int x1 = min(int(P.w) - 1, x + r);
            LOOP for (int xx = x0; xx <= x1; ++xx)
            {
                float v = src[uint(zz) * P.w + uint(xx)];
                float d = v - c;
                float wt = ws[(dz + r) * n + r + (xx - x)] / (1.0f + d * d * P.inv);
                sum += wt * v;
                wsum += wt;
            }
        }
    }
    float res = sum / wsum;
    if (P.hasMask != 0u)
    {
        float t = saturate(mask[uint(z) * P.w + uint(x)]);
        res = c + (res - c) * t;
    }
    dst[uint(z) * P.w + uint(x)] = res;
}
