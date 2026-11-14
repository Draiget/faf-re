// Op convolve (EdFieldFilt.cpp OpConvolve): out(x, z) = bias + mul * sum over the n x n kernel of k[j * n + i] * src(x + i - r, z + j - r), edges clamp / wrap / mirror. The taps are added
// in the CPU op's order (rows j outside, i inside), so the result matches it bit for bit when the compiler does not fuse multiply and add.
#include "common.hlsli"
#include "field_convolve_params.hlsli"

CBUFFER(ConvolveParams, P, 0)
SRV_BUFFER(float, src, 0)
SRV_BUFFER(float, kern, 1)
UAV_BUFFER(float, dst, 0)

FN int WrapIdx(int i, int n)
{
    int m = i % n;
    return m < 0 ? m + n : m;
}

FN int EdgeIdx(int i, int n)
{
    if (P.edge == 1u) return WrapIdx(i, n);
    if (P.edge == 2u)
    {
        if (n == 1) return 0;
        int period = 2 * (n - 1);
        int m = WrapIdx(i, period);
        return m < n ? m : period - m;
    }
    return i < 0 ? 0 : (i >= n ? n - 1 : i);
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    int w = int(P.w);
    int h = int(P.h);
    int n = int(P.n);
    int r = n / 2;
    float acc = 0.0f;
    LOOP for (int j = 0; j < n; ++j)
    {
        int zz = EdgeIdx(z + j - r, h);
        LOOP for (int i = 0; i < n; ++i)
        {
            int xx = EdgeIdx(x + i - r, w);
            acc += kern[j * n + i] * src[uint(zz) * P.w + uint(xx)];
        }
    }
    dst[uint(z) * P.w + uint(x)] = acc * P.mul + P.bias;
}
