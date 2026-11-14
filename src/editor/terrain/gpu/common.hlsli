// Helpers every kernel may use. Plain functions and constants only (this file is compiled as HLSL and as C++ by the test shim). Include it with #include "common.hlsli".
#ifndef GPU_COMMON_HLSLI
#define GPU_COMMON_HLSLI

// Row-major index of sample (x, z) in a field of width w.
FN uint FieldIndex(uint x, uint z, uint w)
{
    return z * w + x;
}

// Integer clamp of a lookup coordinate to 0..n-1 (the CPU ops' "clamp" edge mode).
FN int ClampIndex(int i, int n)
{
    return max(0, min(n - 1, i));
}

// 32 bit integer hash (lowbias32): equal bits on the CPU and on the GPU.
FN uint Hash32(uint x)
{
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

// A hash as a float in 0..1 (24 bit steps, exact in float32).
FN float HashToUnit(uint h)
{
    return float(h >> 8) * (1.0f / 16777216.0f);
}

#endif
