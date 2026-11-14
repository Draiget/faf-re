// Op slope_limit (EdFieldSc.cpp OpSlopeLimit), the envelope of one direction: along every line (a row or a column of the field, one thread each) the lowest function below the input that
// rises at most `lim` per sample step: forward then backward sweep, c = min(c, previous + lim). The lower envelope of the whole field is the row scan followed by the column scan (the L1
// distance transform is separable), which is what the CPU op's two sweeps compute.
#include "common.hlsli"
#include "field_slopescan_params.hlsli"

CBUFFER(SlopeScanParams, P, 0)
SRV_BUFFER(float, src, 0)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(64, 1, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.lines) return;
    uint base = dtid.x * P.lineStride;
    float prev = 0.0f;
    LOOP for (uint k = 0u; k < P.len; ++k)
    {
        uint idx = base + k * P.stride;
        float v = src[idx] * P.inSign;
        if (k > 0u) v = min(v, prev + P.lim);
        dst[idx] = v;
        prev = v;
    }
    LOOP for (uint k2 = 1u; k2 < P.len; ++k2)
    {
        uint idx = base + (P.len - 1u - k2) * P.stride;
        float v = min(dst[idx], prev + P.lim);
        dst[idx] = v;
        prev = v;
    }
}
