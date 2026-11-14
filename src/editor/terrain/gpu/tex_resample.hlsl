// dst(x, z) = bilinear sample of the source texture at the centre of destination sample (x, z) (texture coordinates (x + 0.5) / size). The template for kernels that sample
// a texture (noise lookups, advection); also a selftest of the sampler. The output is a field (structured buffer).
#include "field_params.hlsli"

CBUFFER(FieldParams, P, 0)
SRV_TEX(tex, 0)
SAMPLER(linearClamp, 0)
UAV_BUFFER(float, dst, 0)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    float2 uv = float2((float(dtid.x) + 0.5f) / float(P.w), (float(dtid.y) + 0.5f) / float(P.h));
    dst[dtid.y * P.w + dtid.x] = tex.SampleLevel(linearClamp, uv, 0.0f);
}
