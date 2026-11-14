// Op diffuse (EdFieldFilt.cpp OpDiffuse): one iteration of Perona-Malik anisotropic diffusion, next = cur + rate * sum of the conductance weighted differences to the four neighbours
// (smooths flat ground, keeps cliffs). The host runs it `iterations` times over a ping-pong pair of fields.
#include "filt_common.hlsli"
#include "filt_diffuse_params.hlsli"

CBUFFER(DiffuseParams, P, 0)
SRV_BUFFER(float, cur, 1)
SRV_BUFFER(float, mask, 2)
UAV_BUFFER(float, nxt, 0)

FN float Cond(float diff)
{
    float g = diff * P.invCell;
    float t = g * g * P.invK2;
    return P.expo != 0u ? exp(-t) : 1.0f / (1.0f + t);
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    int x = int(dtid.x);
    int z = int(dtid.y + P.z0);
    uint i = uint(z) * P.w + uint(x);
    float c = cur[i];
    float flux = 0.0f;
    if (x > 0)
    {
        float d = cur[i - 1u] - c;
        flux += Cond(d) * d;
    }
    if (x < int(P.w) - 1)
    {
        float d = cur[i + 1u] - c;
        flux += Cond(d) * d;
    }
    if (z > 0)
    {
        float d = cur[i - P.w] - c;
        flux += Cond(d) * d;
    }
    if (z < int(P.h) - 1)
    {
        float d = cur[i + P.w] - c;
        flux += Cond(d) * d;
    }
    float r = P.rate;
    if (P.hasMask != 0u) r *= saturate(mask[i]);
    nxt[i] = c + r * flux;
}
