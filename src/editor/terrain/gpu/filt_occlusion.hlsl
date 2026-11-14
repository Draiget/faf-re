// Op occlusion (EdFieldFilt.cpp OpOcclusion): ambient occlusion of the surface. For every sample the horizon is searched along `dirs` directions, `steps` taps each (denser close to the point):
// the largest rise (concave: cavities) and drop (convex: exposed ridges) per run. The costliest filter of the field engine (dirs * steps bilinear taps per sample).
// Tables: ray (t1): the tap distances in samples, then cos and sin of the directions; src (t2): the field.
#include "filt_common.hlsli"
#include "filt_occlusion_params.hlsli"

CBUFFER(OcclusionParams, P, 0)
SRV_BUFFER(float, ray, 1)
SRV_BUFFER(float, src, 2)
UAV_BUFFER(float, dst, 0)

DEFINE_BILINEAR_C(src)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.rows) return;
    uint row = dtid.y + P.z0;
    float x = float(dtid.x);
    float z = float(row);
    float c = src[row * P.w + dtid.x];
    float occConcave = 0.0f;
    float occConvex = 0.0f;
    LOOP for (uint d = 0u; d < P.dirs; ++d)
    {
        float cs = ray[P.steps + d];
        float sn = ray[P.steps + P.dirs + d];
        float up = 0.0f;
        float down = 0.0f;
        LOOP for (uint s = 0u; s < P.steps; ++s)
        {
            float dsm = ray[s];
            float v = BilinearC(x + cs * dsm, z + sn * dsm);
            float tg = (v - c) / (dsm * P.cell);
            up = max(up, tg);
            down = max(down, -tg);
        }
        occConcave += up / sqrt(1.0f + up * up);
        occConvex += down / sqrt(1.0f + down * down);
    }
    occConcave /= float(P.dirs);
    occConvex /= float(P.dirs);
    float r = 0.0f;
    if (P.mode == 0u) r = saturate(occConcave * P.gain);
    else if (P.mode == 1u) r = saturate(occConvex * P.gain);
    else r = saturate(0.5f + 0.5f * (occConcave - occConvex) * P.gain);
    dst[row * P.w + dtid.x] = r;
}
