// Op erode_wind (EdFieldEro2.cpp OpWind), the read-only pass of one step: from the surface (rock + sand) the slope along the wind, the rock abraded where sand is thin and the wind blows
// uphill (take) and the carrying speed (vel). Pass B applies and transports.
#include "filt_common.hlsli"
#include "field_wind_params.hlsli"

CBUFFER(WindParams, P, 0)
SRV_BUFFER(float, rock, 0)
SRV_BUFFER(float, sand, 1)
UAV_BUFFER(float, take, 0)
UAV_BUFFER(float, vel, 1)

FN float Surf(int x, int z)
{
    uint j = uint(z) * P.w + uint(x);
    return rock[j] + sand[j];
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint i = dtid.y * P.w + dtid.x;
    int xl = max(0, x - 1);
    int xr = min(w - 1, x + 1);
    int zu = max(0, z - 1);
    int zd = min(h - 1, z + 1);
    float gx = (Surf(xr, z) - Surf(xl, z)) / (2.0f * P.cell);
    float gz = (Surf(x, zd) - Surf(x, zu)) / (2.0f * P.cell);
    float ds = gx * P.windx + gz * P.windz;
    float up = max(0.0f, ds);
    float bare = 1.0f - SmoothStep(0.0f, 0.5f, sand[i]);
    take[i] = min(P.abrade * up * bare, P.abrade);
    vel[i] = P.speed * saturate(1.0f - P.drag * up);
}
