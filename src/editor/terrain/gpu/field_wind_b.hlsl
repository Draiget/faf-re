// Op erode_wind (EdFieldEro2.cpp OpWind), the update pass of one step: the abraded rock becomes sand (rock -= take, wear += take, in place), then the sand is carried one step downwind,
// conservatively: next = sand - (|wx| + |wz|) * vel * sand + what the upwind neighbours (x - sign(wx), z - sign(wz)) send; nothing enters from outside the field. `sand` is the sand
// before the abrasion, the abraded amount is added here (the same sum the CPU op stores).
#include "common.hlsli"
#include "field_wind_params.hlsli"

CBUFFER(WindParams, P, 0)
SRV_BUFFER(float, sand, 0)
SRV_BUFFER(float, take, 1)
SRV_BUFFER(float, vel, 2)
UAV_BUFFER(float, nxt, 0)
UAV_BUFFER(float, rock, 1)
UAV_BUFFER(float, wear, 2)

FN float SandAt(uint j)
{
    return sand[j] + take[j];
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
    float inflow = 0.0f;
    int ux = P.windx > 0.0f ? x - 1 : x + 1;
    int uz = P.windz > 0.0f ? z - 1 : z + 1;
    if (P.awx > 0.0f && ux >= 0 && ux < w)
    {
        uint j = uint(z) * P.w + uint(ux);
        inflow += P.awx * vel[j] * SandAt(j);
    }
    if (P.awz > 0.0f && uz >= 0 && uz < h)
    {
        uint j = uint(uz) * P.w + uint(x);
        inflow += P.awz * vel[j] * SandAt(j);
    }
    float s = SandAt(i);
    nxt[i] = s - (P.awx + P.awz) * vel[i] * s + inflow;
    rock[i] = rock[i] - take[i];
    wear[i] = wear[i] + take[i];
}
