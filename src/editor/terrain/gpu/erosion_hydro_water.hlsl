// Hydraulic erosion, pass B: the water update from the pipe fluxes, the flow speed, then dissolving and settling of sediment.
//   water   d' = d + rain + inflow - outflow
//   speed   the vector sum of the unit directions of the in and out fluxes over the mean depth (cells per iteration), at most maxSpeed
//   slope   sin of the ground's slope (central differences); the capacity uses it limited above slopeCap (a plateau, then falling off on cliffs: steep faces do not dominate) and floored at minSlope
//   cap     capacity * slope * speed^speedPow * min(1, depth / depth_max); no dissolving below the speed threshold vThresh
//   dig     erosion * rock * (cap - s) (at most cutLimit of the drop to the lowest of the eight neighbours), or settle deposition * (s - cap)
// The sediment itself moves in pass C. Outputs: the change of the ground (dT = dissolved - settled, which erosion_hydro_apply spreads over the neighbourhood and subtracts), the water (D, in
// place), the sediment after dissolving / settling (SN) and the water before the update (DO, which pass C divides by).
#include "common.hlsli"
#include "erosion_hydro_params.hlsli"
#include "erosion_common.hlsli"

CBUFFER(ErodeHydroParams, P, 0)
SRV_BUFFER(float, T, 0)
SRV_BUFFER(float, Fa, 1)
SRV_BUFFER(float, Fb, 2)
SRV_BUFFER(float, rainMap, 3)
SRV_BUFFER(float, rock, 4)
SRV_BUFFER(float, S, 5)
UAV_BUFFER(float, dT, 0)
UAV_BUFFER(float, D, 1)
UAV_BUFFER(float, SN, 2)
UAV_BUFFER(float, DO, 3)
UAV_BUFFER(float, wear, 4)
UAV_BUFFER(float, dep, 5)
UAV_BUFFER(float, flow, 6)

FN float FluxOf(uint cellIndex, uint n, int k)
{
    if (k < 4) return Fa[uint(k) * n + cellIndex];
    return Fb[uint(k - 4) * n + cellIndex];
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint n = P.w * P.h;
    uint i = dtid.y * P.w + dtid.x;
    bool pinned = (P.flags & 8u) != 0u && (x == 0 || z == 0 || x == w - 1 || z == h - 1);
    if (pinned)
    {
        dT[i] = 0.0f;
        SN[i] = 0.0f;
        DO[i] = 0.0f;
        D[i] = 0.0f;
        return;
    }
    float rm = 1.0f;
    if ((P.flags & 1u) != 0u) rm = rainMap[i];
    float dOld = D[i] + RainAmount(i, rm, P.rain, P.rainNoise, P.seed, P.iter);
    float outSum = 0.0f;
    float inSum = 0.0f;
    float ux = 0.0f;
    float uz = 0.0f;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        float fo = FluxOf(i, n, k);
        float fi = 0.0f;
        int nx = x + kDirX[k];
        int nz = z + kDirZ[k];
        if (nx >= 0 && nz >= 0 && nx < w && nz < h) fi = FluxOf(uint(nz) * P.w + uint(nx), n, kDirOpp[k]);
        outSum += fo;
        inSum += fi;
        float len = DirLen(k);
        ux += float(kDirX[k]) * len * (fo - fi);
        uz += float(kDirZ[k]) * len * (fo - fi);
    }
    float dNew = max(0.0f, dOld + inSum - outSum);
    float dm = 0.5f * (dOld + dNew);
    float inv = 0.5f / max(dm, P.velFloor);
    ux *= inv;
    uz *= inv;
    float speed = sqrt(ux * ux + uz * uz);
    if (speed > P.maxSpeed) speed = P.maxSpeed;
    D[i] = dNew;
    DO[i] = dOld;
    // slope from the ground at the start of the pass
    int xl = max(x - 1, 0);
    int xr = min(x + 1, w - 1);
    int zu = max(z - 1, 0);
    int zd = min(z + 1, h - 1);
    float gx = (T[uint(z) * P.w + uint(xr)] - T[uint(z) * P.w + uint(xl)]) / (float(xr - xl) * P.cell);
    float gz = (T[uint(zd) * P.w + uint(x)] - T[uint(zu) * P.w + uint(x)]) / (float(zd - zu) * P.cell);
    float g = sqrt(gx * gx + gz * gz);
    float sinA = g / sqrt(1.0f + g * g);
    float sr = sinA / P.slopeCap;
    float soft = sinA / sqrt(1.0f + sr * sr * sr * sr);      // ~ sinA below slopeCap, a plateau above it, falling off again on cliffs
    float tilt = max(soft, P.minSlope);
    float sp = speed;
    if (P.speedPow != 1.0f) sp = pow(max(speed, 1e-6f), P.speedPow);
    float stress = min(P.rampMax, dNew * P.invDepthMax) * tilt;
    float cap = P.capacity * sp * max(0.0f, stress - P.tauC);
    if (speed < P.vThresh) cap = 0.0f;
    float ti = T[i];
    float s0 = S[i];
    float erode = 0.0f;
    float deposit = 0.0f;
    if (cap > s0)
    {
        float kr = P.erosion;
        if ((P.flags & 2u) != 0u) kr *= rock[i];
        erode = kr * (cap - s0);
        if (P.cutLimit > 0.0f)
        {
            float low = ti;
            UNROLL for (int k = 0; k < 8; ++k)
            {
                int nx = x + kDirX[k];
                int nz = z + kDirZ[k];
                if (nx >= 0 && nz >= 0 && nx < w && nz < h) low = min(low, T[uint(nz) * P.w + uint(nx)]);
            }
            erode = min(erode, P.cutLimit * (ti - low));
        }
        erode = max(0.0f, erode);
    }
    else
    {
        deposit = P.deposition * (s0 - cap);
    }
    dT[i] = erode - deposit;
    SN[i] = s0 + erode - deposit;
    if ((P.flags & 16u) != 0u)
    {
        wear[i] += erode;
        dep[i] += deposit;
        flow[i] += speed * dNew;
    }
}
