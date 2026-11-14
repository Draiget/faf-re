// Droplet erosion (Beyer / Lague, the CPU RunDroplet of EdErosion.cpp), one thread per droplet. A droplet starts at a random place, steers on the bilinear gradient of the steering surface hs
// (the pit filled terrain) with inertia, picks up sediment where it is fast on a slope and drops it where it slows down or climbs. Everything it digs or drops goes into integer buffers with
// atomic adds (fixed point, 1/65536 unit): the ground it sees is the round's start height plus that accumulated change, which other droplets are changing at the same time (no order, no
// determinism: the editor does not need it). erosion_drop_resolve adds the integers to the float fields between rounds.
//   dig      a cone shaped brush of radius R cells (weights R + 0.5 - distance, normalised, reflected at the map edge), times the rock factor, at most roundCut below the steering surface
//   drop     bilinear on the four samples around the droplet, never above the spill surface plus a hair
//   random   a hash of (seed, round, droplet number): the start place, the release test and, with dropVary, the droplet's own size, life, inertia, load, dissolving rate and water
#include "common.hlsli"
#include "erosion_drop_params.hlsli"

CBUFFER(ErodeDropParams, P, 0)
SRV_BUFFER(float, hs, 0)
SRV_BUFFER(float, tb, 1)
SRV_BUFFER(float, accept, 2)
SRV_BUFFER(float, rock, 3)
SRV_BUFFER(float, soft, 4)
UAV_BUFFER(int, dq, 0)
UAV_BUFFER(int, wq, 1)
UAV_BUFFER(int, pq, 2)
UAV_BUFFER(int, fq, 3)

FN float Rand(INOUT(uint) s)
{
    s += 0x9E3779B9u;
    return HashToUnit(Hash32(s));
}

// the ground now: the round's start height plus the change made so far
FN float Ground(uint idx)
{
    return tb[idx] + float(dq[idx]) * (1.0f / EROSION_DROP_SCALE);
}

// mirror boundary: -1 -> 1, n -> n - 2; -1 when even that falls outside (a tiny map)
FN int Reflect(int i, int n)
{
    int r = i;
    if (r < 0) r = -r;
    if (r > n - 1) r = 2 * (n - 1) - r;
    if (r < 0 || r > n - 1) return -1;
    return r;
}

// drops `amount` on the four samples around (fx, fz) of cell i00, bilinear, never above the spill surface plus a hair; returns what was dropped
FN float Settle(uint i00, float fx, float fz, float amount, uint w, float cell, uint track)
{
    if (amount <= 0.0f) return 0.0f;
    float done = 0.0f;
    UNROLL for (int k = 0; k < 4; ++k)
    {
        uint idx = i00;
        float wgt = (1.0f - fx) * (1.0f - fz);
        if (k == 1) { idx = i00 + 1u; wgt = fx * (1.0f - fz); }
        if (k == 2) { idx = i00 + w; wgt = (1.0f - fx) * fz; }
        if (k == 3) { idx = i00 + w + 1u; wgt = fx * fz; }
        float room = max(0.0f, hs[idx] - Ground(idx) + 0.02f * cell);
        float a = min(amount * wgt, room);
        int aq = int(a * EROSION_DROP_SCALE + 0.5f);
        if (aq > 0)
        {
            InterlockedAdd(dq[idx], aq);
            if (track != 0u) InterlockedAdd(pq[idx], aq);
            done += float(aq) * (1.0f / EROSION_DROP_SCALE);
        }
    }
    return done;
}

FN float BrushSum(int R)
{
    float wsum = 0.0f;
    for (int oz = -R; oz <= R; ++oz)
    {
        for (int ox = -R; ox <= R; ++ox)
        {
            float d = sqrt(float(ox * ox + oz * oz));
            if (d < float(R) + 0.5f) wsum += float(R) + 0.5f - d;
        }
    }
    return wsum;
}

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    uint lid = dtid.y * P.gw + dtid.x;
    if (dtid.x >= P.gw || lid >= P.count) return;
    uint id = P.idOffset + lid;
    int w = int(P.w);
    int h = int(P.h);
    uint rs = Hash32(P.seed * 0x9E3779B1u + P.roundNo * 0x85EBCA6Bu + id * 0xC2B2AE35u + 0x27D4EB2Fu);
    float x0 = Rand(rs) * float(w - 1);
    float z0 = Rand(rs) * float(h - 1);
    if ((P.flags & 1u) != 0u)
    {
        float u = Rand(rs);
        if (u > accept[uint(int(z0 + 0.5f)) * P.w + uint(int(x0 + 0.5f))]) return;
    }
    uint track = (P.flags & 8u) != 0u ? 1u : 0u;
    float inertia = P.inertia;
    float capacityK = P.capacity;
    float erodeK = P.erode;
    float waterK = P.water;
    int R = int(P.radius);
    int lifetime = int(P.lifetime);
    if ((P.flags & 16u) != 0u)
    {
        float u = P.dropVary;
        float s0 = Rand(rs) * 2.0f - 1.0f;
        R = max(1, min(12, int(floor(float(P.radius) * (1.0f + u * s0) + 0.5f))));
        float s1 = Rand(rs) * 2.0f - 1.0f;
        lifetime = max(1, min(int(P.maxLife), int(floor(float(P.lifetime) * (1.0f + 0.4f * u * s1) + 0.5f))));
        float s2 = Rand(rs) * 2.0f - 1.0f;
        inertia = saturate(min(0.95f, P.inertia * (1.0f + u * s2)));
        float s3 = Rand(rs) * 2.0f - 1.0f;
        capacityK = P.capacity * (1.0f + 0.6f * u * s3);
        float s4 = Rand(rs) * 2.0f - 1.0f;
        erodeK = P.erode * (1.0f + 0.4f * u * s4);
        float s5 = Rand(rs) * 2.0f - 1.0f;
        waterK = P.water * (1.0f + 0.5f * u * s5);
    }
    float px = x0;
    float pz = z0;
    float dx = 0.0f;
    float dz = 0.0f;
    float speed = P.speed;
    float water = waterK;
    float sediment = 0.0f;
    float wsum = BrushSum(R);
    float cell = P.cell;
    LOOP for (int life = 0; life < lifetime; ++life)
    {
        int ix = int(px);
        int iz = int(pz);
        if (ix < 0 || iz < 0 || ix >= w - 1 || iz >= h - 1) break;
        float fx = px - float(ix);
        float fz = pz - float(iz);
        uint i00 = uint(iz) * P.w + uint(ix);
        float h00 = hs[i00];
        float h10 = hs[i00 + 1u];
        float h01 = hs[i00 + P.w];
        float h11 = hs[i00 + P.w + 1u];
        float gx = ((h10 - h00) * (1.0f - fz) + (h11 - h01) * fz) / cell;
        float gz = ((h01 - h00) * (1.0f - fx) + (h11 - h10) * fx) / cell;
        float height = h00 * (1.0f - fx) * (1.0f - fz) + h10 * fx * (1.0f - fz) + h01 * (1.0f - fx) * fz + h11 * fx * fz;
        dx = dx * inertia - gx * (1.0f - inertia);
        dz = dz * inertia - gz * (1.0f - inertia);
        float len = sqrt(dx * dx + dz * dz);
        if (len < 1e-6f)
        {
            float ang = Rand(rs) * 6.2831853f;
            dx = cos(ang);
            dz = sin(ang);
            len = 1.0f;
        }
        dx /= len;
        dz /= len;
        px += dx;
        pz += dz;
        int nx = int(px);
        int nz = int(pz);
        if (px < 0.0f || pz < 0.0f || nx >= w - 1 || nz >= h - 1) return;      // runs off the map with its sediment
        float ex = px - float(nx);
        float ez = pz - float(nz);
        uint j = uint(nz) * P.w + uint(nx);
        float newHeight = hs[j] * (1.0f - ex) * (1.0f - ez) + hs[j + 1u] * ex * (1.0f - ez) + hs[j + P.w] * (1.0f - ex) * ez + hs[j + P.w + 1u] * ex * ez;
        float dh = newHeight - height;
        float cap = max(-dh, P.minSlope * cell) * speed * water * capacityK;
        if (track != 0u) InterlockedAdd(fq[i00], int(water * EROSION_FLOW_SCALE + 0.5f));
        if (sediment > cap || dh > 0.0f)
        {
            float amount = (sediment - cap) * P.deposit;
            if (dh > 0.0f) amount = min(dh, sediment);
            sediment -= Settle(i00, fx, fz, amount, P.w, cell, track);
        }
        else
        {
            float amount = min((cap - sediment) * erodeK, -dh);
            // inside a filled basin the droplet runs on the spill surface above the real ground: nothing to dissolve there
            float ground = Ground(i00) * (1.0f - fx) * (1.0f - fz) + Ground(i00 + 1u) * fx * (1.0f - fz) + Ground(i00 + P.w) * (1.0f - fx) * fz + Ground(i00 + P.w + 1u) * fx * fz;
            if (height - ground > 0.03f * cell || life < 2) amount = 0.0f;
            if (amount > 0.0f && (P.flags & 4u) != 0u) amount *= soft[i00];
            if (amount > 0.0f && wsum > 0.0f)
            {
                float taken = 0.0f;
                for (int oz = -R; oz <= R; ++oz)
                {
                    for (int ox = -R; ox <= R; ++ox)
                    {
                        float d = sqrt(float(ox * ox + oz * oz));
                        if (d < float(R) + 0.5f)
                        {
                            int cx = Reflect(ix + ox, w);
                            int cz = Reflect(iz + oz, h);
                            if (cx >= 0 && cz >= 0)
                            {
                                uint jj = uint(cz) * P.w + uint(cx);
                                float kr = 1.0f;
                                if ((P.flags & 2u) != 0u) kr = saturate(rock[jj]);
                                float a = min(amount * (float(R) + 0.5f - d) / wsum * kr, max(0.0f, Ground(jj) - (hs[jj] - P.roundCut * cell)));
                                int aq = int(a * EROSION_DROP_SCALE + 0.5f);
                                if (aq > 0)
                                {
                                    InterlockedAdd(dq[jj], -aq);
                                    if (track != 0u) InterlockedAdd(wq[jj], aq);
                                    taken += float(aq) * (1.0f / EROSION_DROP_SCALE);
                                }
                            }
                        }
                    }
                }
                sediment += taken;
            }
        }
        // accel 1: speeds up going down (v^2 grows by the drop times gravity); accel 0 is the old rule (slows down going down)
        speed = sqrt(max(0.0f, speed * speed + dh * P.gravity / cell * (1.0f - 2.0f * P.accel)));
        water *= 1.0f - P.evaporate;
    }
    // the rest settles where the droplet stopped
    if (sediment > 0.0f)
    {
        int ix = max(0, min(w - 2, int(px)));
        int iz = max(0, min(h - 2, int(pz)));
        Settle(uint(iz) * P.w + uint(ix), px - float(ix), pz - float(iz), sediment, P.w, cell, track);
    }
}
