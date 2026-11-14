// Op wetness, step 2: the order in which a tile of 32 x 32 samples is worked through. One group per tile, one thread per sample; every thread counts the samples of its tile that stand
// higher (equal heights: the lower index first) and so finds its rank. order[tile * 1024 + rank] = the sample's index inside the tile (y * 32 + x). Samples past the field's edge sort last.
// (A rank sort of 1024 keys is 1M comparisons per tile; it is done once per op.)
#include "field_wet_params.hlsli"

CBUFFER(WetParams, P, 0)
SRV_BUFFER(float, hgt, 0)
UAV_BUFFER(uint, order, 0)
GROUPSHARED(float, keys, 1024)

NUMTHREADS(1024, 1, 1)
void CSMain(KERNEL_IDS)
{
    PHASES_BEGIN
    uint tile = gid.x + P.tile0;
    uint tx = tile % P.tilesX;
    uint tz = tile / P.tilesX;
    uint x = tx * 32u + (gtid.x & 31u);
    uint z = tz * 32u + (gtid.x >> 5u);
    float key = -3.0e38f;
    if (x < P.w && z < P.h) key = hgt[z * P.w + x];
    keys[gtid.x] = key;
    BARRIER(0);
    uint tile2 = gid.x + P.tile0;
    float mine = keys[gtid.x];
    uint rank = 0u;
    LOOP for (uint j = 0u; j < 1024u; ++j)
    {
        float kj = keys[j];
        if (kj > mine || (kj == mine && j < gtid.x)) rank += 1u;
    }
    if (tile2 < P.tilesX * P.tilesZ) order[tile2 * 1024u + rank] = gtid.x;
    PHASES_END
}
