// Helpers of the erosion kernels: the eight pipe directions, the rain at a cell.
#ifndef GPU_EROSION_COMMON_HLSLI
#define GPU_EROSION_COMMON_HLSLI

#include "common.hlsli"

// directions 0..3 = -x +x -z +z (flux buffer Fa), 4..7 = (-1,-1) (+1,-1) (-1,+1) (+1,+1) (flux buffer Fb); the flux buffers hold the planes k * cells + cell
static const int kDirX[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kDirZ[8] = {0, 0, -1, 1, -1, -1, 1, 1};
// the direction a neighbour's pipe has back to us
static const int kDirOpp[8] = {1, 0, 3, 2, 7, 6, 5, 4};

FN float DirLen(int k)
{
    return k < 4 ? 1.0f : 0.70710678f;   // the unit length share of a lattice step: the speed is a vector sum of unit vectors
}

// the rain of one cell in one iteration: depth * map * (1 + amplitude * white noise of (cell, seed, iteration / 4))
FN float RainAmount(uint i, float mapValue, float rain, float amplitude, uint seed, uint iter)
{
    float r = rain * mapValue;
    if (amplitude > 0.0f)
    {
        uint hsh = Hash32(i * 747796405u + seed * 2891336453u + (iter >> 2) * 277803737u + 12345u);
        r *= 1.0f + amplitude * (2.0f * HashToUnit(hsh) - 1.0f);
    }
    return r;
}

#endif
