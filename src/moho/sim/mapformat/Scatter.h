// Normative scatter placement of the Extended map format (docs/mapformat/EXTENDED.md, chunk SCAT).
// Every machine, build and tool (C++ reader, Python reference) must produce the same instances for the same layer
// and the same sampler answers. Nothing here uses <random>, libm transcendental functions or the clock.
//
// ===================================================================================== EXACT DERIVATION (v1)
// Notation: f32 = IEEE binary32, every operation below is ONE correctly rounded binary32 operation (the C++ code
// stores each product in a `volatile float` so a compiler can never fuse a*b+c into an FMA). `u24(r)` =
// `float(r >> 8) * (1.0f / 16777216.0f)` (exact: 24 bit integer times 2^-24, so in [0, 1)).
//
//  PCG32 (PCG-XSH-RR 64/32, the reference implementation of pcg-random.org):
//    seeding Pcg32(initstate, initseq=54): state = 0; inc = (initseq << 1) | 1; Next(); state += initstate; Next();
//    Next(): old = state; state = old * 6364136223846793005 + inc (mod 2^64);
//            xorshifted = (u32)(((old >> 18) ^ old) >> 27); rot = (u32)(old >> 59);
//            return (xorshifted >> rot) | (xorshifted << ((-rot) & 31)).
//    Known answer: Pcg32(42, 54) -> a15c02b7 7b47f409 ba1d3330 83d2f293 bfa4784b cbed606e.
//  SplitMix64(x): z = x + 0x9E3779B97F4A7C15; z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
//                 z = (z ^ (z >> 27)) * 0x94D049BB133111EB; return z ^ (z >> 31).   (all mod 2^64)
//  hash64(seed, L, bx, bz) = SplitMix64( seed ^ ((L & 0xFFFF) << 48) ^ ((bx & 0xFFFFFF) << 24) ^ (bz & 0xFFFFFF) )
//    L = layer index in the SCAT chunk, bx/bz = block coordinates as two's complement (so negative blocks work).
//  Blocks are 32 x 32 world units; block (bx, bz) covers x in [32 bx, 32 bx + 32), z likewise.
//
//  Per block: rng = Pcg32(hash64(seed, L, bx, bz), 54).
//    1. d = layer.density. If layer.densityMap >= 0: m = DensityMap(densityMap, cx, cz) at the block centre
//       (cx = float(32 bx + 16), cz likewise), clamped to [0, 1] (NaN = 0); d = d * m (one f32 multiply).
//       NaN or d <= 0 -> 0; d > 16384 -> 16384 (per-block candidate cap).
//    2. fl = floor(d) (integer), frac = d - float(fl) (exact). r = rng.Next() is ALWAYS drawn here (even for
//       frac == 0). n = fl + (double(r) < double(frac) * 4294967296.0 ? 1 : 0).
//    3. For each candidate i in 0..n-1, six draws in this order: r0 r1 r2 r3 r4 r5 = rng.Next() x 6 (always all six,
//       also when the candidate is rejected):
//         x = float(32 bx) + u24(r0) * 32.0f        (f32 add; the product is exact)
//         z = float(32 bz) + u24(r1) * 32.0f
//         variant: w_i = weight if (weight > 0 and finite) else 0; total = ((0 + w_0) + w_1) + ... in f32;
//                  if !(total > 0) the candidate is rejected. t = u24(r2) * total (f32 multiply); acc = 0;
//                  pick the first variant i with w_i > 0 and t < (acc += w_i) (f32 adds, in order);
//                  if none (t rounded up to total) pick the last variant with w_i > 0.
//         scale = smin + (smax - smin) * u24(r3)    (f32: d = smax - smin; p = d * u; scale = smin + p) with the
//                  picked variant's scaleMin / scaleMax
//         yawDeg = RANDOM_YAW flag ? u24(r4) * 360.0f : 0.0f
//         tint   = 1.0f + tintVariation * (2.0f * u24(r5) - 1.0f)   (f32: a = 2u - 1 (exact); p = tv * a; 1 + p)
//       Rejection tests (a failing test discards the candidate; the sampler is called with (x, z)):
//         y = Height(x, z); slope = SlopeDeg(x, z): reject unless minSlopeDeg <= slope <= maxSlopeDeg;
//         reject unless minAltitude <= y <= maxAltitude (NaN rejects);
//         allowedMaterials non-empty and DominantMaterial(x, z) not in it; Surface(x, z) in forbiddenSurfaces;
//         densityMap >= 0 and DensityMap(densityMap, x, z) is not > 0; Hole(x, z).
//       The ORDER of the tests only matters for how often the sampler is called.
//  `jitter` takes no part in placement (there is no random number left for it); renderers may use it for
//  sub-instance wobble. `variant` in the output is the index into layer.variant.
//
// PlaceScatter(rect) returns the instances of all blocks that intersect the rect, restricted to
// x0 <= x < x1 and z0 <= z < z1, ordered by block row (bz), then block column (bx), then candidate number.
// A rect needing more than 2^22 blocks (or with a non-finite / empty extent) returns nothing.
#pragma once

#include <cstdint>
#include <vector>

#include "moho/sim/mapformat/RenderChunks.h"

namespace moho::mapformat {

constexpr int kScatterBlockSize = 32;
constexpr float kScatterMaxPerBlock = 16384.0f;

/// PCG-XSH-RR 64/32, reference implementation.
class Pcg32
{
public:
  Pcg32(std::uint64_t initstate, std::uint64_t initseq = 54)
  {
    state_ = 0;
    inc_ = (initseq << 1) | 1u;
    Next();
    state_ += initstate;
    Next();
  }
  std::uint32_t Next()
  {
    const std::uint64_t old = state_;
    state_ = old * 6364136223846793005ULL + inc_;
    const std::uint32_t xorshifted = static_cast<std::uint32_t>(((old >> 18) ^ old) >> 27);
    const std::uint32_t rot = static_cast<std::uint32_t>(old >> 59);
    return (xorshifted >> rot) | (xorshifted << ((0u - rot) & 31u));
  }

private:
  std::uint64_t state_, inc_;
};

std::uint64_t SplitMix64(std::uint64_t x);
std::uint64_t ScatterHash64(std::uint64_t seed, std::uint32_t layerIndex, std::int32_t bx, std::int32_t bz);

/// Terrain / mask queries the placement needs. Answers must be deterministic functions of the arguments (in the
/// engine they come from the baked heightfield, SPLT, GPLY, SCDM and HOLE). The defaults describe flat open ground.
struct ScatterSampler
{
  virtual ~ScatterSampler() = default;
  virtual float Height(float, float) const { return 0.0f; }
  virtual float SlopeDeg(float, float) const { return 0.0f; }
  virtual int DominantMaterial(float, float) const { return 0; }
  virtual int Surface(float, float) const { return 0; }
  virtual float DensityMap(int, float, float) const { return 1.0f; } // 0..1, bilinear
  virtual bool Hole(float, float) const { return false; }
};

struct ScatterInstance
{
  std::uint32_t variant = 0;
  float x = 0, z = 0, y = 0, scale = 1, yawDeg = 0, tint = 1;
};

/// Instances of block (bx, bz) of layer `layerIndex` in candidate order.
std::vector<ScatterInstance> PlaceScatterBlock(const ScatterLayer& layer, int layerIndex, int bx, int bz,
                                               const ScatterSampler& sampler);

/// All instances inside [x0, x1) x [z0, z1) (world units), see the header comment for the order and limits.
std::vector<ScatterInstance> PlaceScatter(const ScatterLayer& layer, int layerIndex, const ScatterSampler& sampler,
                                          float x0, float z0, float x1, float z1);

} // namespace moho::mapformat
