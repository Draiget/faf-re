// Normative scatter placement; the derivation of every number is in Scatter.h.
#include "moho/sim/mapformat/Scatter.h"

#include <cmath>

namespace moho::mapformat {
namespace {

// Each product goes through a volatile store so the compiler must round it to binary32 before it is used: a
// contracted multiply-add (-ffp-contract, ARM) would give different low bits than the reference.
inline float Mul(float a, float b)
{
  volatile float r = a * b;
  return r;
}

// Same for sums: on x87 targets (32-bit builds) intermediate sums would otherwise stay in extended precision.
inline float Add(float a, float b)
{
  volatile float r = a + b;
  return r;
}

inline float U24(std::uint32_t r) { return Mul(static_cast<float>(r >> 8), 1.0f / 16777216.0f); }

inline float Clamp01(float v) { return v > 0.0f ? (v < 1.0f ? v : 1.0f) : 0.0f; } // NaN -> 0

} // namespace

std::uint64_t SplitMix64(std::uint64_t x)
{
  std::uint64_t z = x + 0x9E3779B97F4A7C15ULL;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

std::uint64_t ScatterHash64(std::uint64_t seed, std::uint32_t layerIndex, std::int32_t bx, std::int32_t bz)
{
  const std::uint64_t l = static_cast<std::uint64_t>(layerIndex) & 0xFFFFULL;
  const std::uint64_t x = static_cast<std::uint64_t>(static_cast<std::uint32_t>(bx)) & 0xFFFFFFULL;
  const std::uint64_t z = static_cast<std::uint64_t>(static_cast<std::uint32_t>(bz)) & 0xFFFFFFULL;
  return SplitMix64(seed ^ (l << 48) ^ (x << 24) ^ z);
}

std::vector<ScatterInstance> PlaceScatterBlock(const ScatterLayer& layer, int layerIndex, int bx, int bz,
                                               const ScatterSampler& sampler)
{
  std::vector<ScatterInstance> out;
  if (layer.variant.empty()) return out;
  Pcg32 rng(ScatterHash64(layer.seed, static_cast<std::uint32_t>(layerIndex), bx, bz), 54);

  const float ox = static_cast<float>(bx * kScatterBlockSize);
  const float oz = static_cast<float>(bz * kScatterBlockSize);

  float density = layer.density;
  if (layer.densityMap >= 0) {
    const float m = Clamp01(sampler.DensityMap(layer.densityMap, Add(ox, 16.0f), Add(oz, 16.0f)));
    density = Mul(density, m);
  }
  if (!(density > 0.0f)) density = 0.0f; // also NaN
  if (density > kScatterMaxPerBlock) density = kScatterMaxPerBlock;
  const std::uint32_t whole = static_cast<std::uint32_t>(std::floor(density));
  const float frac = Add(density, -static_cast<float>(whole)); // exact
  const std::uint32_t countDraw = rng.Next(); // always consumed
  const std::uint32_t n =
      whole + (static_cast<double>(countDraw) < static_cast<double>(frac) * 4294967296.0 ? 1u : 0u);

  // Weights are sanitised once; the variant pick of every candidate uses the same total.
  const std::size_t vc = layer.variant.size();
  std::vector<float> w(vc);
  float total = 0.0f;
  std::size_t lastPositive = vc;
  for (std::size_t i = 0; i < vc; ++i) {
    const float wi = layer.variant[i].weight;
    w[i] = (wi > 0.0f && wi <= 3.4028234663852886e38f) ? wi : 0.0f;
    total = Add(total, w[i]);
    if (w[i] > 0.0f) lastPositive = i;
  }

  for (std::uint32_t k = 0; k < n; ++k) {
    std::uint32_t r[6];
    for (auto& v : r) v = rng.Next(); // a rejected candidate consumes its six numbers like an accepted one
    if (!(total > 0.0f)) continue;

    const float x = Add(ox, Mul(U24(r[0]), 32.0f));
    const float z = Add(oz, Mul(U24(r[1]), 32.0f));

    const float t = Mul(U24(r[2]), total);
    float acc = 0.0f;
    std::size_t pick = lastPositive;
    for (std::size_t i = 0; i < vc; ++i) {
      if (!(w[i] > 0.0f)) continue;
      acc = Add(acc, w[i]);
      if (t < acc) {
        pick = i;
        break;
      }
    }

    const float y = sampler.Height(x, z);
    const float slope = sampler.SlopeDeg(x, z);
    if (!(slope >= layer.minSlopeDeg && slope <= layer.maxSlopeDeg)) continue;
    if (!(y >= layer.minAltitude && y <= layer.maxAltitude)) continue;
    if (!layer.allowedMaterials.empty()) {
      const int mat = sampler.DominantMaterial(x, z);
      bool found = false;
      for (std::uint16_t a : layer.allowedMaterials) found = found || (static_cast<int>(a) == mat);
      if (!found) continue;
    }
    {
      const int surf = sampler.Surface(x, z);
      bool forbidden = false;
      for (std::uint16_t f : layer.forbiddenSurfaces) forbidden = forbidden || (static_cast<int>(f) == surf);
      if (forbidden) continue;
    }
    if (layer.densityMap >= 0 && !(sampler.DensityMap(layer.densityMap, x, z) > 0.0f)) continue;
    if (sampler.Hole(x, z)) continue;

    const ScatterVariant& v = layer.variant[pick];
    ScatterInstance inst;
    inst.variant = static_cast<std::uint32_t>(pick);
    inst.x = x;
    inst.z = z;
    inst.y = y;
    const float span = Add(v.scaleMax, -v.scaleMin);
    inst.scale = Add(v.scaleMin, Mul(span, U24(r[3])));
    inst.yawDeg = (layer.flags & ScatterFlags::RandomYaw) ? Mul(U24(r[4]), 360.0f) : 0.0f;
    const float a = Add(Mul(2.0f, U24(r[5])), -1.0f); // exact
    inst.tint = Add(1.0f, Mul(layer.tintVariation, a));
    out.push_back(inst);
  }
  return out;
}

std::vector<ScatterInstance> PlaceScatter(const ScatterLayer& layer, int layerIndex, const ScatterSampler& sampler,
                                          float x0, float z0, float x1, float z1)
{
  std::vector<ScatterInstance> out;
  const float lim = 1.0e8f;
  if (!(x1 > x0 && z1 > z0) ||
      !(std::fabs(x0) < lim && std::fabs(x1) < lim && std::fabs(z0) < lim && std::fabs(z1) < lim))
    return out;
  const float inv = 1.0f / static_cast<float>(kScatterBlockSize); // exact power of two
  const long long bx0 = static_cast<long long>(std::floor(x0 * inv));
  const long long bx1 = static_cast<long long>(std::ceil(x1 * inv)) - 1;
  const long long bz0 = static_cast<long long>(std::floor(z0 * inv));
  const long long bz1 = static_cast<long long>(std::ceil(z1 * inv)) - 1;
  if (bx1 < bx0 || bz1 < bz0) return out;
  if ((bx1 - bx0 + 1) * (bz1 - bz0 + 1) > (1LL << 22)) return out;
  for (long long bz = bz0; bz <= bz1; ++bz)
    for (long long bx = bx0; bx <= bx1; ++bx)
      for (const ScatterInstance& i :
           PlaceScatterBlock(layer, layerIndex, static_cast<int>(bx), static_cast<int>(bz), sampler))
        if (i.x >= x0 && i.x < x1 && i.z >= z0 && i.z < z1) out.push_back(i);
  return out;
}

} // namespace moho::mapformat
