// Scatter placement: known answers for PCG32 / SplitMix64 / hash64, golden instance lists (computed with the
// independent Python reference in the task notes: PCG32 + f32 emulation through struct), determinism, order
// independence, rejection behaviour and a fuzz loop.
#include <algorithm>
#include <cmath>
#include <cstring>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/Scatter.h"

using namespace moho::mapformat;

namespace {

std::uint32_t Bits(float f)
{
  std::uint32_t b;
  std::memcpy(&b, &f, 4);
  return b;
}

// FNV-1a over (variant u32, x z y scale yawDeg tint as f32 bit patterns), little endian.
std::uint64_t Checksum(const std::vector<ScatterInstance>& v)
{
  std::uint64_t h = 0xcbf29ce484222325ULL;
  auto feed = [&](std::uint32_t w) {
    for (int i = 0; i < 4; ++i) {
      h ^= (w >> (8 * i)) & 0xFFu;
      h *= 0x100000001b3ULL;
    }
  };
  for (const auto& i : v) {
    feed(i.variant);
    feed(Bits(i.x));
    feed(Bits(i.z));
    feed(Bits(i.y));
    feed(Bits(i.scale));
    feed(Bits(i.yawDeg));
    feed(Bits(i.tint));
  }
  return h;
}

// Float equality by bit pattern; the values go through volatile so a 32-bit x87 build compares rounded floats.
#define FEQ(a, b)                            do {                                         volatile float fa_ = (a);                  volatile float fb_ = (b);                  EXPECT_EQ(Bits(fa_), Bits(fb_));       } while (0)

bool SameInst(const ScatterInstance& a, const ScatterInstance& b)
{
  return a.variant == b.variant && Bits(a.x) == Bits(b.x) && Bits(a.z) == Bits(b.z) && Bits(a.y) == Bits(b.y) &&
         Bits(a.scale) == Bits(b.scale) && Bits(a.yawDeg) == Bits(b.yawDeg) && Bits(a.tint) == Bits(b.tint);
}

bool SameList(const std::vector<ScatterInstance>& a, const std::vector<ScatterInstance>& b)
{
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i)
    if (!SameInst(a[i], b[i])) return false;
  return true;
}

void SortList(std::vector<ScatterInstance>& v)
{
  std::sort(v.begin(), v.end(), [](const ScatterInstance& a, const ScatterInstance& b) {
    if (a.z != b.z) return a.z < b.z;
    if (a.x != b.x) return a.x < b.x;
    return a.variant < b.variant;
  });
}

ScatterVariant Var(std::uint8_t kind, float w, float smin, float smax)
{
  ScatterVariant v;
  v.kind = kind;
  v.ref = "/props/test.bp";
  v.weight = w;
  v.scaleMin = smin;
  v.scaleMax = smax;
  return v;
}

// Layer A of the Python reference.
ScatterLayer LayerA()
{
  ScatterLayer l;
  l.name = "a";
  l.seed = 0x1234567890abcdefULL;
  l.variant = {Var(0, 1.0f, 0.5f, 1.5f), Var(0, 2.0f, 1.0f, 1.0f), Var(1, 0.5f, 2.0f, 3.0f)};
  l.density = 2.75f;
  l.flags = ScatterFlags::RandomYaw;
  l.tintVariation = 0.2f;
  return l;
}

// Layer B of the Python reference, used with RestrictedSampler.
ScatterLayer LayerB()
{
  ScatterLayer l;
  l.name = "b";
  l.seed = 77;
  l.variant = {Var(0, 1.0f, 1.0f, 2.0f)};
  l.density = 6.5f;
  l.minSlopeDeg = 5.0f;
  l.maxSlopeDeg = 30.0f;
  l.minAltitude = 2.0f;
  l.maxAltitude = 100.0f;
  l.allowedMaterials = {0, 2};
  l.forbiddenSurfaces = {1};
  l.densityMap = 3;
  return l;
}

// All answers are exact in binary32, so the Python reference reproduces them bit for bit.
struct RestrictedSampler : ScatterSampler
{
  float Height(float x, float) const override { return x * 0.25f; }
  float SlopeDeg(float, float z) const override { return static_cast<float>(static_cast<int>(z) % 40); }
  int DominantMaterial(float x, float) const override { return static_cast<int>(x) % 3; }
  int Surface(float, float z) const override { return static_cast<int>(z) % 4; }
  float DensityMap(int, float x, float z) const override
  {
    return static_cast<float>((static_cast<int>(x) + static_cast<int>(z)) % 5) / 4.0f;
  }
  bool Hole(float x, float z) const override { return static_cast<int>(x) % 7 == 0 && static_cast<int>(z) % 3 == 0; }
};

struct LeftHoleSampler : ScatterSampler
{
  float limit;
  explicit LeftHoleSampler(float l) : limit(l) {}
  bool Hole(float x, float) const override { return x < limit; }
};

struct ConstSampler : ScatterSampler
{
  float height = 0, slope = 0, density = 1;
  int material = 0, surface = 0;
  bool hole = false;
  float Height(float, float) const override { return height; }
  float SlopeDeg(float, float) const override { return slope; }
  int DominantMaterial(float, float) const override { return material; }
  int Surface(float, float) const override { return surface; }
  float DensityMap(int, float, float) const override { return density; }
  bool Hole(float, float) const override { return hole; }
};

struct Xs
{
  std::uint64_t s;
  std::uint32_t next()
  {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return static_cast<std::uint32_t>(s >> 16);
  }
  float unit() { return static_cast<float>(next() & 0xFFFF) / 65536.0f; }
};

} // namespace

TEST(MapFormatScatter, Checks)
{
  // ---- PCG32 known answers (reference pcg32, initseq 54; values computed with Python)
  {
    Pcg32 a(42);
    const std::uint32_t e42[] = {0xa15c02b7u, 0x7b47f409u, 0xba1d3330u, 0x83d2f293u, 0xbfa4784bu, 0xcbed606eu};
    for (std::uint32_t e : e42) EXPECT_EQ(a.Next(), e);
    Pcg32 b(0);
    const std::uint32_t e0[] = {0x47c28b93u, 0xb98f6a27u, 0x7d3dcb1eu, 0xf0761116u, 0x9cc33f5bu, 0xbe0e744du};
    for (std::uint32_t e : e0) EXPECT_EQ(b.Next(), e);
    Pcg32 c(0x0123456789abcdefULL);
    const std::uint32_t e3[] = {0x420eb9e1u, 0x3359e6eau, 0x3d920f25u, 0xbfdc3029u, 0x75c1c720u, 0xa483119bu};
    for (std::uint32_t e : e3) EXPECT_EQ(c.Next(), e);
  }

  // ---- SplitMix64 / hash64 known answers
  EXPECT_EQ(SplitMix64(0), 0xe220a8397b1dcdafULL);
  EXPECT_EQ(SplitMix64(1), 0x910a2dec89025cc1ULL);
  EXPECT_EQ(ScatterHash64(0x1234567890abcdefULL, 3, 5, 9), 0xaabffe6090f65368ULL);
  EXPECT_EQ(ScatterHash64(77, 0, -1, -2), 0x722c6b9b5fd8b9beULL);
  EXPECT_EQ(ScatterHash64(0, 255, 0xFFFFFF, 0xFFFFFF), 0x991051fccdb19732ULL);
  // bx is masked to 24 bits, L to 16: out-of-range bits cannot leak into neighbouring fields
  EXPECT_EQ(ScatterHash64(5, 1, 0x1000000, 0), ScatterHash64(5, 1, 0, 0));
  EXPECT_EQ(ScatterHash64(5, 0x10001, 2, 3), ScatterHash64(5, 1, 2, 3));

  // ---- goldens (Python reference: tests/.. notes in the task report)
  {
    ConstSampler flat;
    const auto a = PlaceScatter(LayerA(), 0, flat, 0, 0, 128, 96);
    EXPECT_EQ(a.size(), 30u);
    EXPECT_EQ(Checksum(a), 0xa4626b77401e4439ULL);
    if (!a.empty()) {
      EXPECT_EQ(a[0].variant, 0u);
      FEQ(a[0].x, 18.31493377685547f);
      FEQ(a[0].z, 31.571928024291992f);
      FEQ(a[0].scale, 1.4489622116088867f);
      FEQ(a[0].yawDeg, 74.69525146484375f);
      FEQ(a[0].tint, 0.8086053729057312f);
      EXPECT_EQ(a.back().variant, 1u);
      FEQ(a.back().x, 122.05404663085938f);
    }
    const auto a1 = PlaceScatter(LayerA(), 2, flat, -64, -64, 64, 64); // negative blocks, other layer index
    EXPECT_EQ(a1.size(), 44u);
    EXPECT_EQ(Checksum(a1), 0x7e45c0008f93393dULL);
    const auto blk = PlaceScatterBlock(LayerA(), 0, 2, 1, flat);
    EXPECT_EQ(blk.size(), 2u);
    if (blk.size() == 2) {
      FEQ(blk[0].x, 79.1760482788086f);
      FEQ(blk[1].yawDeg, 134.74862670898438f);
    }
    RestrictedSampler rs;
    const auto b = PlaceScatter(LayerB(), 1, rs, 0, 0, 256, 256);
    EXPECT_EQ(b.size(), 49u);
    EXPECT_EQ(Checksum(b), 0x8756b9ce9e037c96ULL);
    if (!b.empty()) {
      FEQ(b[0].x, 20.699623107910156f);
      FEQ(b[0].y, 5.174905776977539f);
      FEQ(b[0].yawDeg, 0.0f); // no RANDOM_YAW flag
      FEQ(b[0].tint, 1.0f);   // tintVariation 0
    }
  }

  // ---- the draw order is exactly the documented one
  {
    ScatterLayer l = LayerA();
    l.density = 1.0f; // exactly one candidate per block: the count draw is consumed but cannot add one
    l.variant = {Var(0, 1.0f, 2.0f, 4.0f)};
    ConstSampler flat;
    const auto blk = PlaceScatterBlock(l, 4, 3, 7, flat);
    EXPECT_EQ(blk.size(), 1u);
    Pcg32 rng(ScatterHash64(l.seed, 4, 3, 7), 54);
    (void)rng.Next(); // count draw
    std::uint32_t r[6];
    for (auto& v : r) v = rng.Next();
    const float ux = static_cast<float>(r[0] >> 8) * (1.0f / 16777216.0f);
    const float uz = static_cast<float>(r[1] >> 8) * (1.0f / 16777216.0f);
    if (blk.size() == 1) {
      FEQ(blk[0].x, 96.0f + ux * 32.0f);
      FEQ(blk[0].z, 224.0f + uz * 32.0f);
      EXPECT_TRUE(blk[0].x >= 96.0f && blk[0].x < 128.0f && blk[0].z >= 224.0f && blk[0].z < 256.0f);
      EXPECT_TRUE(blk[0].scale >= 2.0f && blk[0].scale <= 4.0f);
      EXPECT_TRUE(blk[0].tint >= 0.8f - 1e-6f && blk[0].tint <= 1.2f + 1e-6f);
    }
  }

  // ---- determinism and order independence
  {
    ConstSampler flat;
    const auto one = PlaceScatter(LayerA(), 0, flat, 0, 0, 256, 192);
    const auto two = PlaceScatter(LayerA(), 0, flat, 0, 0, 256, 192);
    EXPECT_TRUE(SameList(one, two));
    // blocks visited in reverse order give the same multiset
    std::vector<ScatterInstance> rev;
    for (int bz = 5; bz >= 0; --bz)
      for (int bx = 7; bx >= 0; --bx) {
        const auto b = PlaceScatterBlock(LayerA(), 0, bx, bz, flat);
        rev.insert(rev.end(), b.begin(), b.end());
      }
    std::vector<ScatterInstance> fwd = one;
    SortList(rev);
    SortList(fwd);
    EXPECT_TRUE(SameList(rev, fwd));
    // tiling the rectangle gives the same instances as one big call
    std::vector<ScatterInstance> tiles;
    const float xs[] = {0, 40, 130, 256}, zs[] = {0, 33, 192};
    for (int i = 0; i < 3; ++i)
      for (int j = 0; j < 2; ++j) {
        const auto t = PlaceScatter(LayerA(), 0, flat, xs[i], zs[j], xs[i + 1], zs[j + 1]);
        tiles.insert(tiles.end(), t.begin(), t.end());
      }
    SortList(tiles);
    fwd = one;
    SortList(fwd);
    EXPECT_TRUE(SameList(tiles, fwd));
    // a different layer index or seed changes the result
    EXPECT_TRUE(!SameList(one, PlaceScatter(LayerA(), 1, flat, 0, 0, 256, 192)));
    ScatterLayer other = LayerA();
    other.seed ^= 1;
    EXPECT_TRUE(!SameList(one, PlaceScatter(other, 0, flat, 0, 0, 256, 192)));
  }

  // ---- rejection tests; a rejected candidate still consumes its six numbers, so survivors are unchanged
  {
    ConstSampler flat;
    ScatterLayer l = LayerA();
    const auto all = PlaceScatter(l, 0, flat, 0, 0, 128, 128);
    EXPECT_TRUE(all.size() > 20);
    LeftHoleSampler left(64.0f);
    const auto kept = PlaceScatter(l, 0, left, 0, 0, 128, 128);
    std::vector<ScatterInstance> expect;
    for (const auto& i : all)
      if (i.x >= 64.0f) expect.push_back(i);
    EXPECT_TRUE(!kept.empty());
    EXPECT_TRUE(SameList(kept, expect));

    ConstSampler s;
    s.slope = 45;
    l.maxSlopeDeg = 30;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    l.maxSlopeDeg = 90;
    l.minSlopeDeg = 46;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    l.minSlopeDeg = 45;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).size() == all.size()); // bounds are inclusive

    l = LayerA();
    s = ConstSampler();
    s.height = 10;
    l.maxAltitude = 9.5f;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    l.maxAltitude = 20;
    l.minAltitude = 10.5f;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    l.minAltitude = 10;
    const auto atAlt = PlaceScatter(l, 0, s, 0, 0, 128, 128);
    EXPECT_EQ(atAlt.size(), all.size());
    if (!atAlt.empty()) FEQ(atAlt[0].y, 10.0f);

    l = LayerA();
    s = ConstSampler();
    s.material = 5;
    l.allowedMaterials = {1, 2};
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    l.allowedMaterials = {1, 5};
    EXPECT_EQ(PlaceScatter(l, 0, s, 0, 0, 128, 128).size(), all.size());

    l = LayerA();
    s = ConstSampler();
    s.surface = 3;
    l.forbiddenSurfaces = {3};
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    l.forbiddenSurfaces = {1, 2};
    EXPECT_EQ(PlaceScatter(l, 0, s, 0, 0, 128, 128).size(), all.size());

    l = LayerA();
    s = ConstSampler();
    s.hole = true;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());

    // density map: scales the density at the block centre and must be > 0 at the point
    l = LayerA();
    l.densityMap = 0;
    s = ConstSampler();
    s.density = 0;
    EXPECT_TRUE(PlaceScatter(l, 0, s, 0, 0, 128, 128).empty());
    s.density = 1;
    EXPECT_EQ(PlaceScatter(l, 0, s, 0, 0, 128, 128).size(), all.size());
    s.density = 0.5f;
    const auto half = PlaceScatter(l, 0, s, 0, 0, 512, 512);
    ScatterLayer full = LayerA();
    const auto fullList = PlaceScatter(full, 0, flat, 0, 0, 512, 512);
    EXPECT_TRUE(half.size() < fullList.size() && half.size() * 4 > fullList.size()); // ~half
    s.density = 7; // clamped to 1
    EXPECT_EQ(PlaceScatter(l, 0, s, 0, 0, 128, 128).size(), all.size());
  }

  // ---- degenerate layers and rectangles
  {
    ConstSampler flat;
    ScatterLayer l = LayerA();
    l.density = 0;
    EXPECT_TRUE(PlaceScatter(l, 0, flat, 0, 0, 128, 128).empty());
    l.density = std::nanf("");
    EXPECT_TRUE(PlaceScatter(l, 0, flat, 0, 0, 128, 128).empty());
    l.density = -3;
    EXPECT_TRUE(PlaceScatter(l, 0, flat, 0, 0, 128, 128).empty());
    l = LayerA();
    for (auto& v : l.variant) v.weight = 0;
    EXPECT_TRUE(PlaceScatter(l, 0, flat, 0, 0, 128, 128).empty());
    l.variant[2].weight = 1; // only variant 2 can be picked
    const auto only = PlaceScatter(l, 0, flat, 0, 0, 128, 128);
    EXPECT_TRUE(!only.empty());
    for (const auto& i : only) EXPECT_EQ(i.variant, 2u);
    l = LayerA();
    l.variant.clear();
    EXPECT_TRUE(PlaceScatter(l, 0, flat, 0, 0, 128, 128).empty());

    l = LayerA();
    l.density = 1.0e9f; // capped
    const auto capped = PlaceScatterBlock(l, 0, 0, 0, flat);
    EXPECT_EQ(capped.size(), 16384u);

    EXPECT_TRUE(PlaceScatter(LayerA(), 0, flat, 10, 10, 10, 50).empty());
    EXPECT_TRUE(PlaceScatter(LayerA(), 0, flat, 50, 10, 10, 50).empty());
    EXPECT_TRUE(PlaceScatter(LayerA(), 0, flat, 0, 0, std::nanf(""), 50).empty());
    EXPECT_TRUE(PlaceScatter(LayerA(), 0, flat, -1e30f, 0, 1e30f, 50).empty());
    EXPECT_TRUE(PlaceScatter(LayerA(), 0, flat, 0, 0, 1e7f, 1e7f).empty()); // more than 2^22 blocks
  }

  // ---- fuzz: random layers and rectangles never crash and keep the invariants
  {
    Xs rng{0x9E3779B97F4A7C15ULL};
    RestrictedSampler rs;
    for (int it = 0; it < 300; ++it) {
      ScatterLayer l;
      l.seed = (static_cast<std::uint64_t>(rng.next()) << 32) | rng.next();
      const int nv = 1 + static_cast<int>(rng.next() % 5);
      for (int i = 0; i < nv; ++i) l.variant.push_back(Var(0, rng.unit() * 3 - 0.5f, rng.unit(), 1 + rng.unit()));
      l.density = rng.unit() * 8;
      l.minSlopeDeg = rng.unit() * 20;
      l.maxSlopeDeg = 20 + rng.unit() * 70;
      l.flags = static_cast<std::uint16_t>(rng.next() & 31);
      l.tintVariation = rng.unit();
      l.densityMap = (rng.next() & 1) ? 0 : -1;
      const float x0 = rng.unit() * 200 - 100, z0 = rng.unit() * 200 - 100;
      const float x1 = x0 + rng.unit() * 120, z1 = z0 + rng.unit() * 120;
      const auto v = PlaceScatter(l, static_cast<int>(rng.next() % 256), rs, x0, z0, x1, z1);
      for (const auto& i : v) {
        EXPECT_TRUE(i.x >= x0 && i.x < x1 && i.z >= z0 && i.z < z1);
        EXPECT_TRUE(i.variant < l.variant.size());
        EXPECT_TRUE(l.variant[i.variant].weight > 0);
      }
    }
  }
}
