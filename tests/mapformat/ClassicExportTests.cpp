#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/ClassicExport.h"
#include "moho/sim/mapformat/ExtendedMap.h"

using namespace moho::mapformat;

static std::vector<std::uint8_t> ReadAll(const std::string& p)
{
  std::ifstream f(p, std::ios::binary);
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// A strict reader of the Classic layout, written from the engine's loaders (not from the exporter): it must consume the
// exported file exactly. Returns an empty string when the layout is consistent, else what went wrong.
static std::string ParseClassic(const std::vector<std::uint8_t>& d, std::uint32_t& cellsX, std::uint32_t& cellsZ)
{
  ByteReader r(d.data(), d.size());
  auto cstr = [&]() { while (r.ok() && r.u8() != 0) {} };
  auto blob = [&]() { const std::int32_t n = r.i32(); if (n < 0) r.fail(); else r.bytes(static_cast<std::uint64_t>(n)); };
  if (r.u32() != 0x1A70614DU) return "magic";
  if (r.u32() != 2) return "container";
  if (r.u32() != 0xBEEFFEEDU) return "preview magic";
  if (r.u32() != 2) return "preview version";
  r.f32(); r.f32();
  if (r.u16() != 0) return "preview name";
  const std::uint32_t meta = r.u32();
  for (std::uint32_t i = 0; i < meta; ++i) { r.u32(); r.u32(); }
  blob();
  if (r.i32() != 56) return "minor";
  cellsX = r.u32(); cellsZ = r.u32();
  r.f32();
  r.bytes(static_cast<std::uint64_t>(cellsX + 1) * (cellsZ + 1) * 2);
  r.u8();
  cstr(); cstr(); cstr();
  const std::int32_t env = r.i32();
  for (std::int32_t i = 0; i < env; ++i) { cstr(); cstr(); }
  r.bytes(23 * 4);
  r.u8();
  r.bytes(3 * 4);
  r.bytes(20 * 4);
  cstr(); cstr();
  r.bytes(4 * 4);
  for (int i = 0; i < 4; ++i) { r.bytes(8); cstr(); }
  const std::int32_t waves = r.i32();
  if (waves != 0) return "waves";
  r.bytes(24);
  for (int i = 0; i < 19; ++i) { cstr(); r.bytes(4); }
  r.i32(); r.i32();
  const std::int32_t decals = r.i32();
  for (std::int32_t i = 0; i < decals; ++i) {
    r.i32(); r.i32();
    const std::int32_t names = r.i32();
    for (std::int32_t k = 0; k < names; ++k) { const std::int32_t n = r.i32(); r.bytes(static_cast<std::uint64_t>(n)); }
    r.bytes(9 * 4 + 4 + 4 + 4);
  }
  r.i32();
  r.i32(); r.i32();
  if (r.i32() != 1) return "skip list count";
  blob(); blob(); blob();
  if (r.i32() != 1) return "water map count";
  blob();
  const std::uint64_t half = static_cast<std::uint64_t>(cellsX / 2) * (cellsZ / 2);
  r.bytes(half * 3);
  r.bytes(static_cast<std::uint64_t>(cellsX) * cellsZ);
  const std::int32_t props = r.i32();
  for (std::int32_t i = 0; i < props; ++i) { cstr(); r.bytes(15 * 4); }
  if (!r.ok()) return "ran past the end";
  if (!r.atEnd()) return "trailing bytes";
  return std::string();
}

TEST(MapFormatClassicExport, Checks)
{
  const char* names[] = {"golden/extended_classic_equiv.fmap", "golden/extended_min.fmap", "golden/extended_full.fmap"};
  for (const char* n : names) {
    std::vector<std::uint8_t> bytes = ReadAll(n);
    EXPECT_TRUE(!bytes.empty());
    ExtendedMap m;
    std::string err;
    LoadOptions lo;
    lo.supportedFeatures = ~0ULL;
    const bool loaded = LoadExtendedMap(std::move(bytes), lo, m, err);
    if (!loaded) std::printf("load %s: %s\n", n, err.c_str());
    EXPECT_TRUE(loaded);
    if (!loaded) continue;
    ClassicExportResult res;
    ClassicExportOptions eo;
    eo.exportDecals = true;
    const bool ok = ExportClassic(m, eo, res, err);
    if (!ok) std::printf("export %s: %s\n", n, err.c_str());
    EXPECT_TRUE(ok);
    if (!ok) continue;
    std::uint32_t cx = 0, cz = 0;
    const std::string problem = ParseClassic(res.bytes, cx, cz);
    if (!problem.empty()) std::printf("layout %s: %s\n", n, problem.c_str());
    EXPECT_TRUE(problem.empty());
    EXPECT_EQ(cx, m.sim.grid->cellsX);
    EXPECT_EQ(cz, m.sim.grid->cellsZ);
    for (const std::string& note : res.notes) std::printf("  note (%s): %s\n", n, note.c_str());
    std::string out = std::string("out/") + (std::string(n).substr(7)) + ".scmap";
    std::ofstream f(out, std::ios::binary);
    f.write(reinterpret_cast<const char*>(res.bytes.data()), static_cast<std::streamsize>(res.bytes.size()));
  }
  // Heights of the Classic-equivalent map survive exactly.
  {
    ExtendedMap m;
    std::string err;
    LoadOptions lo;
    lo.supportedFeatures = ~0ULL;
    EXPECT_TRUE(LoadExtendedMap(ReadAll("golden/extended_classic_equiv.fmap"), lo, m, err));
    ClassicExportResult res;
    EXPECT_TRUE(ExportClassic(m, ClassicExportOptions(), res, err));
    EXPECT_EQ(res.maxHeightError, 0.0f);
  }
}
