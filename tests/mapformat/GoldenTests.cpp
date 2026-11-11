// Golden maps (tests/mapformat/golden/, written by tools/mapformat/make_golden.py): every valid map opens, verifies its
// simHash and dumps byte for byte the text of the Python reference; every negative map is refused at the stage the
// golden README names; the normative scatter result is reproduced; TextDump::Quote equals json.dumps(ensure_ascii=True).
// CTest runs the tests with the working directory tests/mapformat, so the golden directory is `golden/`.
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/ChunkFamilies.h"
#include "moho/sim/mapformat/FeatureBits.h"
#include "moho/sim/mapformat/MapContainer.h"
#include "moho/sim/mapformat/MapDump.h"
#include "moho/sim/mapformat/RenderChunks.h"
#include "moho/sim/mapformat/Scatter.h"
#include "moho/sim/mapformat/SimChunks.h"

using namespace moho::mapformat;

namespace {

typedef std::vector<std::uint8_t> Bytes;

bool ReadFile(const std::string& path, Bytes& out)
{
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  return true;
}

std::string ReadText(const std::string& path, bool& ok)
{
  Bytes b;
  ok = ReadFile(path, b);
  std::string s(b.begin(), b.end());
  std::string r;
  for (char c : s)
    if (c != '\r') r.push_back(c);
  return r;
}

OpenOptions AllFeatures()
{
  OpenOptions o;
  o.supportedFeatures = ~0ULL;
  return o;
}

/// "Does this reader understand the chunk?" for OpenOptions::isKnownChunk: one of the three families answers for the id.
bool KnownChunk(const char id[4], std::uint16_t version)
{
  if (version != 1) return false;
  const std::string s(id, 4);
  ChunkCtx ctx;
  TextDump d;
  std::string err;
  return DumpChunkSim(s, version, nullptr, 0, ctx, d, err) != DecodeStatus::NotMine ||
         DumpChunkRender(s, version, nullptr, 0, ctx, d, err) != DecodeStatus::NotMine ||
         DumpChunkWorld3D(s, version, nullptr, 0, ctx, d, err) != DecodeStatus::NotMine;
}

// ---- sim loader used by the negative tests: every sim chunk into MapSimData, then the cross-chunk validation -----------

struct LoadedSim
{
  MapSimData sim;
  ChunkCtx ctx;
};

template <typename T, typename Fn>
bool LoadSimChunk(const MapContainer& c, const char* id, bool required, std::optional<T>& dst, Fn fn, ChunkCtx& ctx,
                  std::uint64_t& budget, std::string& err)
{
  const ChunkEntry* e = nullptr;
  if (!c.FindChunk(id, 0, &e)) {
    if (required) {
      err = std::string(id) + ": required chunk is missing";
      return false;
    }
    return true;
  }
  std::vector<std::uint8_t> raw;
  const Result rr = c.ReadChunk(*e, raw, &budget);
  if (!rr.ok()) {
    err = std::string(id) + ": " + rr.message;
    return false;
  }
  if (e->version != 1) {
    err = std::string(id) + ": unsupported chunk version";
    return false;
  }
  T value;
  if (!fn(raw.data(), raw.size(), ctx, value, err)) {
    if (err.empty()) err = std::string(id) + ": malformed";
    return false;
  }
  dst = std::move(value);
  return true;
}

/// false + `err`: the map must be refused, at the chunk-decode stage (crossStage false) or in the cross-chunk stage
/// (ValidateSimData and the feature declaration rule of EXTENDED.md appendix A; crossStage true).
bool LoadSim(const MapContainer& c, LoadedSim& out, std::string& err, bool& crossStage)
{
  crossStage = false;
  MapSimData& m = out.sim;
  m = MapSimData();
  m.container = static_cast<int>(c.header().container);
  ChunkCtx& ctx = out.ctx;
  ctx = ChunkCtx();
  ctx.container = m.container;
  std::uint64_t budget = 0;
  const bool f4 = m.container == 4;
  if (!LoadSimChunk(c, "GRID", true, m.grid, DecodeGrid, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "WRLD", f4, m.wrld, DecodeWrld, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "HGHT", true, m.hght, DecodeHght, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "PLAY", true, m.play, DecodePlay, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "GPLY", true, m.gply, DecodeGply, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "WBOD", true, m.wbod, DecodeWbod, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "LEVL", false, m.levl, DecodeLevl, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "MRKR", false, m.mrkr, DecodeMrkr, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "AREA", false, m.area, DecodeArea, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "PROP", false, m.prop, DecodeProp, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "HINT", false, m.hint, DecodeHint, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "SLYR", false, m.slyr, DecodeSlyr, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "NAVS", false, m.navs, DecodeNavs, ctx, budget, err)) return false;
  if (!LoadSimChunk(c, "VOLS", false, m.vols, DecodeVols, ctx, budget, err)) return false;
  for (const ChunkEntry& e : c.entries()) {
    if (e.Id() != "COLL") continue;
    std::vector<std::uint8_t> raw;
    const Result rr = c.ReadChunk(e, raw, &budget);
    if (!rr.ok()) {
      err = "COLL: " + rr.message;
      return false;
    }
    MapSimData::CollEntry ce;
    ce.instance = e.instance;
    if (!DecodeColl(raw.data(), raw.size(), ctx, ce.chunk, err)) return false;
    m.coll.push_back(std::move(ce));
  }
  crossStage = true;
  if (!ValidateSimData(m, err)) return false;
  std::uint64_t used = RequiredFeatureMaskFor(m);
  const ChunkEntry* cidx = nullptr;
  if (m.wrld && c.FindChunk("CIDX", 0, &cidx)) used |= kFeat_WorldCells; // a cell index makes the world streamed
  constexpr std::uint64_t kSimBits = 0x3FFULL | (0x3FULL << 32);
  const std::uint64_t missing = used & kSimBits & ~c.header().requiredFeatures;
  if (missing) {
    err = "content needs features not in requiredFeatures:";
    for (const std::string& n : FeatureNames(missing)) err += " " + n;
    return false;
  }
  return true;
}

// ---- valid maps ----------------------------------------------------------------------------------------------------------

void TestValid(const std::string& name)
{
  const std::string base = "golden/" + name;
  Bytes file;
  EXPECT_TRUE(ReadFile(base + ".fmap", file));
  MapContainer c;
  const Result open = MapContainer::Open(file.data(), file.size(), AllFeatures(), c);
  if (!open.ok()) std::printf("  %s: Open failed: %s\n", name.c_str(), open.message.c_str());
  EXPECT_TRUE(open.ok());
  if (!open.ok()) return;

  const Result verify = c.VerifySimHash();
  if (!verify.ok()) std::printf("  %s: VerifySimHash: %s\n", name.c_str(), verify.message.c_str());
  EXPECT_TRUE(verify.ok());

  bool ok = false;
  const std::string simhash = ReadText(base + ".simhash", ok);
  EXPECT_TRUE(ok);
  EXPECT_EQ(simhash, HexString(c.header().simHash.data(), c.header().simHash.size()) + "\n");

  const std::string want = ReadText(base + ".dump.txt", ok);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(!want.empty());
  std::string err;
  const std::string got = DumpText(c, &err);
  if (!err.empty()) std::printf("  %s: DumpText: %s\n", name.c_str(), err.c_str());
  EXPECT_TRUE(err.empty());
  if (got != want) {
    std::size_t i = 0;
    while (i < got.size() && i < want.size() && got[i] == want[i]) ++i;
    std::size_t line = 1;
    for (std::size_t k = 0; k < i; ++k) line += got[k] == '\n';
    const std::size_t gs = got.rfind('\n', i ? i - 1 : 0), ws = want.rfind('\n', i ? i - 1 : 0);
    std::printf("  %s: dump differs at line %zu\n    C++: %s\n    Py : %s\n", name.c_str(), line,
                got.substr(gs == std::string::npos ? 0 : gs + 1, got.find('\n', i) - (gs == std::string::npos ? 0 : gs + 1)).c_str(),
                want.substr(ws == std::string::npos ? 0 : ws + 1, want.find('\n', i) - (ws == std::string::npos ? 0 : ws + 1)).c_str());
  }
  EXPECT_TRUE(got == want);

  // The sim chunks decode and cross-validate (what the engine does before it accepts the map).
  LoadedSim ls;
  bool cross = false;
  const bool loaded = LoadSim(c, ls, err, cross);
  if (!loaded) std::printf("  %s: LoadSim: %s\n", name.c_str(), err.c_str());
  EXPECT_TRUE(loaded);
}

// ---- negative maps -------------------------------------------------------------------------------------------------------

Bytes MustRead(const std::string& name)
{
  Bytes b;
  EXPECT_TRUE(ReadFile("golden/" + name + ".fmap", b));
  return b;
}

/// Container-level refusal: Open fails with `code`.
void ExpectOpenFails(const std::string& name, ContainerError code, const OpenOptions& options)
{
  const Bytes f = MustRead(name);
  MapContainer c;
  const Result r = MapContainer::Open(f.data(), f.size(), options, c);
  if (r.code != code) std::printf("  %s: got %s (%s), want %s\n", name.c_str(), ContainerErrorName(r.code), r.message.c_str(), ContainerErrorName(code));
  EXPECT_TRUE(r.code == code);
}

void TestNegative()
{
  const OpenOptions all = AllFeatures();
  ExpectOpenFails("bad_magic", ContainerError::BadMagic, all);
  ExpectOpenFails("bad_container_5", ContainerError::UnsupportedContainer, all);
  ExpectOpenFails("bad_header_crc", ContainerError::HeaderCrc, all);
  ExpectOpenFails("truncated", ContainerError::FileSizeMismatch, all);
  ExpectOpenFails("bad_dir_crc", ContainerError::DirectoryCrc, all);
  ExpectOpenFails("chunk_out_of_range", ContainerError::ChunkOutOfRange, all);
  ExpectOpenFails("inflate_bomb", ContainerError::RatioExceeded, all);
  // requiredFeatures has bit 63 (EXTENDED_FEATURES), which the engine's default options never claim.
  ExpectOpenFails("unsupported_required_feature", ContainerError::UnsupportedFeature, OpenOptions());

  { // Valid container, an unknown chunk with the REQUIRED flag: the caller's isKnownChunk refuses it; without the callback
    // the container opens and the dump (which walks the families) refuses it.
    OpenOptions known = all;
    known.isKnownChunk = &KnownChunk;
    ExpectOpenFails("unknown_required_chunk", ContainerError::UnknownRequiredChunk, known);
    const Bytes f = MustRead("unknown_required_chunk");
    MapContainer c;
    EXPECT_TRUE(MapContainer::Open(f.data(), f.size(), all, c).ok());
    std::string err;
    EXPECT_TRUE(DumpText(c, &err).empty());
    EXPECT_TRUE(err.find("ZZZZ") != std::string::npos);
  }

  { // One byte inside GRID's stored data flipped: the container opens, the chunk fails its CRC (also for the hash and the dump).
    const Bytes f = MustRead("bad_chunk_crc");
    MapContainer c;
    EXPECT_TRUE(MapContainer::Open(f.data(), f.size(), all, c).ok());
    const ChunkEntry* grid = nullptr;
    EXPECT_TRUE(c.FindChunk("GRID", 0, &grid));
    Bytes raw;
    EXPECT_TRUE(grid != nullptr && c.ReadChunk(*grid, raw).code == ContainerError::ChunkCrc);
    EXPECT_TRUE(c.VerifySimHash().code == ContainerError::ChunkCrc);
    std::string err;
    EXPECT_TRUE(DumpText(c, &err).empty());
    EXPECT_TRUE(!err.empty());
    LoadedSim ls;
    bool cross = true;
    EXPECT_TRUE(!LoadSim(c, ls, err, cross));
    EXPECT_TRUE(!cross);
  }

  { // GPLY's id plane holds surface id 5 which the surface table lacks. The container is fine; the chunk decoder and the
    // cross-chunk validation (ValidateSimData, which a caller can reach with hand-built data) both refuse it.
    const Bytes f = MustRead("gpl_bad_surface_id");
    MapContainer c;
    EXPECT_TRUE(MapContainer::Open(f.data(), f.size(), all, c).ok());
    LoadedSim ls;
    std::string err;
    bool cross = false;
    EXPECT_TRUE(!LoadSim(c, ls, err, cross));
    EXPECT_TRUE(err.find("surface id") != std::string::npos);
    std::string dumpErr;
    EXPECT_TRUE(DumpText(c, &dumpErr).empty());
    EXPECT_TRUE(dumpErr.find("surface id") != std::string::npos);

    // The same rule inside ValidateSimData: take the valid map, put the foreign id into the decoded plane.
    const Bytes good = MustRead("extended_min");
    MapContainer cg;
    EXPECT_TRUE(MapContainer::Open(good.data(), good.size(), all, cg).ok());
    LoadedSim lg;
    EXPECT_TRUE(LoadSim(cg, lg, err, cross));
    EXPECT_TRUE(lg.sim.gply.has_value() && !lg.sim.gply->ids.empty());
    if (lg.sim.gply && !lg.sim.gply->ids.empty()) {
      EXPECT_TRUE(ValidateSimData(lg.sim, err));
      lg.sim.gply->ids[0] = 5;
      EXPECT_TRUE(!ValidateSimData(lg.sim, err));
      EXPECT_TRUE(err.find("surface id") != std::string::npos);
    }
  }
}

// ---- scatter golden ------------------------------------------------------------------------------------------------------

struct FlatGround : ScatterSampler
{
  float Height(float, float) const override { return 10.0f; }
};

void TestScatter()
{
  bool ok = false;
  const std::string expected = ReadText("golden/scatter_expected.txt", ok);
  EXPECT_TRUE(ok);
  auto value = [&](const std::string& key) {
    const std::string k = "\n" + key + " = ";
    const std::size_t p = ("\n" + expected).find(k);
    if (p == std::string::npos) return std::string();
    const std::size_t s = p + k.size();
    const std::size_t e = ("\n" + expected).find('\n', s);
    return ("\n" + expected).substr(s, e - s);
  };
  const std::string fileName = value("file"), count = value("count"), sha = value("sha256");
  EXPECT_TRUE(!fileName.empty() && !count.empty() && !sha.empty());

  const Bytes file = MustRead(fileName.substr(0, fileName.rfind('.')));
  MapContainer c;
  EXPECT_TRUE(MapContainer::Open(file.data(), file.size(), AllFeatures(), c).ok());
  const ChunkEntry* e = nullptr;
  EXPECT_TRUE(c.FindChunk("SCAT", 0, &e));
  if (!e) return;
  Bytes raw;
  EXPECT_TRUE(c.ReadChunk(*e, raw).ok());
  ScatChunk scat;
  ChunkCtx ctx;
  std::string err;
  EXPECT_TRUE(DecodeScat(raw.data(), raw.size(), ctx, scat, err));
  EXPECT_TRUE(!scat.layer.empty());
  if (scat.layer.empty()) return;

  // "layer = 0", "grid = 64x48 cells": the whole grid (cellSize 1, origin 0).
  const FlatGround sampler;
  const std::vector<ScatterInstance> v = PlaceScatter(scat.layer[0], 0, sampler, 0.0f, 0.0f, 64.0f, 48.0f);
  Bytes packed;
  auto put32 = [&](std::uint32_t w) {
    for (int i = 0; i < 4; ++i) packed.push_back(static_cast<std::uint8_t>(w >> (8 * i)));
  };
  auto putF = [&](float f) {
    std::uint32_t w;
    std::memcpy(&w, &f, 4);
    put32(w);
  };
  for (const ScatterInstance& s : v) {
    put32(s.variant);
    putF(s.x);
    putF(s.z);
    putF(s.y);
    putF(s.scale);
    putF(s.yawDeg);
    putF(s.tint);
  }
  EXPECT_EQ(std::to_string(v.size()), count);
  EXPECT_EQ(Sha256Hex(packed.data(), packed.size()), sha);
  EXPECT_EQ(packed.size(), v.size() * 28);
}

// ---- TextDump::Quote against json.dumps(ensure_ascii=True) -----------------------------------------------------------

void TestQuote()
{
  EXPECT_EQ(TextDump::Quote(""), std::string("\"\""));
  EXPECT_EQ(TextDump::Quote("plain /path/x.dds"), std::string("\"plain /path/x.dds\"")); // '/' is not escaped
  EXPECT_EQ(TextDump::Quote("q\" b\\ n\n r\r t\t b\b f\f"), std::string("\"q\\\" b\\\\ n\\n r\\r t\\t b\\b f\\f\""));
  EXPECT_EQ(TextDump::Quote(std::string("\x01\x1f", 2)), std::string("\"\\u0001\\u001f\""));
  EXPECT_EQ(TextDump::Quote("\x7f"), std::string("\"\x7f\"")); // json leaves DEL alone
  EXPECT_EQ(TextDump::Quote("caf\xc3\xa9"), std::string("\"caf\\u00e9\""));                // U+00E9
  EXPECT_EQ(TextDump::Quote("\xe2\x82\xac"), std::string("\"\\u20ac\""));                      // U+20AC
  EXPECT_EQ(TextDump::Quote("\xef\xbf\xbd"), std::string("\"\\ufffd\""));                      // U+FFFD itself
  EXPECT_EQ(TextDump::Quote("\xf0\x9f\x98\x80"), std::string("\"\\ud83d\\ude00\""));           // U+1F600: surrogate pair
  EXPECT_EQ(TextDump::Quote("\xf4\x8f\xbf\xbf"), std::string("\"\\udbff\\udfff\""));           // U+10FFFF
  // The reader refuses invalid UTF-8 in file strings (strict like Python's decoder).
  const char* bad[] = {"\xc0\x80", "\xe0\x80\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xff", "\x80", "\xc3", "\xe2\x82"};
  for (const char* b : bad) {
    Bytes w;
    const std::string s(b);
    w.push_back(static_cast<std::uint8_t>(s.size()));
    w.push_back(0);
    w.insert(w.end(), s.begin(), s.end());
    ByteReader r(w.data(), w.size());
    (void)r.str();
    EXPECT_TRUE(!r.ok());
  }
  Bytes good = {4, 0, 'c', 'a', 'f', 0xc3};
  good.push_back(0xa9);
  good[0] = 5;
  ByteReader r(good.data(), good.size());
  EXPECT_EQ(r.str(), std::string("caf\xc3\xa9"));
  EXPECT_TRUE(r.ok());
}

} // namespace

TEST(MapFormatGolden, Checks)
{
  const char* const valid[] = {"extended_min", "extended_full", "full3d_full", "extended_classic_equiv", "unknown_optional_chunk"};
  for (const char* name : valid) TestValid(name);

  { // The unknown optional chunk is skipped by the dump and does not change the simHash.
    bool ok = false;
    const std::string dump = ReadText("golden/unknown_optional_chunk.dump.txt", ok);
    EXPECT_TRUE(dump.find("chunk ZZZO inst=0 skipped\n") != std::string::npos);
    const std::string a = ReadText("golden/unknown_optional_chunk.simhash", ok), b = ReadText("golden/extended_min.simhash", ok);
    EXPECT_EQ(a, b);
  }

  TestNegative();
  TestScatter();
  TestQuote();
}
