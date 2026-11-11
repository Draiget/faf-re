// Container 3/4 reader tests: framing, validation, limits, simHash, text dump, format detection and a fuzz loop.
// The Sim and Render chunk families are written by other people: this test links tiny stand-ins (MF_STUB_FAMILIES).
#define MF_STUB_FAMILIES 1

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/ChunkFamilies.h"
#include "moho/sim/mapformat/MapContainer.h"
#include "moho/sim/mapformat/MapDump.h"
#include "moho/sim/mapformat/MapFormat.h"
#include "moho/sim/mapformat/MapFormatCommon.h"

using namespace moho::mapformat;
typedef std::vector<std::uint8_t> Bytes;

#ifdef MF_STUB_FAMILIES
namespace moho::mapformat {
// Sim stand-in: GRID = u32 cellsX, u32 cellsZ (fills ctx like the real one).
DecodeStatus DumpChunkSim(const std::string& id, std::uint16_t, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, TextDump& dump,
                          std::string& err)
{
  if (id != "GRID") return DecodeStatus::NotMine;
  ByteReader r(data, size);
  const std::uint32_t x = r.u32(), z = r.u32();
  if (!r.finish()) {
    err = "GRID: malformed";
    return DecodeStatus::Error;
  }
  ctx.cellsX = x;
  ctx.cellsZ = z;
  dump.U("GRID.cellsX", x);
  dump.U("GRID.cellsZ", z);
  return DecodeStatus::Ok;
}
// Render stand-in: DECL reports the grid size the dump had in the context; ERRR always fails.
DecodeStatus DumpChunkRender(const std::string& id, std::uint16_t, const std::uint8_t*, std::size_t, ChunkCtx& ctx, TextDump& dump,
                             std::string& err)
{
  if (id == "ERRR") {
    dump.U("ERRR.partial", 1);
    err = "ERRR: boom";
    return DecodeStatus::Error;
  }
  if (id != "DECL") return DecodeStatus::NotMine;
  dump.U("DECL.ctxCellsX", ctx.cellsX);
  dump.U("DECL.ctxCellsZ", ctx.cellsZ);
  return DecodeStatus::Ok;
}
} // namespace moho::mapformat
#endif

namespace {

// ------------------------------------------------------------------ test file builder
enum Codec { kRaw = 0, kDeflateStored = 1, kDeflateFixed = 2 };

struct TC
{
  std::string id;
  std::uint16_t flags = 0; // SIM / REQUIRED / DERIVED; DEFLATE is added by the builder
  std::uint32_t instance = 0;
  Bytes raw;
  int codec = kRaw;
  std::uint16_t version = 1;
  bool useOverride = false;
  Bytes storedOverride; // when set, these are the stored bytes (rawSize is still raw.size())
};

struct Opts
{
  std::uint32_t container = 3;
  std::uint16_t revision = 1;
  std::uint64_t required = 0, optional = 0;
};

TC Chunk(const char* id, std::uint16_t flags, Bytes raw, int codec = kRaw, std::uint32_t instance = 0)
{
  TC c;
  c.id = id;
  c.flags = flags;
  c.raw = std::move(raw);
  c.codec = codec;
  c.instance = instance;
  return c;
}

Bytes DeflateStored(const Bytes& raw)
{
  Bytes o;
  std::size_t pos = 0;
  do {
    const std::size_t n = std::min<std::size_t>(65535, raw.size() - pos);
    const bool last = pos + n == raw.size();
    o.push_back(last ? 1 : 0);
    o.push_back(static_cast<std::uint8_t>(n & 255));
    o.push_back(static_cast<std::uint8_t>(n >> 8));
    o.push_back(static_cast<std::uint8_t>(~n & 255));
    o.push_back(static_cast<std::uint8_t>((~n >> 8) & 255));
    o.insert(o.end(), raw.begin() + pos, raw.begin() + pos + n);
    pos += n;
  } while (pos < raw.size());
  return o;
}

// Literal-only fixed-Huffman deflate (valid, a different byte stream than the stored one for the same content).
Bytes DeflateFixed(const Bytes& raw)
{
  Bytes o;
  int n = 0;
  auto bit = [&](unsigned b) {
    if (n == 0) o.push_back(0);
    o.back() = static_cast<std::uint8_t>(o.back() | (b << n));
    n = (n + 1) & 7;
  };
  auto code = [&](unsigned v, int c) {
    for (int i = c - 1; i >= 0; --i) bit((v >> i) & 1);
  };
  bit(1);
  bit(1); // BTYPE 01, LSB first: 1, 0
  bit(0);
  for (std::uint8_t b : raw) {
    if (b < 144) code(0x30U + b, 8);
    else code(0x190U + (b - 144U), 9);
  }
  code(0, 7); // end of block (symbol 256)
  return o;
}

void Put(Bytes& b, std::size_t off, std::uint64_t v, int n)
{
  for (int i = 0; i < n; ++i) b[off + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}
std::uint64_t Get(const Bytes& b, std::size_t off, int n)
{
  std::uint64_t v = 0;
  for (int i = 0; i < n; ++i) v |= static_cast<std::uint64_t>(b[off + static_cast<std::size_t>(i)]) << (8 * i);
  return v;
}

// Header / entry field offsets.
enum { kHContainer = 4, kHRevision = 8, kHHeaderSize = 10, kHFlags = 12, kHFileSize = 16, kHDirOffset = 24, kHDirCount = 32, kHDirCrc = 36,
       kHRequired = 40, kHOptional = 48, kHGuid = 56, kHSimHash = 72, kHReserved = 104, kHReserved2 = 120, kHCrc = 124 };
enum { kEId = 0, kEVersion = 4, kEFlags = 6, kEInstance = 8, kECrc = 12, kEOffset = 16, kEStored = 24, kERaw = 32, kEReserved = 40 };

bool Less(const TC& a, const TC& b)
{
  const int c = std::memcmp(a.id.data(), b.id.data(), 4);
  return c != 0 ? c < 0 : a.instance < b.instance;
}

std::array<std::uint8_t, 32> ExpectedSimHash(std::vector<TC> v)
{
  std::sort(v.begin(), v.end(), Less);
  Sha256 h;
  for (const TC& c : v) {
    if (!(c.flags & kChunkSim)) continue;
    ByteWriter w;
    w.bytes(reinterpret_cast<const std::uint8_t*>(c.id.data()), 4);
    w.u16(c.version);
    w.u32(c.instance);
    w.u64(c.raw.size());
    h.Update(w.buf.data(), w.buf.size());
    h.Update(c.raw.data(), c.raw.size());
  }
  std::array<std::uint8_t, 32> out{};
  h.Final(out.data());
  return out;
}

// Recomputes the directory CRC and the header CRC after a test patched the file.
void FixCrcs(Bytes& b)
{
  const std::uint64_t dirOff = Get(b, kHDirOffset, 8), cnt = Get(b, kHDirCount, 4);
  if (dirOff <= b.size() && cnt * 48 <= b.size() - dirOff) Put(b, kHDirCrc, Crc32(b.data() + dirOff, static_cast<std::size_t>(cnt * 48)), 4);
  Put(b, kHCrc, Crc32(b.data(), 124), 4);
}

Bytes Build(std::vector<TC> chunks, const Opts& o = Opts())
{
  Bytes f(128, 0);
  std::vector<std::uint64_t> offsets(chunks.size());
  std::vector<std::uint64_t> stored(chunks.size());
  std::vector<std::uint32_t> crcs(chunks.size());
  for (std::size_t i = 0; i < chunks.size(); ++i) {
    TC& c = chunks[i];
    Bytes s = c.useOverride ? c.storedOverride : (c.codec == kDeflateStored ? DeflateStored(c.raw) : c.codec == kDeflateFixed ? DeflateFixed(c.raw) : c.raw);
    while (f.size() % 16) f.push_back(0);
    offsets[i] = f.size();
    stored[i] = s.size();
    crcs[i] = Crc32(s.data(), s.size());
    f.insert(f.end(), s.begin(), s.end());
  }
  while (f.size() % 16) f.push_back(0);
  const std::uint64_t dirOffset = f.size();
  std::vector<std::size_t> order(chunks.size());
  for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
  std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return Less(chunks[a], chunks[b]); });
  ByteWriter dir;
  for (std::size_t i : order) {
    const TC& c = chunks[i];
    char id[4] = {' ', ' ', ' ', ' '};
    std::memcpy(id, c.id.data(), std::min<std::size_t>(4, c.id.size()));
    dir.bytes(reinterpret_cast<const std::uint8_t*>(id), 4);
    dir.u16(c.version);
    dir.u16(static_cast<std::uint16_t>(c.flags | (c.codec ? kChunkDeflate : 0)));
    dir.u32(c.instance);
    dir.u32(crcs[i]);
    dir.u64(offsets[i]);
    dir.u64(stored[i]);
    dir.u64(c.raw.size());
    dir.u64(0);
  }
  f.insert(f.end(), dir.buf.begin(), dir.buf.end());
  Put(f, 0, kMapMagic, 4);
  Put(f, kHContainer, o.container, 4);
  Put(f, kHRevision, o.revision, 2);
  Put(f, kHHeaderSize, 128, 2);
  Put(f, kHFileSize, f.size(), 8);
  Put(f, kHDirOffset, dirOffset, 8);
  Put(f, kHDirCount, chunks.size(), 4);
  Put(f, kHRequired, o.required, 8);
  Put(f, kHOptional, o.optional, 8);
  for (int i = 0; i < 16; ++i) f[kHGuid + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(i);
  const auto sh = ExpectedSimHash(chunks);
  std::copy(sh.begin(), sh.end(), f.begin() + kHSimHash);
  FixCrcs(f);
  return f;
}

Bytes Pattern(std::size_t n, unsigned seed)
{
  Bytes b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>((i * 7 + seed * 31 + (i >> 3)) & 255);
  return b;
}

Bytes GridPayload(std::uint32_t x, std::uint32_t z)
{
  ByteWriter w;
  w.u32(x);
  w.u32(z);
  return w.buf;
}

// A representative small Extended file: sim + render + metadata, all three codecs, odd layout order.
std::vector<TC> SampleChunks()
{
  std::vector<TC> v;
  v.push_back(Chunk("META", 0, Pattern(70, 1), kDeflateFixed));
  v.push_back(Chunk("GRID", kChunkSim | kChunkRequired, GridPayload(4, 6)));
  v.push_back(Chunk("HGHT", kChunkSim | kChunkRequired, Pattern(200, 2), kDeflateStored));
  v.push_back(Chunk("DECL", 0, Pattern(8, 3)));
  v.push_back(Chunk("AREA", kChunkSim, Pattern(33, 4), kDeflateFixed));
  v.push_back(Chunk("PROB", kChunkDerived, Pattern(40, 5), kDeflateStored));
  return v;
}

Result OpenBuf(const Bytes& b, MapContainer& c, const OpenOptions& o = OpenOptions())
{
  return MapContainer::Open(b.data(), b.size(), o, c);
}

// The container points into the buffer: a temporary file image is parked here so it lives as long as the test.
Result OpenBuf(Bytes&& b, MapContainer& c, const OpenOptions& o = OpenOptions())
{
  static std::deque<Bytes> pool;
  pool.push_back(std::move(b));
  return OpenBuf(pool.back(), c, o);
}

OpenOptions AllFeatures()
{
  OpenOptions o;
  o.supportedFeatures = ~0ULL;
  return o;
}

ContainerError Code(const Bytes& b, const OpenOptions& o = OpenOptions())
{
  MapContainer c;
  return OpenBuf(b, c, o).code;
}

bool Contains(const std::string& s, const char* part) { return s.find(part) != std::string::npos; }

// Patches directory entry `idx` (directory order) and refreshes the CRCs so only the semantic checks can object.
void PatchEntry(Bytes& b, std::size_t idx, std::size_t field, std::uint64_t v, int n)
{
  Put(b, static_cast<std::size_t>(Get(b, kHDirOffset, 8)) + idx * 48 + field, v, n);
  FixCrcs(b);
}

// ------------------------------------------------------------------ tests
void TestValidFile()
{
  const std::vector<TC> chunks = SampleChunks();
  Opts o;
  o.required = kFeat_GridNonSquare | kFeat_GridLarge;
  o.optional = 0x1fa;
  const Bytes f = Build(chunks, o);
  MapContainer c;
  const Result r = OpenBuf(f, c);
  EXPECT_TRUE(r.ok());
  EXPECT_TRUE(c.valid());
  EXPECT_EQ(c.header().container, 3U);
  EXPECT_EQ(c.header().revision, 1);
  EXPECT_EQ(c.header().requiredFeatures, o.required);
  EXPECT_EQ(c.header().optionalFeatures, o.optional);
  EXPECT_EQ(c.header().mapGuid[15], 15);
  EXPECT_EQ(c.entries().size(), 6U);
  // Directory order is bytewise by id.
  const char* order[] = {"AREA", "DECL", "GRID", "HGHT", "META", "PROB"};
  for (std::size_t i = 0; i < 6 && i < c.entries().size(); ++i) EXPECT_EQ(c.entries()[i].Id(), std::string(order[i]));

  // Every chunk reads back exactly, whatever its codec.
  for (const TC& t : chunks) {
    const ChunkEntry* e = nullptr;
    EXPECT_TRUE(c.FindChunk(t.id.c_str(), t.instance, &e));
    if (!e) continue;
    std::vector<std::uint8_t> raw;
    const Result rr = c.ReadChunk(*e, raw);
    EXPECT_TRUE(rr.ok());
    EXPECT_TRUE(raw == t.raw);
    EXPECT_EQ(e->rawSize, static_cast<std::uint64_t>(t.raw.size()));
    EXPECT_EQ(e->deflated(), t.codec != kRaw);
    EXPECT_EQ(e->sim(), (t.flags & kChunkSim) != 0);
  }
  const ChunkEntry* none = nullptr;
  EXPECT_TRUE(!c.FindChunk("NOPE", 0, &none));
  EXPECT_TRUE(!c.FindChunk("GRID", 1, &none));
  EXPECT_TRUE(c.FindChunk("GRID", 0, nullptr));

  // simHash: header equals an independent computation and verifies.
  const auto want = ExpectedSimHash(chunks);
  std::array<std::uint8_t, 32> got{};
  EXPECT_TRUE(c.ComputeSimHash(got).ok());
  EXPECT_TRUE(got == want);
  EXPECT_TRUE(c.header().simHash == want);
  EXPECT_TRUE(c.VerifySimHash().ok());

  const SMapFormatInfo info = c.FormatInfo();
  EXPECT_TRUE(info.id == EMapFormat::Extended);
  EXPECT_EQ(info.revision, 1U);
  EXPECT_TRUE(info.simHash == want);
  EXPECT_TRUE(DescribeFormat(info).find("MapFormat: Extended rev 1 features req=0x3 opt=0x1fa simhash=") == 0);

  // Container 4 reads the same.
  Opts o4;
  o4.container = 4;
  MapContainer c4;
  EXPECT_TRUE(OpenBuf(Build(chunks, o4), c4).ok());
  EXPECT_TRUE(c4.FormatInfo().id == EMapFormat::Full3D);

  // Zero chunks and zero-size chunks are legal framing.
  MapContainer c0;
  EXPECT_TRUE(OpenBuf(Build({}), c0).ok());
  EXPECT_EQ(c0.entries().size(), 0U);
  std::vector<TC> z;
  z.push_back(Chunk("EMTY", 0, Bytes()));
  z.push_back(Chunk("EMT2", 0, Bytes(), kDeflateStored));
  MapContainer cz;
  EXPECT_TRUE(OpenBuf(Build(z), cz).ok());
  for (const ChunkEntry& e : cz.entries()) {
    std::vector<std::uint8_t> raw(5, 1);
    EXPECT_TRUE(cz.ReadChunk(e, raw).ok());
    EXPECT_TRUE(raw.empty());
  }
  // Repeated chunks: (id, instance) pairs.
  std::vector<TC> rep;
  rep.push_back(Chunk("SPLT", 0, Pattern(10, 1), kRaw, 2));
  rep.push_back(Chunk("SPLT", 0, Pattern(11, 2), kRaw, 0));
  rep.push_back(Chunk("SPLT", 0, Pattern(12, 3), kRaw, 1));
  MapContainer cr;
  EXPECT_TRUE(OpenBuf(Build(rep), cr).ok());
  EXPECT_EQ(cr.entries().size(), 3U);
  EXPECT_EQ(cr.entries()[0].instance, 0U);
  EXPECT_EQ(cr.entries()[2].instance, 2U);
  const ChunkEntry* e1 = nullptr;
  EXPECT_TRUE(cr.FindChunk("SPLT", 1, &e1) && e1 && e1->rawSize == 12);
}

void TestHeaderErrors()
{
  const Bytes good = Build(SampleChunks());
  EXPECT_TRUE(Code(good) == ContainerError::Ok);

  { // too small
    MapContainer c;
    EXPECT_TRUE(MapContainer::Open(good.data(), 127, OpenOptions(), c).code == ContainerError::TooSmall);
    EXPECT_TRUE(MapContainer::Open(nullptr, 0, OpenOptions(), c).code == ContainerError::TooSmall);
    EXPECT_TRUE(!c.valid());
  }
  { Bytes b = good; Put(b, 0, 0x12345678, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadMagic); }
  for (std::uint32_t v : {0U, 1U, 2U, 5U, 0xFFFFFFFFU}) {
    Bytes b = good;
    Put(b, kHContainer, v, 4);
    FixCrcs(b);
    MapContainer c;
    const Result r = OpenBuf(b, c);
    EXPECT_TRUE(r.code == ContainerError::UnsupportedContainer);
    if (v == 2) EXPECT_TRUE(Contains(r.message, "Classic"));
    else EXPECT_TRUE(Contains(r.message, std::to_string(v).c_str()));
  }
  { Bytes b = good; Put(b, kHRevision, 0, 2); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadRevision); }
  { Bytes b = good; Put(b, kHRevision, 2, 2); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::Ok); } // newer revision, nothing required
  { // newer revision that requires an unknown feature
    Bytes b = good;
    Put(b, kHRevision, 2, 2);
    Put(b, kHRequired, 1ULL << 50, 8);
    FixCrcs(b);
    MapContainer c;
    const Result r = OpenBuf(b, c);
    EXPECT_TRUE(r.code == ContainerError::UnsupportedFeature);
    EXPECT_TRUE(Contains(r.message, "BIT_50"));
  }
  { Bytes b = good; Put(b, kHHeaderSize, 64, 2); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadHeader); }
  { Bytes b = good; Put(b, kHHeaderSize, 144, 2); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadHeader); } // revision 1: exactly 128
  { // truncated and padded files
    Bytes b = good;
    b.pop_back();
    EXPECT_TRUE(Code(b) == ContainerError::FileSizeMismatch);
    b = good;
    b.push_back(0);
    EXPECT_TRUE(Code(b) == ContainerError::FileSizeMismatch);
    b.assign(good.begin(), good.begin() + 128);
    EXPECT_TRUE(Code(b) == ContainerError::FileSizeMismatch);
  }
  { // header CRC: change a byte the CRC covers without refreshing it; or the CRC itself
    Bytes b = good;
    b[kHGuid + 3] ^= 1;
    EXPECT_TRUE(Code(b) == ContainerError::HeaderCrc);
    b = good;
    b[kHCrc] ^= 0x80;
    EXPECT_TRUE(Code(b) == ContainerError::HeaderCrc);
  }
  { Bytes b = good; b[kHReserved + 5] = 1; FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadHeader); }
  { Bytes b = good; Put(b, kHReserved2, 1, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadHeader); }
  { Bytes b = good; Put(b, kHFlags, 2, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadHeader); }
  { Bytes b = good; Put(b, kHFlags, 1, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::Ok); } // has-signature flag is legal

  { // unsupported required features are named
    Bytes b = good;
    Put(b, kHRequired, kFeat_WaterBodies | kFeat_Levels | kFeat_WorldCollision | kFeat_GridNonSquare, 8);
    FixCrcs(b);
    MapContainer c;
    const Result r = OpenBuf(b, c);
    EXPECT_TRUE(r.code == ContainerError::UnsupportedFeature);
    EXPECT_TRUE(Contains(r.message, "WATER_BODIES"));
    EXPECT_TRUE(Contains(r.message, "LEVELS"));
    EXPECT_TRUE(Contains(r.message, "WORLD_COLLISION"));
    EXPECT_TRUE(!Contains(r.message, "GRID_NONSQUARE"));
    EXPECT_TRUE(!c.valid());
    EXPECT_TRUE(Code(b, AllFeatures()) == ContainerError::Ok); // a tool that implements everything
    OpenOptions only;
    only.supportedFeatures = kFeat_WaterBodies | kFeat_Levels | kFeat_WorldCollision | kFeat_GridNonSquare;
    EXPECT_TRUE(Code(b, only) == ContainerError::Ok);
    Put(b, kHRequired, kFeat_GridNonSquare | kFeat_GridLarge | kFeat_HeightFine, 8);
    FixCrcs(b);
    EXPECT_TRUE(Code(b) == ContainerError::Ok); // reader-decodable bits are supported by default
    EXPECT_TRUE((SupportedFeaturesMask() & kFeat_Levels) == 0);
    EXPECT_TRUE((SupportedFeaturesMask() & kFeat_GridNonSquare) != 0);
  }
  { // limits on the file
    OpenOptions o;
    o.limits.maxFileSize = good.size() - 1;
    EXPECT_TRUE(Code(good, o) == ContainerError::LimitExceeded);
  }
}

void TestDirectoryErrors()
{
  const Bytes good = Build(SampleChunks());
  const std::size_t dirOff = static_cast<std::size_t>(Get(good, kHDirOffset, 8));
  { Bytes b = good; Put(b, kHDirCount, 4097, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::LimitExceeded); }
  { OpenOptions o; o.limits.maxDirEntries = 5; EXPECT_TRUE(Code(good, o) == ContainerError::LimitExceeded); }
  { Bytes b = good; Put(b, kHDirOffset, b.size() + 16, 8); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadDirectory); }
  { Bytes b = good; Put(b, kHDirOffset, 0xFFFFFFFFFFFFFFF0ULL, 8); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadDirectory); }
  { Bytes b = good; Put(b, kHDirOffset, 64, 8); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadDirectory); } // inside the header
  { Bytes b = good; Put(b, kHDirCount, 0xFFFFFFFFULL, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::LimitExceeded); }
  { Bytes b = good; Put(b, kHDirCount, 4096, 4); FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadDirectory); } // entries would pass the file end
  { Bytes b = good; b[dirOff + 20] ^= 1; EXPECT_TRUE(Code(b) == ContainerError::DirectoryCrc); }
  { Bytes b = good; Put(b, kHDirCrc, Get(b, kHDirCrc, 4) ^ 1, 4); Put(b, kHCrc, Crc32(b.data(), 124), 4); EXPECT_TRUE(Code(b) == ContainerError::DirectoryCrc); }

  { // unsorted: swap entries 0 and 1
    Bytes b = good;
    for (int i = 0; i < 48; ++i) std::swap(b[dirOff + static_cast<std::size_t>(i)], b[dirOff + 48 + static_cast<std::size_t>(i)]);
    FixCrcs(b);
    MapContainer c;
    const Result r = OpenBuf(b, c);
    EXPECT_TRUE(r.code == ContainerError::BadChunkEntry);
    EXPECT_TRUE(Contains(r.message, "sorted"));
  }
  { // duplicate (id, instance)
    Bytes b = good;
    std::memcpy(&b[dirOff + 48], &b[dirOff], 4);
    Put(b, dirOff + 48 + kEInstance, Get(b, dirOff + kEInstance, 4), 4);
    FixCrcs(b);
    MapContainer c;
    const Result r = OpenBuf(b, c);
    EXPECT_TRUE(r.code == ContainerError::BadChunkEntry);
    EXPECT_TRUE(Contains(r.message, "duplicate"));
  }
  { Bytes b = good; b[dirOff + 1] = 0x07; FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); }  // control character in an id
  { Bytes b = good; b[dirOff + 2] = ' '; FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); }   // space in an id
  { Bytes b = good; b[dirOff + 3] = 0xC3; FixCrcs(b); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); }  // non-ASCII
  { Bytes b = good; PatchEntry(b, 0, kEFlags, kChunkSim | kChunkDerived, 2); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); }
  { Bytes b = good; PatchEntry(b, 0, kEFlags, 0x10, 2); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); } // future codec bit
  { Bytes b = good; PatchEntry(b, 0, kEReserved, 1, 8); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); }
  { Bytes b = good; PatchEntry(b, 1, kERaw, Get(b, dirOff + 48 + kERaw, 8) + 1, 8); EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry); } // DECL: raw, not deflate

  { // alignment, range, overlap
    Bytes b = good;
    PatchEntry(b, 0, kEOffset, Get(b, dirOff + kEOffset, 8) + 1, 8);
    EXPECT_TRUE(Code(b) == ContainerError::BadChunkEntry);
    b = good;
    PatchEntry(b, 0, kEOffset, 0, 8);
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOutOfRange);
    b = good;
    PatchEntry(b, 0, kEOffset, 112, 8);
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOutOfRange);
    b = good;
    PatchEntry(b, 0, kEOffset, dirOff, 8); // starts at the directory (offset valid only for empty chunks)
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOutOfRange);
    b = good;
    PatchEntry(b, 0, kEStored, 0xFFFFFFFFFFFFFFF0ULL, 8);
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOutOfRange);
    b = good;
    PatchEntry(b, 0, kEOffset, 0xFFFFFFFFFFFFFFF0ULL, 8);
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOutOfRange);
    b = good;
    PatchEntry(b, 0, kEStored, Get(b, dirOff + kEStored, 8) + 16, 8); // grows into the directory or the next chunk
    const ContainerError grow = Code(b);
    EXPECT_TRUE(grow == ContainerError::ChunkOverlap || grow == ContainerError::ChunkOutOfRange || grow == ContainerError::BadChunkEntry);
    b = good;
    PatchEntry(b, 1, kEOffset, Get(b, dirOff + kEOffset, 8), 8); // two chunks at one offset
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOverlap);
  }
  { // an overlap by one aligned block
    std::vector<TC> v;
    v.push_back(Chunk("AAAA", 0, Pattern(40, 1)));
    v.push_back(Chunk("BBBB", 0, Pattern(40, 2)));
    Bytes b = Build(v);
    const std::size_t d = static_cast<std::size_t>(Get(b, kHDirOffset, 8));
    const std::uint64_t first = Get(b, d + kEOffset, 8);
    PatchEntry(b, 1, kEOffset, first + 16, 8);
    EXPECT_TRUE(Code(b) == ContainerError::ChunkOverlap);
  }
  { // required-chunk callback
    OpenOptions o;
    o.isKnownChunk = [](const char id[4], std::uint16_t) { return std::memcmp(id, "GRID", 4) == 0; };
    EXPECT_TRUE(Code(good, o) == ContainerError::UnknownRequiredChunk); // HGHT is REQUIRED and unknown to this callback
    std::vector<TC> v;
    v.push_back(Chunk("GRID", kChunkSim | kChunkRequired, GridPayload(1, 1)));
    v.push_back(Chunk("ZZZZ", 0, Pattern(4, 1)));
    EXPECT_TRUE(Code(Build(v), o) == ContainerError::Ok); // unknown optional chunks are skipped, not refused
    v[1].flags = kChunkRequired;
    EXPECT_TRUE(Code(Build(v), o) == ContainerError::UnknownRequiredChunk);
  }
}

void TestChunkReading()
{
  const std::vector<TC> chunks = SampleChunks();
  const Bytes good = Build(chunks);
  MapContainer c;
  EXPECT_TRUE(OpenBuf(good, c).ok());

  { // flipping a stored byte fails exactly that chunk
    for (const ChunkEntry& victim : c.entries()) {
      if (victim.storedSize == 0) continue;
      Bytes b = good;
      b[static_cast<std::size_t>(victim.offset) + static_cast<std::size_t>(victim.storedSize) / 2] ^= 0x10;
      MapContainer c2;
      EXPECT_TRUE(OpenBuf(b, c2).ok()); // payload corruption is found when the chunk is read
      for (const ChunkEntry& e : c2.entries()) {
        std::vector<std::uint8_t> raw;
        const Result r = c2.ReadChunk(e, raw);
        if (std::memcmp(e.id, victim.id, 4) == 0) {
          EXPECT_TRUE(r.code == ContainerError::ChunkCrc);
          EXPECT_TRUE(Contains(r.message, victim.Id().c_str()));
        } else {
          EXPECT_TRUE(r.ok());
        }
      }
      EXPECT_TRUE(c2.VerifySimHash().ok() || victim.sim()); // only a corrupted SIM chunk may break the hash verification
    }
  }
  { // wrong CRC field
    Bytes b = good;
    const std::size_t d = static_cast<std::size_t>(Get(b, kHDirOffset, 8));
    PatchEntry(b, 0, kECrc, Get(b, d + kECrc, 4) ^ 0xFFFF, 4);
    MapContainer c2;
    EXPECT_TRUE(OpenBuf(b, c2).ok());
    std::vector<std::uint8_t> raw;
    EXPECT_TRUE(c2.ReadChunk(c2.entries()[0], raw).code == ContainerError::ChunkCrc);
    EXPECT_TRUE(raw.empty());
  }
  { // a ChunkEntry from outside is re-validated against this buffer
    ChunkEntry fake = c.entries()[0];
    fake.offset = good.size() + 1000;
    std::vector<std::uint8_t> raw;
    EXPECT_TRUE(c.ReadChunk(fake, raw).code == ContainerError::ChunkOutOfRange);
    fake = c.entries()[0];
    fake.storedSize = ~0ULL;
    EXPECT_TRUE(c.ReadChunk(fake, raw).code == ContainerError::ChunkOutOfRange);
  }
}

void TestBombs()
{
  // rawSize beyond the per-chunk limit, declared in an uncompressed-looking way: refused at Open.
  {
    std::vector<TC> v;
    v.push_back(Chunk("BOMB", 0, Pattern(30, 1), kDeflateStored));
    Bytes b = Build(v);
    PatchEntry(b, 0, kERaw, (1ULL << 30) + 1, 8);
    const ContainerError e = Code(b);
    EXPECT_TRUE(e == ContainerError::LimitExceeded || e == ContainerError::RatioExceeded);
    PatchEntry(b, 0, kERaw, 0xFFFFFFFFFFFFFFFFULL, 8);
    EXPECT_TRUE(Code(b) == ContainerError::LimitExceeded);
  }
  // The ratio cap: stored 100 bytes may declare at most 100 * 1032 raw bytes.
  {
    std::vector<TC> v;
    TC t = Chunk("RATI", 0, Bytes(103200), kDeflateStored);
    t.useOverride = true;
    t.storedOverride = Pattern(100, 9); // not a valid stream; only the framing is under test here
    v.push_back(t);
    Bytes ok = Build(v);
    MapContainer c;
    EXPECT_TRUE(OpenBuf(ok, c).ok());
    std::vector<std::uint8_t> raw;
    EXPECT_TRUE(c.ReadChunk(c.entries()[0], raw).code == ContainerError::InflateFailed); // framing fine, content garbage
    EXPECT_TRUE(raw.empty());
    Bytes over = ok;
    PatchEntry(over, 0, kERaw, 103201, 8);
    MapContainer c2;
    const Result r = OpenBuf(over, c2);
    EXPECT_TRUE(r.code == ContainerError::RatioExceeded);
    EXPECT_TRUE(Contains(r.message, "RATI"));
    // A stricter caller-supplied ratio limit applies too.
    OpenOptions tight;
    tight.limits.maxInflateRatio = 500;
    EXPECT_TRUE(Code(ok, tight) == ContainerError::RatioExceeded);
  }
  // rawSize lies about a perfectly valid stream: too large and too small both fail at read time, never overrun.
  {
    std::vector<TC> v;
    v.push_back(Chunk("LIES", 0, Pattern(50, 3), kDeflateFixed));
    for (int delta : {-1, 1, 5, 100}) {
      Bytes b = Build(v);
      PatchEntry(b, 0, kERaw, static_cast<std::uint64_t>(50 + delta), 8);
      MapContainer c;
      const ContainerError e = OpenBuf(b, c).code;
      if (e != ContainerError::Ok) continue; // e.g. ratio refusal
      std::vector<std::uint8_t> raw;
      EXPECT_TRUE(c.ReadChunk(c.entries()[0], raw).code == ContainerError::InflateFailed);
    }
  }
  // Trailing bytes after the deflate stream are refused.
  {
    std::vector<TC> v;
    TC t = Chunk("TAIL", 0, Pattern(20, 1), kDeflateStored);
    t.useOverride = true;
    t.storedOverride = DeflateStored(t.raw);
    t.storedOverride.push_back(0xEE);
    t.storedOverride.push_back(0xEE);
    v.push_back(t);
    MapContainer c;
    EXPECT_TRUE(OpenBuf(Build(v), c).ok());
    std::vector<std::uint8_t> raw;
    const Result r = c.ReadChunk(c.entries()[0], raw);
    EXPECT_TRUE(r.code == ContainerError::InflateFailed);
    EXPECT_TRUE(Contains(r.message, "follow"));
  }
  // The total decoded budget of one load.
  {
    std::vector<TC> v;
    v.push_back(Chunk("AAAA", 0, Pattern(40, 1), kDeflateStored));
    v.push_back(Chunk("BBBB", 0, Pattern(40, 2)));
    v.push_back(Chunk("CCCC", 0, Pattern(10, 3)));
    OpenOptions o;
    o.limits.maxTotalRaw = 85;
    MapContainer c;
    EXPECT_TRUE(OpenBuf(Build(v), c, o).ok());
    std::uint64_t budget = 0;
    std::vector<std::uint8_t> raw;
    EXPECT_TRUE(c.ReadChunk(c.entries()[0], raw, &budget).ok());
    EXPECT_EQ(budget, 40U);
    EXPECT_TRUE(c.ReadChunk(c.entries()[1], raw, &budget).ok());
    EXPECT_EQ(budget, 80U);
    EXPECT_TRUE(c.ReadChunk(c.entries()[2], raw, &budget).code == ContainerError::LimitExceeded);
    EXPECT_EQ(budget, 80U); // a refused read does not count
    EXPECT_TRUE(c.ReadChunk(c.entries()[2], raw).ok()); // no budget given: unchecked
  }
  // Single chunk limit configurable.
  {
    std::vector<TC> v;
    v.push_back(Chunk("BIGG", 0, Pattern(100, 1)));
    OpenOptions o;
    o.limits.maxChunkRaw = 99;
    EXPECT_TRUE(Code(Build(v), o) == ContainerError::LimitExceeded);
  }
}

void TestSimHash()
{
  std::vector<TC> base = SampleChunks();
  const Bytes fa = Build(base);
  MapContainer ca;
  EXPECT_TRUE(OpenBuf(fa, ca).ok());
  const auto ha = ca.header().simHash;

  // Recompressing every chunk differently does not change it.
  {
    std::vector<TC> v = base;
    for (std::size_t i = 0; i < v.size(); ++i) v[i].codec = (v[i].codec + 1 + static_cast<int>(i)) % 3;
    const Bytes f = Build(v);
    MapContainer c;
    EXPECT_TRUE(OpenBuf(f, c).ok());
    EXPECT_TRUE(f != fa);
    EXPECT_TRUE(c.header().simHash == ha);
    EXPECT_TRUE(c.VerifySimHash().ok());
    // Chunk layout order in the file does not matter either.
    std::reverse(v.begin(), v.end());
    MapContainer c2;
    EXPECT_TRUE(OpenBuf(Build(v), c2).ok());
    EXPECT_TRUE(c2.header().simHash == ha);
  }
  // A SIM chunk byte changes it.
  for (const char* id : {"GRID", "HGHT", "AREA"}) {
    std::vector<TC> v = base;
    for (TC& t : v) if (t.id == id) t.raw[t.raw.size() / 2] ^= 1;
    const Bytes f = Build(v);
    MapContainer c;
    EXPECT_TRUE(OpenBuf(f, c).ok());
    EXPECT_TRUE(c.header().simHash != ha);
    // An honest header with the OLD hash over the NEW content is caught by VerifySimHash.
    Bytes forged = f;
    std::copy(ha.begin(), ha.end(), forged.begin() + kHSimHash);
    FixCrcs(forged);
    MapContainer cf;
    EXPECT_TRUE(OpenBuf(forged, cf).ok());
    const Result r = cf.VerifySimHash();
    EXPECT_TRUE(r.code == ContainerError::SimHashMismatch);
  }
  // Version and instance of a SIM chunk are part of the hash.
  {
    std::vector<TC> v = base;
    for (TC& t : v) if (t.id == "GRID") t.version = 2;
    MapContainer c;
    EXPECT_TRUE(OpenBuf(Build(v), c).ok());
    EXPECT_TRUE(c.header().simHash != ha);
    v = base;
    for (TC& t : v) if (t.id == "GRID") t.instance = 1;
    MapContainer c2;
    EXPECT_TRUE(OpenBuf(Build(v), c2).ok());
    EXPECT_TRUE(c2.header().simHash != ha);
  }
  // Render, metadata and derived chunks do not change it, nor do the flags REQUIRED / the optional feature word.
  for (const char* id : {"DECL", "META", "PROB"}) {
    std::vector<TC> v = base;
    for (TC& t : v) if (t.id == id) t.raw[0] ^= 0xFF;
    const Bytes f = Build(v);
    MapContainer c;
    EXPECT_TRUE(OpenBuf(f, c).ok());
    EXPECT_TRUE(f != fa);
    EXPECT_TRUE(c.header().simHash == ha);
    EXPECT_TRUE(c.VerifySimHash().ok());
  }
  {
    std::vector<TC> v = base;
    v.push_back(Chunk("EXTR", 0, Pattern(9, 1)));
    MapContainer c;
    EXPECT_TRUE(OpenBuf(Build(v), c).ok());
    EXPECT_TRUE(c.header().simHash == ha);
  }
  // No SIM chunk at all: the hash of the empty input.
  {
    std::vector<TC> v;
    v.push_back(Chunk("DECL", 0, Pattern(9, 1)));
    MapContainer c;
    EXPECT_TRUE(OpenBuf(Build(v), c).ok());
    std::uint8_t digest[32];
    Sha256 s;
    s.Final(digest);
    EXPECT_TRUE(std::equal(c.header().simHash.begin(), c.header().simHash.end(), digest));
    EXPECT_TRUE(c.VerifySimHash().ok());
  }
  // A corrupt SIM chunk makes ComputeSimHash fail with the chunk error.
  {
    Bytes f = fa;
    const ChunkEntry* g = nullptr;
    EXPECT_TRUE(ca.FindChunk("GRID", 0, &g));
    f[static_cast<std::size_t>(g->offset)] ^= 1;
    MapContainer c;
    EXPECT_TRUE(OpenBuf(f, c).ok());
    std::array<std::uint8_t, 32> h{};
    EXPECT_TRUE(c.ComputeSimHash(h).code == ContainerError::ChunkCrc);
  }
}

void TestDump()
{
  std::vector<TC> v;
  v.push_back(Chunk("AREA", kChunkSim, Pattern(5, 1)));                     // no family knows it, optional: skipped
  v.push_back(Chunk("DECL", 0, Pattern(8, 2), kDeflateStored));              // render stand-in: sees the GRID size from pass 1
  v.push_back(Chunk("ERRR", 0, Pattern(3, 3)));                              // fails in an optional class: error line
  v.push_back(Chunk("GRID", kChunkSim | kChunkRequired, GridPayload(4, 6))); // sorts after DECL
  Opts o;
  o.required = 3;
  o.optional = 0x1fa;
  o.container = 3;
  const Bytes f = Build(v, o);
  MapContainer c;
  EXPECT_TRUE(OpenBuf(f, c).ok());
  std::string err = "stale";
  const std::string text = DumpText(c, &err);
  EXPECT_TRUE(err.empty());
  const std::string want = "file.container = 3\n"
                           "file.revision = 1\n"
                           "file.flags = 0x00000000\n"
                           "file.required = 0x0000000000000003\n"
                           "file.optional = 0x00000000000001fa\n"
                           "file.mapGuid = 000102030405060708090a0b0c0d0e0f\n"
                           "file.simHash = " + HexString(c.header().simHash.data(), 32) + "\n"
                           "chunk AREA inst=0 skipped\n"
                           "chunk DECL inst=0 ver=1 flags=0x0008 raw=8\n"
                           "DECL.ctxCellsX = 4\n"
                           "DECL.ctxCellsZ = 6\n"
                           "chunk ERRR inst=0 error \"ERRR: boom\"\n"
                           "chunk GRID inst=0 ver=1 flags=0x0003 raw=8\n"
                           "GRID.cellsX = 4\n"
                           "GRID.cellsZ = 6\n";
  EXPECT_EQ(text, want);
  EXPECT_TRUE(DumpText(c, nullptr) == want); // err is optional

  // The same chunk failing in a SIM or REQUIRED class is fatal: empty result, reason in err.
  for (std::uint16_t cls : {static_cast<std::uint16_t>(kChunkSim), static_cast<std::uint16_t>(kChunkRequired)}) {
    std::vector<TC> w = v;
    for (TC& t : w) if (t.id == "ERRR") t.flags = cls;
    MapContainer cw;
    EXPECT_TRUE(OpenBuf(Build(w, o), cw).ok());
    std::string e2;
    EXPECT_TRUE(DumpText(cw, &e2).empty());
    EXPECT_TRUE(Contains(e2, "boom"));
  }
  { // required chunk nobody understands
    std::vector<TC> w = v;
    w.push_back(Chunk("QQQQ", kChunkRequired, Pattern(3, 1)));
    MapContainer cw;
    EXPECT_TRUE(OpenBuf(Build(w, o), cw).ok());
    std::string e2;
    EXPECT_TRUE(DumpText(cw, &e2).empty());
    EXPECT_TRUE(Contains(e2, "QQQQ"));
  }
  { // container read failure: optional chunk gets an error line, the rest continues
    Bytes bad = f;
    const ChunkEntry* e = nullptr;
    EXPECT_TRUE(c.FindChunk("DECL", 0, &e));
    bad[static_cast<std::size_t>(e->offset)] ^= 1;
    MapContainer cb;
    EXPECT_TRUE(OpenBuf(bad, cb).ok());
    const std::string t = DumpText(cb, nullptr);
    EXPECT_TRUE(Contains(t.c_str(), "chunk DECL inst=0 error \"chunk 'DECL' instance 0: CRC mismatch"));
    EXPECT_TRUE(Contains(t.c_str(), "GRID.cellsZ = 6\n"));
  }
  { // A chunk version this reader does not know is skipped like an unknown chunk; with the REQUIRED flag it refuses the dump.
    std::vector<TC> w;
    w.push_back(Chunk("DECL", 0, Pattern(8, 2)));
    w.push_back(Chunk("GRID", kChunkSim | kChunkRequired, GridPayload(4, 6)));
    w[0].version = 2;
    MapContainer c;
    EXPECT_TRUE(OpenBuf(Build(w), c).ok());
    const std::string t = DumpText(c, nullptr);
    EXPECT_TRUE(Contains(t.c_str(), "chunk DECL inst=0 skipped\n"));
    EXPECT_TRUE(Contains(t.c_str(), "chunk GRID inst=0 ver=1 flags=0x0003 raw=8\n"));
    w[0].flags = kChunkRequired;
    MapContainer cr;
    std::string err;
    EXPECT_TRUE(OpenBuf(Build(w), cr).ok());
    EXPECT_TRUE(DumpText(cr, &err).empty());
    EXPECT_TRUE(err.find("DECL") != std::string::npos);
  }
  { // Full3D: the world3d family answers (LODG with zero proxies), a container 3 file leaves the same chunk skipped
    std::vector<TC> w;
    w.push_back(Chunk("LODG", 0, Bytes{0, 0, 0, 0}));
    Opts o4;
    o4.container = 4;
    MapContainer c4, c3;
    EXPECT_TRUE(OpenBuf(Build(w, o4), c4).ok());
    const std::string t4 = DumpText(c4, nullptr);
    EXPECT_TRUE(Contains(t4.c_str(), "chunk LODG inst=0 ver=1 flags=0x0000 raw=4\nLODG.proxies.count = 0\n"));
    EXPECT_TRUE(OpenBuf(Build(w), c3).ok());
    EXPECT_TRUE(Contains(DumpText(c3, nullptr).c_str(), "chunk LODG inst=0 skipped\n"));
    // A malformed Full3D chunk in a render class is an error line, not fatal.
    w[0].raw = Bytes{9, 0, 0, 0};
    MapContainer cm;
    EXPECT_TRUE(OpenBuf(Build(w, o4), cm).ok());
    EXPECT_TRUE(Contains(DumpText(cm, nullptr).c_str(), "chunk LODG inst=0 error \"LODG:"));
  }
}

void TestFormatDetection()
{
  auto hdr = [](std::uint32_t magic, std::uint32_t container) {
    Bytes b(8);
    Put(b, 0, magic, 4);
    Put(b, 4, container, 4);
    return b;
  };
  std::string why;
  Bytes b = hdr(kMapMagic, 2);
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, false, &why) == EMapFormat::Classic);
  EXPECT_TRUE(why.empty());
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, true, &why) == EMapFormat::Legacy25D);
  b = hdr(kMapMagic, 3);
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, false) == EMapFormat::Extended);
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, true) == EMapFormat::Extended); // mesh flag only matters for container 2
  b = hdr(kMapMagic, 4);
  EXPECT_TRUE(DetectFromHeader(b.data(), 12, false, &why) == EMapFormat::Full3D); // extra bytes ignored
  b = hdr(kMapMagic, 7);
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, false, &why) == EMapFormat::Unknown);
  EXPECT_TRUE(Contains(why, "UnsupportedContainer") && Contains(why, "7"));
  b = hdr(kMapMagic, 0);
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, false, &why) == EMapFormat::Unknown);
  b = hdr(0xDEADBEEF, 3);
  EXPECT_TRUE(DetectFromHeader(b.data(), 8, false, &why) == EMapFormat::Unknown);
  EXPECT_TRUE(Contains(why, "NotAMap"));
  EXPECT_TRUE(DetectFromHeader(b.data(), 7, false, &why) == EMapFormat::Unknown);
  EXPECT_TRUE(DetectFromHeader(nullptr, 0, false, &why) == EMapFormat::Unknown);
  EXPECT_TRUE(Contains(why, "NotAMap"));
  EXPECT_TRUE(DetectFromHeader(nullptr, 0, false) == EMapFormat::Unknown);

  EXPECT_EQ(std::string(MapFormatName(EMapFormat::Classic)), std::string("Classic"));
  EXPECT_EQ(std::string(MapFormatName(EMapFormat::Legacy25D)), std::string("Legacy25D"));
  EXPECT_EQ(std::string(MapFormatName(EMapFormat::Extended)), std::string("Extended"));
  EXPECT_EQ(std::string(MapFormatName(EMapFormat::Full3D)), std::string("Full3D"));
  EXPECT_EQ(std::string(MapFormatName(EMapFormat::Unknown)), std::string("Unknown"));

  EXPECT_EQ(FeatureNamesText(kFeat_WaterBodies | kFeat_Levels), std::string("WATER_BODIES, LEVELS"));
  EXPECT_EQ(FeatureNamesText(0), std::string());
  EXPECT_EQ(FeatureNamesText(1ULL << 40), std::string("BIT_40"));

  SMapFormatInfo i;
  i.id = EMapFormat::Full3D;
  i.revision = 1;
  i.requiredFeatures = 0x3;
  i.optionalFeatures = 0x1fa;
  for (int k = 0; k < 32; ++k) i.simHash[static_cast<std::size_t>(k)] = static_cast<std::uint8_t>(0xab + k);
  EXPECT_EQ(DescribeFormat(i), std::string("MapFormat: Full3D rev 1 features req=0x3 opt=0x1fa simhash=abacadaeafb0b1b2..."));
  i.requiredFeatures = 0;
  EXPECT_TRUE(Contains(DescribeFormat(i), "req=0x0 "));
  SMapFormatInfo cl;
  cl.id = EMapFormat::Classic;
  EXPECT_EQ(DescribeFormat(cl), std::string("MapFormat: Classic"));
  SMapFormatInfo un;
  un.reason = "NotAMap: x";
  EXPECT_EQ(DescribeFormat(un), std::string("MapFormat: Unknown (NotAMap: x)"));
}

// Padding between chunks and the header/directory are the only bytes no CRC covers.
std::vector<bool> CoveredBytes(const Bytes& f)
{
  std::vector<bool> cov(f.size(), false);
  MapContainer c;
  EXPECT_TRUE(OpenBuf(f, c).ok());
  for (std::size_t i = 0; i < 128; ++i) cov[i] = true;
  const std::size_t d = static_cast<std::size_t>(c.header().dirOffset);
  for (std::size_t i = d; i < f.size(); ++i) cov[i] = true;
  for (const ChunkEntry& e : c.entries())
    for (std::uint64_t i = 0; i < e.storedSize; ++i) cov[static_cast<std::size_t>(e.offset + i)] = true;
  return cov;
}

// Exercise everything a reader does with an opened container; the result is irrelevant, surviving is the test.
bool Exercise(const Bytes& f, bool* anyReadFailed = nullptr)
{
  MapContainer c;
  OpenOptions o = AllFeatures();
  if (!OpenBuf(f, c, o).ok()) return false;
  bool failed = false;
  std::uint64_t budget = 0;
  for (const ChunkEntry& e : c.entries()) {
    std::vector<std::uint8_t> raw;
    if (!c.ReadChunk(e, raw, &budget).ok()) failed = true;
  }
  std::string err;
  (void)DumpText(c, &err);
  (void)c.VerifySimHash();
  (void)c.FormatInfo();
  if (anyReadFailed) *anyReadFailed = failed;
  return true;
}

void TestFuzz()
{
  std::vector<TC> v = SampleChunks();
  v.push_back(Chunk("SPLT", 0, Pattern(90, 7), kDeflateFixed, 3));
  Opts o;
  o.container = 4;
  v.push_back(Chunk("CIDX", 0, Bytes{0, 0, 0, 0}));
  const Bytes f = Build(v, o);
  const std::vector<bool> covered = CoveredBytes(f);
  EXPECT_TRUE(Exercise(f));

  // (1) Every truncation is refused; none crashes.
  for (std::size_t len = 0; len < f.size(); ++len) {
    MapContainer c;
    if (MapContainer::Open(f.data(), len, OpenOptions(), c).ok()) {
      std::printf("  truncation to %zu accepted\n", len);
      EXPECT_TRUE(false);
    }
  }
  // (2) Flip every byte with several masks: unless the byte is padding, the damage must be found by Open or by reading.
  for (std::size_t i = 0; i < f.size(); ++i) {
    for (unsigned mask : {0x01U, 0x10U, 0x80U, 0xFFU}) {
      Bytes b = f;
      b[i] = static_cast<std::uint8_t>(b[i] ^ mask);
      bool readFailed = false;
      const bool opened = Exercise(b, &readFailed);
      if (opened && !readFailed && covered[i]) {
        std::printf("  flipped byte %zu mask %02x was accepted\n", i, mask);
        EXPECT_TRUE(false);
      }
    }
  }
  // (3) Structural fuzz: damage the header and directory, then repair both CRCs so only the semantic checks stand
  //     between the garbage and the reader. Nothing may crash; accepted files must read without overruns.
  const std::size_t dirOff = static_cast<std::size_t>(Get(f, kHDirOffset, 8));
  std::vector<std::size_t> sensitive;
  for (std::size_t i = 0; i < 120; ++i) sensitive.push_back(i);
  for (std::size_t i = dirOff; i < f.size(); ++i) sensitive.push_back(i);
  unsigned long long acceptedMutants = 0;
  for (std::size_t i : sensitive) {
    for (unsigned mask : {0x01U, 0x02U, 0x08U, 0x40U, 0x80U, 0xFFU}) {
      Bytes b = f;
      b[i] = static_cast<std::uint8_t>(b[i] ^ mask);
      FixCrcs(b);
      if (Exercise(b)) ++acceptedMutants;
      // Also with 64-bit fields pushed to extremes: set the whole 8-byte word around i to all ones.
      Bytes w = f;
      for (std::size_t k = 0; k < 8 && i + k < w.size(); ++k) w[i + k] = 0xFF;
      FixCrcs(w);
      (void)Exercise(w);
    }
  }
  EXPECT_TRUE(acceptedMutants > 0); // some benign changes (padding-like fields) are legitimately accepted
}

} // namespace

TEST(MapFormatContainer, Checks)
{
  TestValidFile();
  TestHeaderErrors();
  TestDirectoryErrors();
  TestChunkReading();
  TestBombs();
  TestSimHash();
  TestDump();
  TestFormatDetection();
  TestFuzz();
}
