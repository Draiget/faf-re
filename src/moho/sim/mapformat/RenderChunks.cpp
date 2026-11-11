// Decoders and text dumpers for the Extended METADATA and RENDER chunks. See RenderChunks.h and
// docs/mapformat/EXTENDED.md. Standard library only.
#include "moho/sim/mapformat/RenderChunks.h"

#include <cstring>

namespace moho::mapformat {
namespace {

constexpr std::uint32_t kMaxImageDim = 16384; // SPLT's stated limit, reused for every image-like chunk
constexpr std::uint64_t kMaxProbeGrid = 1ULL << 22;

bool Bad(std::string& e, const char* id, const std::string& msg)
{
  e = std::string(id) + ": " + msg;
  return false;
}

// REQ: first a sticky-failure check (a failed read means a truncated or out-of-range payload, so the later value
// checks would only produce misleading messages), then the value check. `r`, `err`, `kId` must be in scope.
#define REQ(cond, msg)                                                                                            \
  do {                                                                                                            \
    if (!r.ok()) return Bad(err, kId, "truncated payload or count/size out of range");                          \
    if (!(cond)) return Bad(err, kId, msg);                                                                       \
  } while (0)
#define DONE()                                                                                                    \
  do {                                                                                                            \
    if (!r.ok()) return Bad(err, kId, "truncated payload or count/size out of range");                           \
    if (!r.atEnd()) return Bad(err, kId, std::to_string(r.remaining()) + " trailing bytes");                     \
    return true;                                                                                                  \
  } while (0)
#define BEGIN(ID)                                                                                                 \
  ByteReader r(d, n);                                                                                             \
  const char* const kId = ID;                                                                                     \
  (void)ctx;

template <std::size_t N>
std::array<float, N> RVec(ByteReader& r)
{
  std::array<float, N> v{};
  for (auto& x : v) x = r.f32();
  return v;
}

template <std::size_t N>
void DV(TextDump& d, const std::string& p, const std::array<float, N>& v)
{
  d.Vec(p, v.data(), static_cast<int>(N));
}

Blob ReadBlob(ByteReader& r, std::uint64_t count)
{
  Blob b;
  b.data = r.bytes(count);
  b.size = r.ok() ? count : 0;
  return b;
}

/// Returns nullptr, or why the shape is invalid (corners not ordered, negative radius).
const char* ReadShape(ByteReader& r, Shape& s)
{
  const char* bad = nullptr;
  s = Shape();
  s.kind = r.u8();
  switch (s.kind) {
  case 0:
    s.rect = RVec<4>(r);
    if (s.rect[2] < s.rect[0] || s.rect[3] < s.rect[1]) bad = "rect corners are not ordered";
    break;
  case 1: {
    const std::uint32_t c = r.count(8, 1024);
    if (r.ok() && c < 3) r.fail(); // polygons have 3..1024 points
    s.points.resize(c);
    for (auto& p : s.points) p = RVec<2>(r);
    break;
  }
  case 2:
    s.circle = RVec<3>(r);
    if (s.circle[2] < 0.0f) bad = "circle radius is negative";
    break;
  default: r.fail(); break;
  }
  return bad;
}

void DumpShape(TextDump& d, const std::string& p, const Shape& s)
{
  d.U(p + ".kind", s.kind);
  if (s.kind == 0) {
    d.F32(p + ".x0", s.rect[0]);
    d.F32(p + ".z0", s.rect[1]);
    d.F32(p + ".x1", s.rect[2]);
    d.F32(p + ".z1", s.rect[3]);
  }
  if (s.kind == 1) {
    d.Count(p + ".points", s.points.size());
    for (std::size_t i = 0; i < s.points.size(); ++i) DV(d, TextDump::Idx(p + ".points", i), s.points[i]);
  }
  if (s.kind == 2) {
    d.F32(p + ".cx", s.circle[0]);
    d.F32(p + ".cz", s.circle[1]);
    d.F32(p + ".r", s.circle[2]);
  }
}

Pose ReadPose(ByteReader& r)
{
  Pose p;
  p.pos = RVec<3>(r);
  p.yawDeg = r.f32();
  p.pitchDeg = r.f32();
  p.fovDeg = r.f32();
  return p;
}

void DumpPose(TextDump& d, const std::string& p, const Pose& v)
{
  DV(d, p + ".pos", v.pos);
  d.F32(p + ".yawDeg", v.yawDeg);
  d.F32(p + ".pitchDeg", v.pitchDeg);
  d.F32(p + ".fovDeg", v.fovDeg);
}

/// `plane<T>`: `u8 predictor`, then rows*cols*channels elements; reads, bounds-checks (before allocating) and
/// reverses the predictor. `predictorOut` receives the stored predictor.
bool ReadPlane(ByteReader& r, std::uint64_t rows, std::uint64_t cols, std::uint32_t channels, std::uint32_t elemBytes,
               std::vector<std::uint8_t>& out, std::uint8_t* predictorOut = nullptr)
{
  const std::uint8_t pred = r.u8();
  if (predictorOut) *predictorOut = pred;
  if (!r.ok() || pred > 3 || rows > 0xFFFFFFFFULL || cols > 0xFFFFFFFFULL) {
    r.fail();
    return false;
  }
  const std::uint64_t total = rows * cols * channels * elemBytes;
  const std::uint8_t* p = r.bytes(total);
  if (!r.ok()) return false;
  out.assign(p, p + static_cast<std::size_t>(total));
  UnpredictPlane(out.data(), static_cast<std::uint32_t>(rows), static_cast<std::uint32_t>(cols), channels, elemBytes,
                 pred);
  return true;
}

std::uint64_t BlockBytes(std::uint32_t w, std::uint32_t h, std::uint64_t blockSize)
{
  return ((static_cast<std::uint64_t>(w) + 3) / 4) * ((static_cast<std::uint64_t>(h) + 3) / 4) * blockSize;
}

bool HasBannedExtension(const std::string& s)
{
  static const char* const kBanned[] = {".lua", ".bp", ".scd", ".xsb", ".xwb", ".exe", ".dll"};
  for (const char* ext : kBanned) {
    const std::size_t n = std::strlen(ext);
    if (s.size() < n) continue;
    bool same = true;
    for (std::size_t i = 0; i < n && same; ++i) {
      char c = s[s.size() - n + i];
      if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
      same = c == ext[i];
    }
    if (same) return true;
  }
  return false;
}

bool ValidAssetName(const std::string& s)
{
  if (s.empty() || s[0] == '/' || HasBannedExtension(s)) return false;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= s.size(); ++i) {
    if (i == s.size() || s[i] == '/') {
      const std::string part = s.substr(start, i - start);
      if (part.empty() || part == "." || part == "..") return false;
      start = i + 1;
    } else if (s[i] == '\\' || s[i] == ':' || static_cast<unsigned char>(s[i]) < 0x20) {
      return false;
    }
  }
  return true;
}

/// Reads `path` fields; `ok` turns false on the first invalid one (the decoder reports it after the last read).
struct PathReader
{
  ByteReader& r;
  bool ok = true;
  explicit PathReader(ByteReader& reader) : r(reader) {}
  std::string operator()()
  {
    std::string s = r.str();
    if (r.ok() && !IsValidVfsPath(s)) ok = false;
    return s;
  }
};
constexpr const char* kPathMsg = "path is not a lower case VFS path starting with /";

void DumpU16Array(TextDump& d, const std::string& p, const std::vector<std::uint16_t>& v)
{
  d.Count(p, v.size());
  for (std::size_t i = 0; i < v.size(); ++i) d.U(TextDump::Idx(p, i), v[i]);
}

std::vector<std::uint16_t> ReadU16Array(ByteReader& r, std::uint32_t maxCount)
{
  std::vector<std::uint16_t> v;
  const std::uint32_t c = r.count(2, maxCount);
  v.resize(c);
  for (auto& x : v) x = r.u16();
  return v;
}

std::string Rgb(const std::array<std::uint8_t, 3>& c)
{
  return "[" + std::to_string(c[0]) + ", " + std::to_string(c[1]) + ", " + std::to_string(c[2]) + "]";
}

} // namespace

// ================================================================================================= META

bool DecodeMeta(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, MetaChunk& out, std::string& err)
{
  BEGIN("META")
  out = MetaChunk();
  REQ(n <= (1u << 20), "chunk larger than 1 MiB");
  out.name = r.str();
  out.loc.resize(r.count(6, 64));
  for (auto& l : out.loc) {
    l.lang = r.str();
    l.name = r.str();
    l.description = r.str();
  }
  out.author = r.str();
  out.version = r.str();
  out.license = r.str();
  out.website = r.str();
  out.tags.resize(r.count(2, 64));
  for (auto& t : out.tags) t = r.str();
  out.mapType = r.u8();
  out.minPlayers = r.u8();
  out.maxPlayers = r.u8();
  REQ(out.mapType <= 3, "unknown mapType");
  REQ(out.minPlayers <= out.maxPlayers, "minPlayers above maxPlayers");
  out.req.resize(r.count(6, 64));
  for (auto& q : out.req) {
    q.kind = r.str();
    q.id = r.str();
    q.minVersion = r.str();
  }
  out.createdUtc = r.u64();
  out.modifiedUtc = r.u64();
  out.toolName = r.str();
  out.toolVersion = r.str();
  DONE();
}

void DumpMeta(TextDump& d, const MetaChunk& c)
{
  d.Str("META.name", c.name);
  d.Count("META.locs", c.loc.size());
  for (std::size_t i = 0; i < c.loc.size(); ++i) {
    const std::string p = TextDump::Idx("META.locs", i);
    d.Str(p + ".lang", c.loc[i].lang);
    d.Str(p + ".name", c.loc[i].name);
    d.Str(p + ".description", c.loc[i].description);
  }
  d.Str("META.author", c.author);
  d.Str("META.version", c.version);
  d.Str("META.license", c.license);
  d.Str("META.website", c.website);
  d.Count("META.tags", c.tags.size());
  for (std::size_t i = 0; i < c.tags.size(); ++i) d.Str(TextDump::Idx("META.tags", i), c.tags[i]);
  d.U("META.mapType", c.mapType);
  d.U("META.minPlayers", c.minPlayers);
  d.U("META.maxPlayers", c.maxPlayers);
  d.Count("META.reqs", c.req.size());
  for (std::size_t i = 0; i < c.req.size(); ++i) {
    const std::string p = TextDump::Idx("META.reqs", i);
    d.Str(p + ".kind", c.req[i].kind);
    d.Str(p + ".id", c.req[i].id);
    d.Str(p + ".minVersion", c.req[i].minVersion);
  }
  d.U("META.createdUtc", c.createdUtc);
  d.U("META.modifiedUtc", c.modifiedUtc);
  d.Str("META.toolName", c.toolName);
  d.Str("META.toolVersion", c.toolVersion);
}

// ================================================================================================= PREV

bool DecodePrev(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, PrevChunk& out, std::string& err)
{
  BEGIN("PREV")
  out = PrevChunk();
  out.kind = r.u8();
  out.width = r.u32();
  out.height = r.u32();
  out.byteCount = r.u32();
  REQ(out.kind <= 1, "unknown kind");
  REQ(out.width >= 1 && out.width <= 2048 && out.height >= 1 && out.height <= 2048, "width/height outside 1..2048");
  out.data = ReadBlob(r, out.byteCount);
  DONE();
}

void DumpPrev(TextDump& d, const PrevChunk& c)
{
  d.U("PREV.kind", c.kind);
  d.U("PREV.width", c.width);
  d.U("PREV.height", c.height);
  d.U("PREV.byteCount", c.byteCount);
  d.Bytes("PREV.data", c.data.data, static_cast<std::size_t>(c.data.size));
}

// ================================================================================================= GENR

bool DecodeGenr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, GenrChunk& out, std::string& err)
{
  BEGIN("GENR")
  out = GenrChunk();
  out.generator = r.str();
  out.generatorVersion = r.str();
  out.seed = r.u64();
  out.jsonLen = r.u32();
  REQ(out.jsonLen <= 256u * 1024u, "jsonLen above 256 KiB");
  out.json = ReadBlob(r, out.jsonLen);
  out.notes.resize(r.count(4, 256));
  for (auto& e : out.notes) {
    e.key = r.str();
    e.value = r.str();
  }
  DONE();
}

void DumpGenr(TextDump& d, const GenrChunk& c)
{
  d.Str("GENR.generator", c.generator);
  d.Str("GENR.generatorVersion", c.generatorVersion);
  d.U("GENR.seed", c.seed);
  d.U("GENR.jsonLen", c.jsonLen);
  d.Bytes("GENR.json", c.json.data, static_cast<std::size_t>(c.json.size));
  d.Count("GENR.notes", c.notes.size());
  for (std::size_t i = 0; i < c.notes.size(); ++i) {
    const std::string p = TextDump::Idx("GENR.notes", i);
    d.Str(p + ".key", c.notes[i].key);
    d.Str(p + ".value", c.notes[i].value);
  }
}

// ================================================================================================= SIGN

bool DecodeSign(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, SignChunk& out, std::string& err)
{
  BEGIN("SIGN")
  out = SignChunk();
  out.algo = r.u8();
  REQ(out.algo == 1, "unknown signature algorithm");
  const std::uint8_t* k = r.bytes(32);
  if (k) std::memcpy(out.publicKey.data(), k, 32);
  const std::uint8_t* s = r.bytes(64);
  if (s) std::memcpy(out.signature.data(), s, 64);
  out.keyName = r.str();
  DONE();
}

void DumpSign(TextDump& d, const SignChunk& c)
{
  d.U("SIGN.algo", c.algo);
  d.Bytes("SIGN.publicKey", c.publicKey.data(), c.publicKey.size());
  d.Bytes("SIGN.signature", c.signature.data(), c.signature.size());
  d.Str("SIGN.keyName", c.keyName);
}

// ================================================================================================= ASST

bool DecodeAsst(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, AsstChunk& out, std::string& err)
{
  BEGIN("ASST")
  out = AsstChunk();
  out.asset.resize(r.count(11, 65535)); // str(2) + kind(1) + size(8)
  for (auto& a : out.asset) {
    a.name = r.str();
    a.kind = r.u8();
    a.size = r.u64();
    if (!r.ok()) break;
    REQ(ValidAssetName(a.name), "asset name is not a relative path below the embedded root");
    REQ(a.kind <= 5, "unknown asset kind");
    a.data = ReadBlob(r, a.size);
  }
  DONE();
}

void DumpAsst(TextDump& d, const AsstChunk& c)
{
  d.Count("ASST.assets", c.asset.size());
  for (std::size_t i = 0; i < c.asset.size(); ++i) {
    const std::string p = TextDump::Idx("ASST.assets", i);
    d.Str(p + ".name", c.asset[i].name);
    d.U(p + ".kind", c.asset[i].kind);
    d.U(p + ".size", c.asset[i].size);
    d.Bytes(p + ".data", c.asset[i].data.data, static_cast<std::size_t>(c.asset[i].data.size));
  }
}

// ================================================================================================= LAYR

bool DecodeLayr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, LayrChunk& out, std::string& err)
{
  BEGIN("LAYR")
  out = LayrChunk();
  out.layer.resize(r.count(4, 255));
  for (auto& l : out.layer) {
    l.name = r.str();
    l.defaultVisible = r.u8();
    l.flags = r.u8();
    REQ(l.defaultVisible <= 1, "defaultVisible must be 0 or 1");
    REQ(l.flags == 0, "layer flags must be 0");
  }
  DONE();
}

void DumpLayr(TextDump& d, const LayrChunk& c)
{
  d.Count("LAYR.layers", c.layer.size());
  for (std::size_t i = 0; i < c.layer.size(); ++i) {
    const std::string p = TextDump::Idx("LAYR.layers", i);
    d.Str(p + ".name", c.layer[i].name);
    d.U(p + ".defaultVisible", c.layer[i].defaultVisible);
    d.U(p + ".flags", c.layer[i].flags);
  }
}

// ================================================================================================= MATL

bool DecodeMatl(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, MatlChunk& out, std::string& err)
{
  BEGIN("MATL")
  out = MatlChunk();
  out.material.resize(r.count(48, 1024));
  PathReader P(r);
  for (auto& m : out.material) {
    m.id = r.u16();
    m.name = r.str();
    m.albedo = P();
    m.normal = P();
    m.orm = P();
    m.height = P();
    m.flags = r.u16();
    REQ((m.flags & ~0x1FU) == 0, "material flags use undefined bits");
    m.tileSize = r.f32();
    m.rotationDeg = r.f32();
    m.normalStrength = r.f32();
    m.roughnessScale = r.f32();
    m.metalness = r.f32();
    m.parallaxScale = r.f32();
    m.heightBlendSharpness = r.f32();
    m.macroInfluence = r.f32();
    m.gameplaySurface = r.u16();
  }
  REQ(P.ok, kPathMsg);
  for (std::size_t i = 0; i < out.material.size(); ++i)
    for (std::size_t j = 0; j < i; ++j) REQ(out.material[i].id != out.material[j].id, "duplicate material id");
  DONE();
}

void DumpMatl(TextDump& d, const MatlChunk& c)
{
  d.Count("MATL.materials", c.material.size());
  for (std::size_t i = 0; i < c.material.size(); ++i) {
    const std::string p = TextDump::Idx("MATL.materials", i);
    const MatlMaterial& m = c.material[i];
    d.U(p + ".id", m.id);
    d.Str(p + ".name", m.name);
    d.Str(p + ".albedo", m.albedo);
    d.Str(p + ".normal", m.normal);
    d.Str(p + ".orm", m.orm);
    d.Str(p + ".height", m.height);
    d.U(p + ".flags", m.flags);
    d.F32(p + ".tileSize", m.tileSize);
    d.F32(p + ".rotationDeg", m.rotationDeg);
    d.F32(p + ".normalStrength", m.normalStrength);
    d.F32(p + ".roughnessScale", m.roughnessScale);
    d.F32(p + ".metalness", m.metalness);
    d.F32(p + ".parallaxScale", m.parallaxScale);
    d.F32(p + ".heightBlendSharpness", m.heightBlendSharpness);
    d.F32(p + ".macroInfluence", m.macroInfluence);
    d.U(p + ".gameplaySurface", m.gameplaySurface);
  }
}

// ================================================================================================= SPLT

bool DecodeSplt(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, SpltChunk& out, std::string& err)
{
  BEGIN("SPLT")
  out = SpltChunk();
  out.width = r.u32();
  out.height = r.u32();
  out.mode = r.u8();
  REQ(out.width >= 1 && out.width <= kMaxImageDim && out.height >= 1 && out.height <= kMaxImageDim,
      "width/height outside 1..16384");
  REQ(out.mode <= 1, "unknown mode");
  if (out.mode == 0) {
    ReadPlane(r, out.height, out.width, 4, 1, out.indices);
    ReadPlane(r, out.height, out.width, 4, 1, out.weights);
    REQ(r.ok(), "truncated plane");
    for (std::size_t i = 0; i + 3 < out.weights.size(); i += 4)
      REQ(out.weights[i] + out.weights[i + 1] + out.weights[i + 2] + out.weights[i + 3] == 255, "texel weights do not sum to 255");
  } else {
    out.layers = r.u8();
    REQ(out.layers >= 1 && out.layers <= 32, "layers outside 1..32");
    // `array<u16> materialIds (length layers)`: read with its u32 count prefix, which must equal `layers`.
    out.materialIds = ReadU16Array(r, 32);
    REQ(out.materialIds.size() == out.layers, "materialIds count differs from layers");
    out.planes.resize(out.layers);
    for (auto& p : out.planes) ReadPlane(r, out.height, out.width, 1, 1, p);
  }
  DONE();
}

void DumpSplt(TextDump& d, const SpltChunk& c)
{
  d.U("SPLT.width", c.width);
  d.U("SPLT.height", c.height);
  d.U("SPLT.mode", c.mode);
  if (c.mode == 0) {
    d.Plane("SPLT.indices", c.width, c.height, c.indices.data(), c.indices.size());
    d.Plane("SPLT.weights", c.width, c.height, c.weights.data(), c.weights.size());
  } else {
    d.U("SPLT.layers", c.layers);
    DumpU16Array(d, "SPLT.materialIds", c.materialIds);
    d.Count("SPLT.planes", c.planes.size());
    for (std::size_t i = 0; i < c.planes.size(); ++i)
      d.Plane(TextDump::Idx("SPLT.planes", i), c.width, c.height, c.planes[i].data(), c.planes[i].size());
  }
}

// ================================================================================================= NRML / AOMP / MACR

namespace {
bool ImageDims(ByteReader& r, std::uint32_t& w, std::uint32_t& h)
{
  w = r.u32();
  h = r.u32();
  return r.ok() && w >= 1 && w <= kMaxImageDim && h >= 1 && h <= kMaxImageDim;
}
} // namespace

bool DecodeNrml(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, NrmlChunk& out, std::string& err)
{
  BEGIN("NRML")
  out = NrmlChunk();
  const bool dimsOk = ImageDims(r, out.width, out.height);
  out.format = r.u8();
  REQ(dimsOk, "width/height outside 1..16384");
  REQ(out.format <= 1, "unknown format");
  const std::uint64_t expect = out.format == 0 ? static_cast<std::uint64_t>(out.width) * out.height * 2
                                               : BlockBytes(out.width, out.height, 16);
  REQ(r.remaining() == expect, "data size does not match width/height/format");
  out.data = ReadBlob(r, expect);
  DONE();
}

void DumpNrml(TextDump& d, const NrmlChunk& c)
{
  d.U("NRML.width", c.width);
  d.U("NRML.height", c.height);
  d.U("NRML.format", c.format);
  d.Bytes("NRML.data", c.data.data, static_cast<std::size_t>(c.data.size));
}

bool DecodeAomp(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, AompChunk& out, std::string& err)
{
  BEGIN("AOMP")
  out = AompChunk();
  const bool dimsOk = ImageDims(r, out.width, out.height);
  out.kind = r.u8();
  out.format = r.u8();
  REQ(dimsOk, "width/height outside 1..16384");
  REQ(out.kind <= 1, "unknown kind");
  REQ(out.format <= 1, "unknown format");
  const std::uint64_t expect =
      out.format == 0 ? static_cast<std::uint64_t>(out.width) * out.height : BlockBytes(out.width, out.height, 8);
  REQ(r.remaining() == expect, "data size does not match width/height/format");
  out.data = ReadBlob(r, expect);
  DONE();
}

void DumpAomp(TextDump& d, const AompChunk& c)
{
  d.U("AOMP.width", c.width);
  d.U("AOMP.height", c.height);
  d.U("AOMP.kind", c.kind);
  d.U("AOMP.format", c.format);
  d.Bytes("AOMP.data", c.data.data, static_cast<std::size_t>(c.data.size));
}

bool DecodeMacr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, MacrChunk& out, std::string& err)
{
  BEGIN("MACR")
  out = MacrChunk();
  const bool dimsOk = ImageDims(r, out.width, out.height);
  out.format = r.u8();
  out.strength = r.f32();
  REQ(dimsOk, "width/height outside 1..16384");
  REQ(out.format <= 1, "unknown format");
  const std::uint64_t expect =
      out.format == 0 ? static_cast<std::uint64_t>(out.width) * out.height * 3 : BlockBytes(out.width, out.height, 8);
  REQ(r.remaining() == expect, "data size does not match width/height/format");
  out.data = ReadBlob(r, expect);
  DONE();
}

void DumpMacr(TextDump& d, const MacrChunk& c)
{
  d.U("MACR.width", c.width);
  d.U("MACR.height", c.height);
  d.U("MACR.format", c.format);
  d.F32("MACR.strength", c.strength);
  d.Bytes("MACR.data", c.data.data, static_cast<std::size_t>(c.data.size));
}

// ================================================================================================= HDET / HOLE

bool DecodeHdet(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, HdetChunk& out, std::string& err)
{
  ByteReader r(d, n);
  const char* const kId = "HDET";
  out = HdetChunk();
  out.log2Mult = r.u8();
  out.lsb = r.f32();
  out.predictor = r.u8();
  REQ(out.log2Mult >= 1 && out.log2Mult <= 3, "log2Mult outside 1..3");
  REQ(out.predictor <= 3, "unknown predictor");
  REQ(ctx.cellsX != 0 && ctx.cellsZ != 0, "grid size unknown (GRID must be decoded first)");
  const std::uint64_t m = 1ULL << out.log2Mult;
  const std::uint64_t w = static_cast<std::uint64_t>(ctx.cellsX) * m + 1;
  const std::uint64_t h = static_cast<std::uint64_t>(ctx.cellsZ) * m + 1;
  REQ(r.remaining() == w * h * 2, "sample count does not match the grid");
  out.width = static_cast<std::uint32_t>(w);
  out.height = static_cast<std::uint32_t>(h);
  const std::uint8_t* p = r.bytes(w * h * 2);
  REQ(p != nullptr, "truncated");
  out.samples.assign(p, p + static_cast<std::size_t>(w * h * 2));
  UnpredictPlane(out.samples.data(), out.height, out.width, 1, 2, out.predictor);
  DONE();
}

void DumpHdet(TextDump& d, const HdetChunk& c)
{
  d.U("HDET.log2Mult", c.log2Mult);
  d.F32("HDET.lsb", c.lsb);
  d.U("HDET.predictor", c.predictor);
  d.Plane("HDET.samples", c.width, c.height, c.samples.data(), c.samples.size());
}

bool DecodeHole(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, HoleChunk& out, std::string& err)
{
  ByteReader r(d, n);
  const char* const kId = "HOLE";
  out = HoleChunk();
  REQ(ctx.cellsX != 0 && ctx.cellsZ != 0, "grid size unknown (GRID must be decoded first)");
  const std::uint64_t expect = BitmaskBytes(ctx.cellsX, ctx.cellsZ);
  REQ(n == expect, "mask size does not match the grid");
  out.mask = ReadBlob(r, expect);
  DONE();
}

void DumpHole(TextDump& d, const HoleChunk& c)
{
  d.Bytes("HOLE.mask", c.mask.data, static_cast<std::size_t>(c.mask.size));
}

// ================================================================================================= LITE

bool DecodeLite(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, LiteChunk& out, std::string& err)
{
  BEGIN("LITE")
  out = LiteChunk();
  out.sunDir = RVec<3>(r);
  out.sunColor = RVec<3>(r);
  out.sunIntensity = r.f32();
  out.sunAngularDeg = r.f32();
  out.hasMoon = r.u8();
  REQ(out.hasMoon <= 1, "hasMoon is not 0 or 1");
  if (out.hasMoon) {
    out.moon.dir = RVec<3>(r);
    out.moon.color = RVec<3>(r);
    out.moon.intensity = r.f32();
    out.moon.angularDeg = r.f32();
  }
  out.ambientMode = r.u8();
  REQ(out.ambientMode <= 2, "unknown ambientMode");
  out.ambient = RVec<3>(r);
  out.ground = RVec<3>(r);
  out.ambientIntensity = r.f32();
  if (out.ambientMode == 2)
    for (auto& v : out.sh) v = r.f32();
  out.shadowFill = RVec<3>(r);
  out.shadowDistance = r.f32();
  out.cascades = r.u8();
  REQ(out.cascades >= 1 && out.cascades <= 4, "cascades outside 1..4");
  out.shadowBias = r.f32();
  out.shadowStrength = r.f32();
  out.fogMode = r.u8();
  REQ(out.fogMode <= 3, "unknown fogMode");
  out.fogColor = RVec<3>(r);
  out.fogStart = r.f32();
  out.fogEnd = r.f32();
  out.fogDensity = r.f32();
  out.fogHeightFalloff = r.f32();
  out.fogBaseHeight = r.f32();
  out.toneMap = r.u8();
  REQ(out.toneMap <= 2, "unknown toneMap");
  out.exposureEV = r.f32();
  out.bloomIntensity = r.f32();
  out.bloomThreshold = r.f32();
  PathReader P(r);
  out.lut = P();
  REQ(P.ok, kPathMsg);
  DONE();
}

void DumpLite(TextDump& d, const LiteChunk& c)
{
  DV(d, "LITE.sunDir", c.sunDir);
  DV(d, "LITE.sunColor", c.sunColor);
  d.F32("LITE.sunIntensity", c.sunIntensity);
  d.F32("LITE.sunAngularDeg", c.sunAngularDeg);
  d.U("LITE.hasMoon", c.hasMoon);
  if (c.hasMoon) {
    DV(d, "LITE.moon.dir", c.moon.dir);
    DV(d, "LITE.moon.color", c.moon.color);
    d.F32("LITE.moon.intensity", c.moon.intensity);
    d.F32("LITE.moon.angularDeg", c.moon.angularDeg);
  }
  d.U("LITE.ambientMode", c.ambientMode);
  DV(d, "LITE.ambient", c.ambient);
  DV(d, "LITE.ground", c.ground);
  d.F32("LITE.ambientIntensity", c.ambientIntensity);
  if (c.ambientMode == 2) {
    d.Count("LITE.sh", c.sh.size());
    for (std::size_t i = 0; i < c.sh.size(); ++i) d.F32(TextDump::Idx("LITE.sh", i), c.sh[i]);
  }
  DV(d, "LITE.shadowFill", c.shadowFill);
  d.F32("LITE.shadowDistance", c.shadowDistance);
  d.U("LITE.cascades", c.cascades);
  d.F32("LITE.shadowBias", c.shadowBias);
  d.F32("LITE.shadowStrength", c.shadowStrength);
  d.U("LITE.fogMode", c.fogMode);
  DV(d, "LITE.fogColor", c.fogColor);
  d.F32("LITE.fogStart", c.fogStart);
  d.F32("LITE.fogEnd", c.fogEnd);
  d.F32("LITE.fogDensity", c.fogDensity);
  d.F32("LITE.fogHeightFalloff", c.fogHeightFalloff);
  d.F32("LITE.fogBaseHeight", c.fogBaseHeight);
  d.U("LITE.toneMap", c.toneMap);
  d.F32("LITE.exposureEV", c.exposureEV);
  d.F32("LITE.bloomIntensity", c.bloomIntensity);
  d.F32("LITE.bloomThreshold", c.bloomThreshold);
  d.Str("LITE.lut", c.lut);
}

// ================================================================================================= LLGT

bool DecodeLlgt(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, LlgtChunk& out, std::string& err)
{
  BEGIN("LLGT")
  out = LlgtChunk();
  out.light.resize(r.count(64, 8192));
  for (auto& l : out.light) {
    l.type = r.u8();
    l.pos = RVec<3>(r);
    l.dir = RVec<3>(r);
    l.color = RVec<3>(r);
    l.intensity = r.f32();
    l.range = r.f32();
    l.innerDeg = r.f32();
    l.outerDeg = r.f32();
    l.flags = r.u8();
    l.flickerAmp = r.f32();
    l.flickerHz = r.f32();
    l.layer = r.u16();
    if (!r.ok()) break;
    REQ(l.type <= 1, "unknown light type");
    REQ((l.flags & ~0xFU) == 0, "light flags use undefined bits");
  }
  DONE();
}

void DumpLlgt(TextDump& d, const LlgtChunk& c)
{
  d.Count("LLGT.lights", c.light.size());
  for (std::size_t i = 0; i < c.light.size(); ++i) {
    const std::string p = TextDump::Idx("LLGT.lights", i);
    const LlgtLight& l = c.light[i];
    d.U(p + ".type", l.type);
    DV(d, p + ".pos", l.pos);
    DV(d, p + ".dir", l.dir);
    DV(d, p + ".color", l.color);
    d.F32(p + ".intensity", l.intensity);
    d.F32(p + ".range", l.range);
    d.F32(p + ".innerDeg", l.innerDeg);
    d.F32(p + ".outerDeg", l.outerDeg);
    d.U(p + ".flags", l.flags);
    d.F32(p + ".flickerAmp", l.flickerAmp);
    d.F32(p + ".flickerHz", l.flickerHz);
    d.U(p + ".layer", l.layer);
  }
}

// ================================================================================================= PROB

bool DecodeProb(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, ProbChunk& out, std::string& err)
{
  BEGIN("PROB")
  out = ProbChunk();
  out.reflProbe.resize(r.count(32, 1024));
  PathReader P(r);
  for (auto& p : out.reflProbe) {
    p.pos = RVec<3>(r);
    p.halfExtents = RVec<3>(r);
    p.blend = r.f32();
    p.priority = r.i16();
    p.cubemap = P();
  }
  REQ(P.ok, kPathMsg);
  out.gridOrigin = RVec<3>(r);
  out.gridSpacing = RVec<3>(r);
  out.nx = r.u32();
  out.ny = r.u32();
  out.nz = r.u32();
  REQ(out.nx <= kMaxProbeGrid && out.ny <= kMaxProbeGrid && out.nz <= kMaxProbeGrid, "probe grid too large");
  const std::uint64_t xy = static_cast<std::uint64_t>(out.nx) * out.ny; // each factor <= 2^22: no overflow
  REQ(xy <= kMaxProbeGrid, "probe grid above 2^22 probes");
  const std::uint64_t total = xy * out.nz;
  REQ(total <= kMaxProbeGrid, "probe grid above 2^22 probes");
  REQ(r.remaining() == total * 27 * 2, "probe data size does not match nx*ny*nz*27 binary16 values");
  out.shData = ReadBlob(r, total * 27 * 2);
  DONE();
}

void DumpProb(TextDump& d, const ProbChunk& c)
{
  d.Count("PROB.reflProbes", c.reflProbe.size());
  for (std::size_t i = 0; i < c.reflProbe.size(); ++i) {
    const std::string p = TextDump::Idx("PROB.reflProbes", i);
    DV(d, p + ".pos", c.reflProbe[i].pos);
    DV(d, p + ".halfExtents", c.reflProbe[i].halfExtents);
    d.F32(p + ".blend", c.reflProbe[i].blend);
    d.I(p + ".priority", c.reflProbe[i].priority);
    d.Str(p + ".cubemap", c.reflProbe[i].cubemap);
  }
  DV(d, "PROB.gridOrigin", c.gridOrigin);
  DV(d, "PROB.gridSpacing", c.gridSpacing);
  d.U("PROB.nx", c.nx);
  d.U("PROB.ny", c.ny);
  d.U("PROB.nz", c.nz);
  d.Bytes("PROB.shData", c.shData.data, static_cast<std::size_t>(c.shData.size));
}

// ================================================================================================= TODK

bool DecodeTodk(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, TodkChunk& out, std::string& err)
{
  BEGIN("TODK")
  out = TodkChunk();
  out.cycleSeconds = r.f32();
  out.startPhase = r.f32();
  REQ(out.cycleSeconds >= 0.0f, "cycleSeconds is negative or NaN");
  REQ(out.startPhase >= 0.0f && out.startPhase <= 1.0f, "startPhase outside 0..1");
  const std::uint32_t c = r.count(96, 256);
  REQ(c >= 1, "no keys");
  out.key.resize(c);
  float prev = -1.0f;
  for (auto& k : out.key) {
    k.t = r.f32();
    k.sunDir = RVec<3>(r);
    k.sunColor = RVec<3>(r);
    k.sunIntensity = r.f32();
    k.ambient = RVec<3>(r);
    k.ground = RVec<3>(r);
    k.ambientIntensity = r.f32();
    k.fogColor = RVec<3>(r);
    k.fogDensity = r.f32();
    k.skyTint = RVec<3>(r);
    k.exposureEV = r.f32();
    k.starIntensity = r.f32();
    if (!r.ok()) break;
    REQ(k.t >= 0.0f && k.t < 1.0f, "key time outside [0,1)");
    REQ(k.t > prev, "key times are not strictly increasing");
    prev = k.t;
  }
  DONE();
}

void DumpTodk(TextDump& d, const TodkChunk& c)
{
  d.F32("TODK.cycleSeconds", c.cycleSeconds);
  d.F32("TODK.startPhase", c.startPhase);
  d.Count("TODK.keys", c.key.size());
  for (std::size_t i = 0; i < c.key.size(); ++i) {
    const std::string p = TextDump::Idx("TODK.keys", i);
    const TodkKey& k = c.key[i];
    d.F32(p + ".t", k.t);
    DV(d, p + ".sunDir", k.sunDir);
    DV(d, p + ".sunColor", k.sunColor);
    d.F32(p + ".sunIntensity", k.sunIntensity);
    DV(d, p + ".ambient", k.ambient);
    DV(d, p + ".ground", k.ground);
    d.F32(p + ".ambientIntensity", k.ambientIntensity);
    DV(d, p + ".fogColor", k.fogColor);
    d.F32(p + ".fogDensity", k.fogDensity);
    DV(d, p + ".skyTint", k.skyTint);
    d.F32(p + ".exposureEV", k.exposureEV);
    d.F32(p + ".starIntensity", k.starIntensity);
  }
}

// ================================================================================================= ATMO

bool DecodeAtmo(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, AtmoChunk& out, std::string& err)
{
  BEGIN("ATMO")
  out = AtmoChunk();
  out.skyModel = r.u8();
  REQ(out.skyModel <= 2, "unknown skyModel");
  PathReader P(r);
  out.cubemap = P();
  out.skyIntensity = r.f32();
  out.rotationDeg = r.f32();
  if (out.skyModel == 1) { // the "procedural:" block exists only for the procedural atmosphere
    out.planetRadiusKm = r.f32();
    out.atmosphereHeightKm = r.f32();
    out.rayleigh = RVec<3>(r);
    out.rayleighScaleHeightKm = r.f32();
    out.mie = r.f32();
    out.mieAnisotropy = r.f32();
    out.mieScaleHeightKm = r.f32();
    out.ozone = RVec<3>(r);
    out.groundAlbedo = r.f32();
  }
  out.cloudMode = r.u8();
  REQ(out.cloudMode <= 2, "unknown cloudMode");
  out.coverage = r.f32();
  out.density = r.f32();
  out.baseAltitude = r.f32();
  out.thickness = r.f32();
  out.wind = RVec<2>(r);
  out.noiseShape = P();
  out.noiseDetail = P();
  out.cloudShadowStrength = r.f32();
  out.volumetricFog = r.u8();
  REQ(out.volumetricFog <= 1, "volumetricFog must be 0 or 1");
  out.scattering = r.f32();
  out.anisotropy = r.f32();
  out.extinction = r.f32();
  out.maxDistance = r.f32();
  out.celestial.resize(r.count(34, 16));
  for (auto& c : out.celestial) {
    c.texture = P();
    c.dir = RVec<3>(r);
    c.sizeDeg = r.f32();
    c.tint = RVec<3>(r);
    c.intensity = r.f32();
  }
  out.starIntensity = r.f32();
  REQ(P.ok, kPathMsg);
  DONE();
}

void DumpAtmo(TextDump& d, const AtmoChunk& c)
{
  d.U("ATMO.skyModel", c.skyModel);
  d.Str("ATMO.cubemap", c.cubemap);
  d.F32("ATMO.skyIntensity", c.skyIntensity);
  d.F32("ATMO.rotationDeg", c.rotationDeg);
  if (c.skyModel == 1) {
    d.F32("ATMO.planetRadiusKm", c.planetRadiusKm);
    d.F32("ATMO.atmosphereHeightKm", c.atmosphereHeightKm);
    DV(d, "ATMO.rayleigh", c.rayleigh);
    d.F32("ATMO.rayleighScaleHeightKm", c.rayleighScaleHeightKm);
    d.F32("ATMO.mie", c.mie);
    d.F32("ATMO.mieAnisotropy", c.mieAnisotropy);
    d.F32("ATMO.mieScaleHeightKm", c.mieScaleHeightKm);
    DV(d, "ATMO.ozone", c.ozone);
    d.F32("ATMO.groundAlbedo", c.groundAlbedo);
  }
  d.U("ATMO.cloudMode", c.cloudMode);
  d.F32("ATMO.coverage", c.coverage);
  d.F32("ATMO.density", c.density);
  d.F32("ATMO.baseAltitude", c.baseAltitude);
  d.F32("ATMO.thickness", c.thickness);
  DV(d, "ATMO.wind", c.wind);
  d.Str("ATMO.noiseShape", c.noiseShape);
  d.Str("ATMO.noiseDetail", c.noiseDetail);
  d.F32("ATMO.cloudShadowStrength", c.cloudShadowStrength);
  d.U("ATMO.volumetricFog", c.volumetricFog);
  d.F32("ATMO.scattering", c.scattering);
  d.F32("ATMO.anisotropy", c.anisotropy);
  d.F32("ATMO.extinction", c.extinction);
  d.F32("ATMO.maxDistance", c.maxDistance);
  d.Count("ATMO.celestials", c.celestial.size());
  for (std::size_t i = 0; i < c.celestial.size(); ++i) {
    const std::string p = TextDump::Idx("ATMO.celestials", i);
    d.Str(p + ".texture", c.celestial[i].texture);
    DV(d, p + ".dir", c.celestial[i].dir);
    d.F32(p + ".sizeDeg", c.celestial[i].sizeDeg);
    DV(d, p + ".tint", c.celestial[i].tint);
    d.F32(p + ".intensity", c.celestial[i].intensity);
  }
  d.F32("ATMO.starIntensity", c.starIntensity);
}

// ================================================================================================= WVIS

bool DecodeWvis(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WvisChunk& out, std::string& err)
{
  BEGIN("WVIS")
  out = WvisChunk();
  out.bodyVis.resize(r.count(90, 256));
  PathReader P(r);
  for (auto& b : out.bodyVis) {
    b.bodyId = r.u16();
    b.shallow = RVec<3>(r);
    b.deep = RVec<3>(r);
    b.absorption = RVec<3>(r);
    b.clarityMeters = r.f32();
    b.reflection = r.f32();
    b.refraction = r.f32();
    b.waveModel = r.u8();
    REQ(b.waveModel <= 2, "unknown waveModel");
    if (b.waveModel == 0) {
      b.normalMaps.resize(r.count(18, 4));
      for (auto& m : b.normalMaps) {
        m.normalMap = P();
        m.tiling = r.f32();
        m.speed = r.f32();
        m.dir = RVec<2>(r);
      }
    } else if (b.waveModel == 1) {
      b.waves.resize(r.count(20, 16));
      for (auto& w : b.waves) {
        w.amplitude = r.f32();
        w.wavelength = r.f32();
        w.steepness = r.f32();
        w.dirDeg = r.f32();
        w.speed = r.f32();
      }
    } else {
      b.windSpeed = r.f32();
      b.windDirDeg = r.f32();
      b.fetchKm = r.f32();
      b.choppiness = r.f32();
      b.patchSize = r.f32();
    }
    b.foamAmount = r.f32();
    b.foamTexture = P();
    b.shoreFoamWidth = r.f32();
    b.causticStrength = r.f32();
    b.causticTexture = P();
    b.flowScale = r.f32();
    b.flowMap = r.u32();
    b.underwaterFog = RVec<3>(r);
    b.underwaterDensity = r.f32();
    if (!r.ok()) break;
  }
  REQ(P.ok, kPathMsg);
  for (std::size_t i = 0; i < out.bodyVis.size(); ++i)
    for (std::size_t j = 0; j < i; ++j) REQ(out.bodyVis[i].bodyId != out.bodyVis[j].bodyId, "duplicate bodyId");
  DONE();
}

void DumpWvis(TextDump& d, const WvisChunk& c)
{
  d.Count("WVIS.bodies", c.bodyVis.size());
  for (std::size_t i = 0; i < c.bodyVis.size(); ++i) {
    const std::string p = TextDump::Idx("WVIS.bodies", i);
    const WvisBodyVis& b = c.bodyVis[i];
    d.U(p + ".bodyId", b.bodyId);
    DV(d, p + ".shallow", b.shallow);
    DV(d, p + ".deep", b.deep);
    DV(d, p + ".absorption", b.absorption);
    d.F32(p + ".clarityMeters", b.clarityMeters);
    d.F32(p + ".reflection", b.reflection);
    d.F32(p + ".refraction", b.refraction);
    d.U(p + ".waveModel", b.waveModel);
    if (b.waveModel == 0) {
      d.Count(p + ".normalMaps", b.normalMaps.size());
      for (std::size_t j = 0; j < b.normalMaps.size(); ++j) {
        const std::string q = TextDump::Idx(p + ".normalMaps", j);
        d.Str(q + ".normalMap", b.normalMaps[j].normalMap);
        d.F32(q + ".tiling", b.normalMaps[j].tiling);
        d.F32(q + ".speed", b.normalMaps[j].speed);
        DV(d, q + ".dir", b.normalMaps[j].dir);
      }
    } else if (b.waveModel == 1) {
      d.Count(p + ".waves", b.waves.size());
      for (std::size_t j = 0; j < b.waves.size(); ++j) {
        const std::string q = TextDump::Idx(p + ".waves", j);
        d.F32(q + ".amplitude", b.waves[j].amplitude);
        d.F32(q + ".wavelength", b.waves[j].wavelength);
        d.F32(q + ".steepness", b.waves[j].steepness);
        d.F32(q + ".dirDeg", b.waves[j].dirDeg);
        d.F32(q + ".speed", b.waves[j].speed);
      }
    } else {
      d.F32(p + ".windSpeed", b.windSpeed);
      d.F32(p + ".windDirDeg", b.windDirDeg);
      d.F32(p + ".fetchKm", b.fetchKm);
      d.F32(p + ".choppiness", b.choppiness);
      d.F32(p + ".patchSize", b.patchSize);
    }
    d.F32(p + ".foamAmount", b.foamAmount);
    d.Str(p + ".foamTexture", b.foamTexture);
    d.F32(p + ".shoreFoamWidth", b.shoreFoamWidth);
    d.F32(p + ".causticStrength", b.causticStrength);
    d.Str(p + ".causticTexture", b.causticTexture);
    d.F32(p + ".flowScale", b.flowScale);
    d.U(p + ".flowMap", b.flowMap);
    DV(d, p + ".underwaterFog", b.underwaterFog);
    d.F32(p + ".underwaterDensity", b.underwaterDensity);
  }
}

// ================================================================================================= WFLW / SCDM

bool DecodeWflw(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WflwChunk& out, std::string& err)
{
  BEGIN("WFLW")
  out = WflwChunk();
  const bool dimsOk = ImageDims(r, out.width, out.height);
  out.maxSpeed = r.f32();
  REQ(dimsOk, "width/height outside 1..16384");
  ReadPlane(r, out.height, out.width, 2, 1, out.plane);
  DONE();
}

void DumpWflw(TextDump& d, const WflwChunk& c)
{
  d.U("WFLW.width", c.width);
  d.U("WFLW.height", c.height);
  d.F32("WFLW.maxSpeed", c.maxSpeed);
  d.Plane("WFLW.flow", c.width, c.height, c.plane.data(), c.plane.size());
}

bool DecodeScdm(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, ScdmChunk& out, std::string& err)
{
  BEGIN("SCDM")
  out = ScdmChunk();
  const bool dimsOk = ImageDims(r, out.width, out.height);
  REQ(dimsOk, "width/height outside 1..16384");
  ReadPlane(r, out.height, out.width, 1, 1, out.plane);
  DONE();
}

void DumpScdm(TextDump& d, const ScdmChunk& c)
{
  d.U("SCDM.width", c.width);
  d.U("SCDM.height", c.height);
  d.Plane("SCDM.density", c.width, c.height, c.plane.data(), c.plane.size());
}

// ================================================================================================= SCAT

bool DecodeScat(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, ScatChunk& out, std::string& err)
{
  BEGIN("SCAT")
  out = ScatChunk();
  out.layer.resize(r.count(80, 256));
  PathReader P(r);
  for (auto& l : out.layer) {
    l.name = r.str();
    l.seed = r.u64();
    const std::uint32_t vc = r.count(15, 64);
    REQ(vc >= 1, "layer without variants");
    l.variant.resize(vc);
    for (auto& v : l.variant) {
      v.kind = r.u8();
      v.ref = P();
      v.weight = r.f32();
      v.scaleMin = r.f32();
      v.scaleMax = r.f32();
      if (!r.ok()) break;
      REQ(v.kind <= 2, "unknown variant kind");
    }
    l.density = r.f32();
    l.minSlopeDeg = r.f32();
    l.maxSlopeDeg = r.f32();
    l.minAltitude = r.f32();
    l.maxAltitude = r.f32();
    l.allowedMaterials = ReadU16Array(r, 64);
    l.forbiddenSurfaces = ReadU16Array(r, 64);
    l.densityMap = r.i32();
    l.jitter = r.f32();
    l.flags = r.u16();
    l.cullDistance = r.f32();
    l.windBend = r.f32();
    l.windHz = r.f32();
    l.tintVariation = r.f32();
    l.layer = r.u16();
    if (!r.ok()) break;
    REQ(l.densityMap >= -1, "densityMap below -1");
    REQ((l.flags & ~0x1FU) == 0, "scatter flags use undefined bits");
    REQ(!(l.density < 0.0f), "negative density");
    double weightSum = 0.0;
    bool negativeWeight = false;
    for (const auto& v : l.variant) {
      weightSum += static_cast<double>(v.weight);
      negativeWeight = negativeWeight || v.weight < 0.0f;
      REQ(!(v.scaleMax < v.scaleMin), "scaleMax below scaleMin");
    }
    REQ(!(weightSum <= 0.0) && !negativeWeight, "variant weights must be >= 0 with a positive sum");
  }
  REQ(P.ok, kPathMsg);
  DONE();
}

void DumpScat(TextDump& d, const ScatChunk& c)
{
  d.Count("SCAT.layers", c.layer.size());
  for (std::size_t i = 0; i < c.layer.size(); ++i) {
    const std::string p = TextDump::Idx("SCAT.layers", i);
    const ScatterLayer& l = c.layer[i];
    d.Str(p + ".name", l.name);
    d.U(p + ".seed", l.seed);
    d.Count(p + ".variants", l.variant.size());
    for (std::size_t j = 0; j < l.variant.size(); ++j) {
      const std::string q = TextDump::Idx(p + ".variants", j);
      d.U(q + ".kind", l.variant[j].kind);
      d.Str(q + ".ref", l.variant[j].ref);
      d.F32(q + ".weight", l.variant[j].weight);
      d.F32(q + ".scaleMin", l.variant[j].scaleMin);
      d.F32(q + ".scaleMax", l.variant[j].scaleMax);
    }
    d.F32(p + ".density", l.density);
    d.F32(p + ".minSlopeDeg", l.minSlopeDeg);
    d.F32(p + ".maxSlopeDeg", l.maxSlopeDeg);
    d.F32(p + ".minAltitude", l.minAltitude);
    d.F32(p + ".maxAltitude", l.maxAltitude);
    DumpU16Array(d, p + ".allowedMaterials", l.allowedMaterials);
    DumpU16Array(d, p + ".forbiddenSurfaces", l.forbiddenSurfaces);
    d.I(p + ".densityMap", l.densityMap);
    d.F32(p + ".jitter", l.jitter);
    d.U(p + ".flags", l.flags);
    d.F32(p + ".cullDistance", l.cullDistance);
    d.F32(p + ".windBend", l.windBend);
    d.F32(p + ".windHz", l.windHz);
    d.F32(p + ".tintVariation", l.tintVariation);
    d.U(p + ".layer", l.layer);
  }
}

// ================================================================================================= SPLN

bool DecodeSpln(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, SplnChunk& out, std::string& err)
{
  BEGIN("SPLN")
  out = SplnChunk();
  out.spline.resize(r.count(100, 4096));
  PathReader P(r);
  for (auto& s : out.spline) {
    s.kind = r.u8();
    REQ(s.kind <= 6, "unknown spline kind");
    s.name = r.str();
    s.flags = r.u16();
    REQ((s.flags & ~0x1FU) == 0, "spline flags use undefined bits");
    const std::uint32_t pc = r.count(44, 65536);
    REQ(pc >= 2, "spline with fewer than 2 points");
    s.point.resize(pc);
    for (auto& p : s.point) {
      p.pos = RVec<3>(r);
      p.tangentIn = RVec<3>(r);
      p.tangentOut = RVec<3>(r);
      p.width = r.f32();
      p.rollDeg = r.f32();
    }
    s.decalTexture = P();
    s.mesh = P();
    s.uvTile = r.f32();
    s.paintWidth = r.f32();
    s.paintMaterial = r.u16();
    s.writeSurface = r.u16();
    s.blendDistance = r.f32();
    s.layer = r.u16();
    if (!r.ok()) break;
  }
  REQ(P.ok, kPathMsg);
  DONE();
}

void DumpSpln(TextDump& d, const SplnChunk& c)
{
  d.Count("SPLN.splines", c.spline.size());
  for (std::size_t i = 0; i < c.spline.size(); ++i) {
    const std::string p = TextDump::Idx("SPLN.splines", i);
    const SplnSpline& s = c.spline[i];
    d.U(p + ".kind", s.kind);
    d.Str(p + ".name", s.name);
    d.U(p + ".flags", s.flags);
    d.Count(p + ".points", s.point.size());
    for (std::size_t j = 0; j < s.point.size(); ++j) {
      const std::string q = TextDump::Idx(p + ".points", j);
      DV(d, q + ".pos", s.point[j].pos);
      DV(d, q + ".tangentIn", s.point[j].tangentIn);
      DV(d, q + ".tangentOut", s.point[j].tangentOut);
      d.F32(q + ".width", s.point[j].width);
      d.F32(q + ".rollDeg", s.point[j].rollDeg);
    }
    d.Str(p + ".decalTexture", s.decalTexture);
    d.Str(p + ".mesh", s.mesh);
    d.F32(p + ".uvTile", s.uvTile);
    d.F32(p + ".paintWidth", s.paintWidth);
    d.U(p + ".paintMaterial", s.paintMaterial);
    d.U(p + ".writeSurface", s.writeSurface);
    d.F32(p + ".blendDistance", s.blendDistance);
    d.U(p + ".layer", s.layer);
  }
}

// ================================================================================================= DECL

bool DecodeDecl(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, DeclChunk& out, std::string& err)
{
  BEGIN("DECL")
  out = DeclChunk();
  out.textures.resize(r.count(2, 65535));
  PathReader P(r);
  for (auto& t : out.textures) t = P();
  REQ(P.ok, kPathMsg);
  out.decal.resize(r.count(82, 1000000));
  for (auto& e : out.decal) {
    e.type = r.u8();
    e.tex0 = r.u32();
    e.tex1 = r.u32();
    e.pos = RVec<3>(r);
    e.rot = RVec<4>(r);
    e.size = RVec<3>(r);
    e.lodMin = r.f32();
    e.lodMax = r.f32();
    e.tint = RVec<4>(r);
    e.fadeDistance = r.f32();
    e.order = r.i16();
    e.layer = r.u16();
    e.blend = r.u8();
    if (!r.ok()) break;
    REQ(e.type <= 4, "unknown decal type");
    REQ(e.tex0 < out.textures.size(), "tex0 outside the texture table");
    REQ(e.tex1 == 0xFFFFFFFFu || e.tex1 < out.textures.size(), "tex1 outside the texture table");
    REQ(e.blend <= 2, "unknown blend mode");
  }
  DONE();
}

void DumpDecl(TextDump& d, const DeclChunk& c)
{
  d.Count("DECL.textures", c.textures.size());
  for (std::size_t i = 0; i < c.textures.size(); ++i) d.Str(TextDump::Idx("DECL.textures", i), c.textures[i]);
  d.Count("DECL.decals", c.decal.size());
  for (std::size_t i = 0; i < c.decal.size(); ++i) {
    const std::string p = TextDump::Idx("DECL.decals", i);
    const DeclDecal& e = c.decal[i];
    d.U(p + ".type", e.type);
    d.U(p + ".tex0", e.tex0);
    d.U(p + ".tex1", e.tex1);
    DV(d, p + ".pos", e.pos);
    DV(d, p + ".rot", e.rot);
    DV(d, p + ".size", e.size);
    d.F32(p + ".lodMin", e.lodMin);
    d.F32(p + ".lodMax", e.lodMax);
    DV(d, p + ".tint", e.tint);
    d.F32(p + ".fadeDistance", e.fadeDistance);
    d.I(p + ".order", e.order);
    d.U(p + ".layer", e.layer);
    d.U(p + ".blend", e.blend);
  }
}

// ================================================================================================= WTHR

bool DecodeWthr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WthrChunk& out, std::string& err)
{
  BEGIN("WTHR")
  out = WthrChunk();
  out.defaultState = r.u16();
  const std::uint32_t sc = r.count(34, 64);
  REQ(sc >= 1, "no weather states");
  out.state.resize(sc);
  for (auto& s : out.state) {
    s.name = r.str();
    s.rain = r.f32();
    s.snow = r.f32();
    s.fogDensityMul = r.f32();
    s.cloudCoverageAdd = r.f32();
    s.windSpeed = r.f32();
    s.windDirDeg = r.f32();
    s.lightMul = r.f32();
    s.wetness = r.f32();
  }
  REQ(out.defaultState < out.state.size(), "defaultState outside the state table");
  out.zone.resize(r.count(21, 1024));
  PathReader P(r);
  for (auto& z : out.zone) {
    z.name = r.str();
    const char* shapeErr = ReadShape(r, z.shape);
    z.state = r.u16();
    z.yMin = r.f32();
    z.yMax = r.f32();
    z.effect = P();
    z.sound = P();
    z.layer = r.u16();
    if (!r.ok()) break;
    REQ(shapeErr == nullptr, shapeErr);
    REQ(z.state < out.state.size(), "zone state outside the state table");
  }
  REQ(P.ok, kPathMsg);
  DONE();
}

void DumpWthr(TextDump& d, const WthrChunk& c)
{
  d.U("WTHR.defaultState", c.defaultState);
  d.Count("WTHR.states", c.state.size());
  for (std::size_t i = 0; i < c.state.size(); ++i) {
    const std::string p = TextDump::Idx("WTHR.states", i);
    const WthrState& s = c.state[i];
    d.Str(p + ".name", s.name);
    d.F32(p + ".rain", s.rain);
    d.F32(p + ".snow", s.snow);
    d.F32(p + ".fogDensityMul", s.fogDensityMul);
    d.F32(p + ".cloudCoverageAdd", s.cloudCoverageAdd);
    d.F32(p + ".windSpeed", s.windSpeed);
    d.F32(p + ".windDirDeg", s.windDirDeg);
    d.F32(p + ".lightMul", s.lightMul);
    d.F32(p + ".wetness", s.wetness);
  }
  d.Count("WTHR.zones", c.zone.size());
  for (std::size_t i = 0; i < c.zone.size(); ++i) {
    const std::string p = TextDump::Idx("WTHR.zones", i);
    const WthrZone& z = c.zone[i];
    d.Str(p + ".name", z.name);
    DumpShape(d, p + ".shape", z.shape);
    d.U(p + ".state", z.state);
    d.F32(p + ".yMin", z.yMin);
    d.F32(p + ".yMax", z.yMax);
    d.Str(p + ".effect", z.effect);
    d.Str(p + ".sound", z.sound);
    d.U(p + ".layer", z.layer);
  }
}

// ================================================================================================= AUDI

bool DecodeAudi(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, AudiChunk& out, std::string& err)
{
  BEGIN("AUDI")
  out = AudiChunk();
  out.ambientBed = r.str();
  out.bedVolume = r.f32();
  out.zone.resize(r.count(17, 1024));
  for (auto& z : out.zone) {
    z.name = r.str();
    const char* shapeErr = ReadShape(r, z.shape);
    z.loop = r.str();
    z.volume = r.f32();
    z.fade = r.f32();
    z.priority = r.i16();
    z.reverbPreset = r.str();
    REQ(shapeErr == nullptr, shapeErr);
  }
  out.cue.resize(r.count(4, 64));
  for (auto& c : out.cue) {
    c.state = r.str();
    c.cue = r.str();
  }
  DONE();
}

void DumpAudi(TextDump& d, const AudiChunk& c)
{
  d.Str("AUDI.ambientBed", c.ambientBed);
  d.F32("AUDI.bedVolume", c.bedVolume);
  d.Count("AUDI.zones", c.zone.size());
  for (std::size_t i = 0; i < c.zone.size(); ++i) {
    const std::string p = TextDump::Idx("AUDI.zones", i);
    const AudiZone& z = c.zone[i];
    d.Str(p + ".name", z.name);
    DumpShape(d, p + ".shape", z.shape);
    d.Str(p + ".loop", z.loop);
    d.F32(p + ".volume", z.volume);
    d.F32(p + ".fade", z.fade);
    d.I(p + ".priority", z.priority);
    d.Str(p + ".reverbPreset", z.reverbPreset);
  }
  d.Count("AUDI.cues", c.cue.size());
  for (std::size_t i = 0; i < c.cue.size(); ++i) {
    const std::string p = TextDump::Idx("AUDI.cues", i);
    d.Str(p + ".state", c.cue[i].state);
    d.Str(p + ".cue", c.cue[i].cue);
  }
}

// ================================================================================================= CAMR

bool DecodeCamr(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, CamrChunk& out, std::string& err)
{
  BEGIN("CAMR")
  out = CamrChunk();
  out.defaultPose = ReadPose(r);
  out.minZoom = r.f32();
  out.maxZoom = r.f32();
  out.pitchMin = r.f32();
  out.pitchMax = r.f32();
  out.bounds = RVec<4>(r);
  out.bookmark.resize(r.count(30, 64));
  for (auto& b : out.bookmark) {
    b.name = r.str();
    b.pose = ReadPose(r);
  }
  out.path.resize(r.count(10, 256));
  for (auto& p : out.path) {
    p.name = r.str();
    p.duration = r.f32();
    const std::uint32_t kc = r.count(37, 4096);
    REQ(kc >= 2, "camera path with fewer than 2 keys");
    p.key.resize(kc);
    for (auto& k : p.key) {
      k.t = r.f32();
      k.pos = RVec<3>(r);
      k.rot = RVec<4>(r);
      k.fovDeg = r.f32();
      k.ease = r.u8();
      if (!r.ok()) break;
      REQ(k.ease <= 1, "unknown ease");
    }
    if (!r.ok()) break;
  }
  DONE();
}

void DumpCamr(TextDump& d, const CamrChunk& c)
{
  DumpPose(d, "CAMR.defaultPose", c.defaultPose);
  d.F32("CAMR.minZoom", c.minZoom);
  d.F32("CAMR.maxZoom", c.maxZoom);
  d.F32("CAMR.pitchMin", c.pitchMin);
  d.F32("CAMR.pitchMax", c.pitchMax);
  DV(d, "CAMR.bounds", c.bounds);
  d.Count("CAMR.bookmarks", c.bookmark.size());
  for (std::size_t i = 0; i < c.bookmark.size(); ++i) {
    const std::string p = TextDump::Idx("CAMR.bookmarks", i);
    d.Str(p + ".name", c.bookmark[i].name);
    DumpPose(d, p + ".pose", c.bookmark[i].pose);
  }
  d.Count("CAMR.paths", c.path.size());
  for (std::size_t i = 0; i < c.path.size(); ++i) {
    const std::string p = TextDump::Idx("CAMR.paths", i);
    d.Str(p + ".name", c.path[i].name);
    d.F32(p + ".duration", c.path[i].duration);
    d.Count(p + ".keys", c.path[i].key.size());
    for (std::size_t j = 0; j < c.path[i].key.size(); ++j) {
      const std::string q = TextDump::Idx(p + ".keys", j);
      const CamrKey& k = c.path[i].key[j];
      d.F32(q + ".t", k.t);
      DV(d, q + ".pos", k.pos);
      DV(d, q + ".rot", k.rot);
      d.F32(q + ".fovDeg", k.fovDeg);
      d.U(q + ".ease", k.ease);
    }
  }
}

// ================================================================================================= MINI

bool DecodeMini(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, MiniChunk& out, std::string& err)
{
  BEGIN("MINI")
  out = MiniChunk();
  out.kind = r.u8();
  REQ(out.kind <= 2, "unknown kind");
  if (out.kind == 1) {
    out.imgFmt = r.u8();
    out.imgWidth = r.u32();
    out.imgHeight = r.u32();
    out.imgByteCount = r.u32();
    REQ(out.imgFmt <= 1, "unknown image format");
    out.imgData = ReadBlob(r, out.imgByteCount);
  }
  out.contourInterval = r.f32();
  out.ramp.resize(r.count(7, 64));
  for (auto& e : out.ramp) {
    e.height = r.f32();
    for (auto& ch : e.color) ch = r.u8();
  }
  for (auto& ch : out.borderColor) ch = r.u8();
  out.strategicStyle = r.str();
  DONE();
}

void DumpMini(TextDump& d, const MiniChunk& c)
{
  d.U("MINI.kind", c.kind);
  if (c.kind == 1) {
    d.U("MINI.image.fmt", c.imgFmt);
    d.U("MINI.image.w", c.imgWidth);
    d.U("MINI.image.h", c.imgHeight);
    d.U("MINI.image.byteCount", c.imgByteCount);
    d.Bytes("MINI.image.data", c.imgData.data, static_cast<std::size_t>(c.imgData.size));
  }
  d.F32("MINI.contourInterval", c.contourInterval);
  d.Count("MINI.ramp", c.ramp.size());
  for (std::size_t i = 0; i < c.ramp.size(); ++i) {
    const std::string p = TextDump::Idx("MINI.ramp", i);
    d.F32(p + ".height", c.ramp[i].height);
    d.Raw(p + ".color", Rgb(c.ramp[i].color));
  }
  d.Raw("MINI.borderColor", Rgb(c.borderColor));
  d.Str("MINI.strategicStyle", c.strategicStyle);
}

// ================================================================================================= POST

bool DecodePost(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, PostChunk& out, std::string& err)
{
  BEGIN("POST")
  out = PostChunk();
  out.flags = r.u32();
  out.bloom = r.f32();
  out.vignette = r.f32();
  out.chromaticAberration = r.f32();
  out.filmGrain = r.f32();
  out.ssaoHint = r.f32();
  out.ssrHint = r.f32();
  out.dofFocus = r.f32();
  out.dofAperture = r.f32();
  REQ((out.flags & ~1U) == 0, "post flags use undefined bits");
  DONE();
}

void DumpPost(TextDump& d, const PostChunk& c)
{
  d.U("POST.flags", c.flags);
  d.F32("POST.bloom", c.bloom);
  d.F32("POST.vignette", c.vignette);
  d.F32("POST.chromaticAberration", c.chromaticAberration);
  d.F32("POST.filmGrain", c.filmGrain);
  d.F32("POST.ssaoHint", c.ssaoHint);
  d.F32("POST.ssrHint", c.ssrHint);
  d.F32("POST.dofFocus", c.dofFocus);
  d.F32("POST.dofAperture", c.dofAperture);
}

// ================================================================================================= DRVD

bool DecodeDrvd(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, DrvdChunk& out, std::string& err)
{
  BEGIN("DRVD")
  out = DrvdChunk();
  out.kind = r.str();
  const std::uint8_t* h = r.bytes(32);
  if (h) std::memcpy(out.inputHash.data(), h, 32);
  out.byteCount = r.u32();
  REQ(true, "");
  out.data = ReadBlob(r, out.byteCount);
  DONE();
}

void DumpDrvd(TextDump& d, const DrvdChunk& c)
{
  d.Str("DRVD.kind", c.kind);
  d.Bytes("DRVD.inputHash", c.inputHash.data(), c.inputHash.size());
  d.U("DRVD.byteCount", c.byteCount);
  d.Bytes("DRVD.data", c.data.data, static_cast<std::size_t>(c.data.size));
}

// ================================================================================================= family entry

namespace {
const char* const kIds[] = {"META", "PREV", "GENR", "SIGN", "ASST", "LAYR", "MATL", "SPLT", "NRML", "AOMP",
                            "HDET", "HOLE", "MACR", "LITE", "LLGT", "PROB", "TODK", "ATMO", "WVIS", "WFLW",
                            "SCAT", "SCDM", "SPLN", "DECL", "WTHR", "AUDI", "CAMR", "MINI", "POST", "DRVD"};
}

bool IsRenderChunkId(const std::string& id)
{
  for (const char* k : kIds)
    if (id == k) return true;
  return false;
}

DecodeStatus DumpChunkRender(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size,
                             ChunkCtx& ctx, TextDump& dump, std::string& err)
{
  if (!IsRenderChunkId(id)) return DecodeStatus::NotMine;
  if (version != 1) {
    err = id + ": unsupported chunk version " + std::to_string(version);
    return DecodeStatus::Error;
  }
  // The dump is appended only after a successful decode, so an error never leaves half a chunk behind.
#define MF_CASE(ID, Name)                                                                                         \
  if (id == ID) {                                                                                                 \
    Name##Chunk c;                                                                                                \
    if (!Decode##Name(data, size, ctx, c, err)) return DecodeStatus::Error;                                       \
    Dump##Name(dump, c);                                                                                          \
    return DecodeStatus::Ok;                                                                                      \
  }
  MF_CASE("META", Meta) MF_CASE("PREV", Prev) MF_CASE("GENR", Genr) MF_CASE("SIGN", Sign) MF_CASE("ASST", Asst)
  MF_CASE("LAYR", Layr) MF_CASE("MATL", Matl) MF_CASE("SPLT", Splt) MF_CASE("NRML", Nrml) MF_CASE("AOMP", Aomp)
  MF_CASE("HDET", Hdet) MF_CASE("HOLE", Hole) MF_CASE("MACR", Macr) MF_CASE("LITE", Lite) MF_CASE("LLGT", Llgt)
  MF_CASE("PROB", Prob) MF_CASE("TODK", Todk) MF_CASE("ATMO", Atmo) MF_CASE("WVIS", Wvis) MF_CASE("WFLW", Wflw)
  MF_CASE("SCAT", Scat) MF_CASE("SCDM", Scdm) MF_CASE("SPLN", Spln) MF_CASE("DECL", Decl) MF_CASE("WTHR", Wthr)
  MF_CASE("AUDI", Audi) MF_CASE("CAMR", Camr) MF_CASE("MINI", Mini) MF_CASE("POST", Post) MF_CASE("DRVD", Drvd)
#undef MF_CASE
  err = id + ": internal dispatch error";
  return DecodeStatus::Error;
}

} // namespace moho::mapformat
