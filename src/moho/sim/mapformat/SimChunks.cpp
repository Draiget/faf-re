// Decoders, dumpers and cross-chunk validation of the sim chunks (see SimChunks.h). Standard library only.
//
// Style of the decoders: every read goes through `Rd`, a ByteReader wrapper that remembers the first reason a read
// went wrong. After a failure all reads return zero, so a decoder can run to the end of its field list and report once
// through Finish(); loops are still guarded by ok() so a hostile count never makes us spin, and every count is checked
// against the remaining bytes (count * minimum element size) before anything is allocated from it.
#include "moho/sim/mapformat/SimChunks.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace moho::mapformat {

namespace {

constexpr std::uint64_t kMaxSamples = 1ULL << 30; // CONTAINER.md section 6: total sample count
constexpr std::uint32_t kMaxAxisCells = 65536;
constexpr std::uint32_t kNoLimit = 0xFFFFFFFFu;

class Rd
{
public:
  Rd(const std::uint8_t* d, std::size_t n) : r(d, n) {}

  ByteReader r;
  std::string why; // first reason, empty = plain truncation

  bool ok() const { return r.ok(); }
  void bad(const std::string& msg)
  {
    if (r.ok()) why = msg;
    r.fail();
  }

  std::uint8_t u8() { return r.u8(); }
  std::uint16_t u16() { return r.u16(); }
  std::uint32_t u32() { return r.u32(); }
  std::int8_t i8() { return r.i8(); }
  std::int16_t i16() { return r.i16(); }
  std::int32_t i32() { return r.i32(); }
  double f64()
  {
    const double v = r.f64();
    if (r.ok() && !std::isfinite(v)) bad("non-finite f64");
    return v;
  }
  /// f32 that must be finite: NaN / infinity in sim data would make results differ between builds.
  float f()
  {
    const float v = r.f32();
    if (r.ok() && !std::isfinite(v)) bad("non-finite f32");
    return v;
  }
  std::string str()
  {
    std::string s = r.str();
    if (!r.ok() && why.empty()) why = "bad string length";
    return s;
  }
  std::uint32_t count(std::size_t minElem, std::uint32_t maxCount, const char* what)
  {
    const std::uint32_t c = r.u32();
    if (!r.ok()) return 0;
    if (c > maxCount) {
      bad(std::string(what) + ": count above limit");
      return 0;
    }
    if (minElem > 0 && static_cast<std::uint64_t>(c) * minElem > r.remaining()) {
      bad(std::string(what) + ": count does not fit in the payload");
      return 0;
    }
    return c;
  }
  /// True when `n` elements of `elemBytes` bytes are still available (64-bit math).
  bool fits(std::uint64_t n, std::uint64_t elemBytes) const
  {
    return n <= r.remaining() && n * elemBytes <= r.remaining();
  }
};

bool Fail(std::string& err, const char* chunk, const std::string& msg)
{
  err = std::string(chunk) + ": " + msg;
  return false;
}

/// Exact-consumption check and error text for the whole decode.
bool Finish(Rd& rd, const char* chunk, std::string& err)
{
  if (rd.ok() && !rd.r.atEnd()) rd.bad("trailing bytes after the payload");
  if (!rd.ok()) return Fail(err, chunk, rd.why.empty() ? std::string("truncated or malformed payload") : rd.why);
  return true;
}

// ---- planes ---------------------------------------------------------------------------------------------------------

/// Reads `cols * rows` elements of `elemBytes` bytes (the predictor byte has been consumed by the caller) and reverses
/// the predictor. Dimensions are limited to the grid limits and checked against the remaining bytes before allocating.
bool ReadPlane(Rd& rd, std::uint64_t cols, std::uint64_t rows, std::uint32_t elemBytes, std::uint8_t predictor,
               std::vector<std::uint8_t>& raw)
{
  if (!rd.ok()) return false;
  if (predictor > 3) {
    rd.bad("unknown predictor");
    return false;
  }
  if (cols == 0 || rows == 0 || cols > kMaxAxisCells + 1ULL || rows > kMaxAxisCells + 1ULL ||
      cols * rows > kMaxSamples) {
    rd.bad("plane dimensions out of range");
    return false;
  }
  const std::uint64_t bytes = cols * rows * elemBytes;
  if (bytes > rd.r.remaining()) {
    rd.bad("plane larger than the remaining payload");
    return false;
  }
  const std::uint8_t* p = rd.r.bytes(bytes);
  if (!p) return false;
  raw.assign(p, p + static_cast<std::size_t>(bytes));
  UnpredictPlane(raw.data(), static_cast<std::uint32_t>(rows), static_cast<std::uint32_t>(cols), 1, elemBytes,
                 predictor);
  return true;
}

std::vector<std::uint16_t> Widen16(const std::vector<std::uint8_t>& raw)
{
  std::vector<std::uint16_t> v(raw.size() / 2);
  for (std::size_t i = 0; i < v.size(); ++i)
    v[i] = static_cast<std::uint16_t>(raw[2 * i] | (raw[2 * i + 1] << 8));
  return v;
}

std::vector<std::uint8_t> Narrow16(const std::vector<std::uint16_t>& v)
{
  std::vector<std::uint8_t> raw(v.size() * 2);
  for (std::size_t i = 0; i < v.size(); ++i) {
    raw[2 * i] = static_cast<std::uint8_t>(v[i] & 0xFF);
    raw[2 * i + 1] = static_cast<std::uint8_t>(v[i] >> 8);
  }
  return raw;
}

const std::uint8_t* DataOf(const std::vector<std::uint8_t>& v) { return v.empty() ? nullptr : v.data(); }

// ---- small shared readers -------------------------------------------------------------------------------------------

FxVec2 ReadFx2(Rd& rd)
{
  FxVec2 v;
  v.x = rd.i32();
  v.z = rd.i32();
  return v;
}

Fx10Vec3 ReadFx3(Rd& rd)
{
  Fx10Vec3 v;
  v.x = rd.i32();
  v.y = rd.i32();
  v.z = rd.i32();
  return v;
}

bool IsLowerVfsPath(const std::string& s) { return !s.empty() && IsValidVfsPath(s); }

void ReadShape2D(Rd& rd, Shape2D& s, const char* what)
{
  s = Shape2D();
  s.kind = rd.u8();
  switch (s.kind) {
  case 0:
    s.x0 = rd.f();
    s.z0 = rd.f();
    s.x1 = rd.f();
    s.z1 = rd.f();
    if (rd.ok() && (s.x0 > s.x1 || s.z0 > s.z1)) rd.bad(std::string(what) + ": rect with x0 > x1 or z0 > z1");
    break;
  case 1: {
    const std::uint32_t c = rd.count(8, 1024, what);
    if (rd.ok() && c < 3) rd.bad(std::string(what) + ": polygon needs 3..1024 points");
    for (std::uint32_t i = 0; i < c && rd.ok(); ++i) {
      std::array<float, 2> p;
      p[0] = rd.f();
      p[1] = rd.f();
      s.polygon.push_back(p);
    }
    break;
  }
  case 2:
    s.cx = rd.f();
    s.cz = rd.f();
    s.r = rd.f();
    if (rd.ok() && s.r < 0.0f) rd.bad(std::string(what) + ": negative circle radius");
    break;
  default:
    rd.bad(std::string(what) + ": unknown shape kind");
  }
}

void ReadShape3D(Rd& rd, Shape3D& s, const char* what)
{
  s = Shape3D();
  s.kind = rd.u8();
  switch (s.kind) {
  case 0:
    s.center = ReadFx3(rd);
    s.halfExtents = ReadFx3(rd);
    for (int i = 0; i < 4; ++i) s.rot[i] = rd.i16();
    if (rd.ok() && (s.halfExtents.x < 0 || s.halfExtents.y < 0 || s.halfExtents.z < 0))
      rd.bad(std::string(what) + ": negative box half extent");
    break;
  case 1:
    s.center = ReadFx3(rd);
    s.radius = rd.i32();
    if (rd.ok() && s.radius < 0) rd.bad(std::string(what) + ": negative radius");
    break;
  case 2: {
    const std::uint32_t c = rd.count(12, 256, what);
    if (rd.ok() && c < 4) rd.bad(std::string(what) + ": convex hull needs 4..256 points");
    for (std::uint32_t i = 0; i < c && rd.ok(); ++i) s.points.push_back(ReadFx3(rd));
    break;
  }
  case 3: {
    const std::uint32_t c = rd.count(8, 1024, what);
    if (rd.ok() && c < 3) rd.bad(std::string(what) + ": polygon needs 3..1024 points");
    for (std::uint32_t i = 0; i < c && rd.ok(); ++i) s.polygon.push_back(ReadFx2(rd));
    s.yMin = rd.i32();
    s.yMax = rd.i32();
    if (rd.ok() && s.yMin > s.yMax) rd.bad(std::string(what) + ": yMin above yMax");
    break;
  }
  case 4:
    s.a = ReadFx3(rd);
    s.b = ReadFx3(rd);
    s.radius = rd.i32();
    if (rd.ok() && s.radius < 0) rd.bad(std::string(what) + ": negative radius");
    break;
  default:
    rd.bad(std::string(what) + ": unknown shape3d kind");
  }
}

// Checks shared by decoder and validator, so hand-built data is held to the same rules.

bool PlayPolygonInsideRect(const PlayChunk& p)
{
  for (const FxVec2& v : p.polygon) {
    if (v.x < static_cast<std::int64_t>(p.x0) * 256 || v.x > static_cast<std::int64_t>(p.x1) * 256) return false;
    if (v.z < static_cast<std::int64_t>(p.z0) * 256 || v.z > static_cast<std::int64_t>(p.z1) * 256) return false;
  }
  return true;
}

/// Index of every id of a 16-bit id table (unique ids required by the caller).
std::vector<std::uint8_t> IdTable(const std::vector<GplySurface>& s)
{
  std::vector<std::uint8_t> t(65536, 0);
  for (const GplySurface& e : s) t[e.id] = 1;
  return t;
}

// ---- dump helpers -----------------------------------------------------------------------------------------------------

void DumpFx2(TextDump& d, const std::string& path, const FxVec2& v)
{
  d.Raw(path, "[" + std::to_string(v.x) + ", " + std::to_string(v.z) + "]");
}

void DumpFx3(TextDump& d, const std::string& path, const Fx10Vec3& v)
{
  d.Raw(path, "[" + std::to_string(v.x) + ", " + std::to_string(v.y) + ", " + std::to_string(v.z) + "]");
}

template <typename T>
void DumpScalarArray(TextDump& d, const std::string& path, const std::vector<T>& v)
{
  d.Count(path, v.size());
  for (std::size_t i = 0; i < v.size(); ++i) d.U(TextDump::Idx(path, i), v[i]);
}

void DumpFx3Array(TextDump& d, const std::string& path, const std::vector<Fx10Vec3>& v)
{
  d.Count(path, v.size());
  for (std::size_t i = 0; i < v.size(); ++i) DumpFx3(d, TextDump::Idx(path, i), v[i]);
}

void DumpShape2D(TextDump& d, const std::string& p, const Shape2D& s)
{
  d.U(p + ".kind", s.kind);
  switch (s.kind) {
  case 0:
    d.F32(p + ".x0", s.x0);
    d.F32(p + ".z0", s.z0);
    d.F32(p + ".x1", s.x1);
    d.F32(p + ".z1", s.z1);
    break;
  case 1:
    d.Count(p + ".points", s.polygon.size());
    for (std::size_t i = 0; i < s.polygon.size(); ++i) d.Vec(TextDump::Idx(p + ".points", i), s.polygon[i].data(), 2);
    break;
  default:
    d.F32(p + ".cx", s.cx);
    d.F32(p + ".cz", s.cz);
    d.F32(p + ".r", s.r);
  }
}

void DumpShape3D(TextDump& d, const std::string& p, const Shape3D& s)
{
  d.U(p + ".kind", s.kind);
  switch (s.kind) {
  case 0:
    DumpFx3(d, p + ".center", s.center);
    DumpFx3(d, p + ".halfExtents", s.halfExtents);
    d.Raw(p + ".rot", "[" + std::to_string(s.rot[0]) + ", " + std::to_string(s.rot[1]) + ", " +
                          std::to_string(s.rot[2]) + ", " + std::to_string(s.rot[3]) + "]");
    break;
  case 1:
    DumpFx3(d, p + ".center", s.center);
    d.I(p + ".radius", s.radius);
    break;
  case 2:
    d.Count(p + ".vertices", s.points.size());
    for (std::size_t i = 0; i < s.points.size(); ++i) DumpFx3(d, TextDump::Idx(p + ".vertices", i), s.points[i]);
    break;
  case 3:
    d.Count(p + ".polygon", s.polygon.size());
    for (std::size_t i = 0; i < s.polygon.size(); ++i) DumpFx2(d, TextDump::Idx(p + ".polygon", i), s.polygon[i]);
    d.I(p + ".yMin", s.yMin);
    d.I(p + ".yMax", s.yMax);
    break;
  default:
    DumpFx3(d, p + ".a", s.a);
    DumpFx3(d, p + ".b", s.b);
    d.I(p + ".radius", s.radius);
  }
}

} // namespace

// =====================================================================================================================
// GRID
// =====================================================================================================================

bool DecodeGrid(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, GridChunk& out, std::string& err)
{
  Rd rd(d, n);
  GridChunk c;
  c.cellsX = rd.u32();
  c.cellsZ = rd.u32();
  c.cellSize = rd.f();
  c.originX = rd.f();
  c.originZ = rd.f();
  c.minElevation = rd.f();
  c.maxElevation = rd.f();
  c.reserved = rd.u8();
  if (rd.ok()) {
    if (c.cellsX < 1 || c.cellsX > kMaxAxisCells || c.cellsZ < 1 || c.cellsZ > kMaxAxisCells)
      rd.bad("cells per axis must be 1..65536");
    else if ((static_cast<std::uint64_t>(c.cellsX) + 1) * (static_cast<std::uint64_t>(c.cellsZ) + 1) > kMaxSamples)
      rd.bad("sample count above 2^30");
    else if (c.cellSize != 1.0f)
      rd.bad("cellSize must be 1.0 in revision 1");
    else if (c.originX != 0.0f || c.originZ != 0.0f)
      rd.bad("origin must be 0 in revision 1");
    else if (c.minElevation > c.maxElevation)
      rd.bad("minElevation above maxElevation");
    else if (c.reserved != 0)
      rd.bad("reserved byte must be 0");
  }
  if (!Finish(rd, "GRID", err)) return false;
  out = c;
  ctx.cellsX = c.cellsX;
  ctx.cellsZ = c.cellsZ;
  return true;
}

void DumpGrid(TextDump& d, const GridChunk& c)
{
  d.U("GRID.cellsX", c.cellsX);
  d.U("GRID.cellsZ", c.cellsZ);
  d.F32("GRID.cellSize", c.cellSize);
  d.F32("GRID.originX", c.originX);
  d.F32("GRID.originZ", c.originZ);
  d.F32("GRID.minElevation", c.minElevation);
  d.F32("GRID.maxElevation", c.maxElevation);
  d.U("GRID.reserved", c.reserved);
}

// =====================================================================================================================
// HGHT
// =====================================================================================================================

bool DecodeHght(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, HghtChunk& out, std::string& err)
{
  if (ctx.cellsX == 0 || ctx.cellsZ == 0) return Fail(err, "HGHT", "GRID must be decoded first");
  Rd rd(d, n);
  HghtChunk c;
  c.minHeight = rd.f();
  c.stepLog2 = rd.i8();
  c.predictor = rd.u8();
  c.tileSize = rd.u16();
  if (rd.ok()) {
    if (c.stepLog2 < -16 || c.stepLog2 > 0) rd.bad("stepLog2 must be -16..0");
    else if (c.predictor > 3) rd.bad("unknown predictor");
    else if (c.tileSize != 0) rd.bad("tileSize must be 0 in revision 1");
  }
  c.width = static_cast<std::uint32_t>(std::min<std::uint64_t>(ctx.cellsX + 1ULL, 0xFFFFFFFFULL));
  c.height = static_cast<std::uint32_t>(std::min<std::uint64_t>(ctx.cellsZ + 1ULL, 0xFFFFFFFFULL));
  std::vector<std::uint8_t> raw;
  ReadPlane(rd, c.width, c.height, 2, c.predictor, raw);
  if (!Finish(rd, "HGHT", err)) return false;
  c.samples = Widen16(raw);
  out = std::move(c);
  return true;
}

void DumpHght(TextDump& d, const HghtChunk& c)
{
  d.F32("HGHT.minHeight", c.minHeight);
  d.I("HGHT.stepLog2", c.stepLog2);
  d.U("HGHT.predictor", c.predictor);
  d.U("HGHT.tileSize", c.tileSize);
  const std::vector<std::uint8_t> raw = Narrow16(c.samples);
  d.Plane("HGHT.samples", c.width, c.height, DataOf(raw), raw.size());
}

float DecodeHeight(const HghtChunk& c, std::uint16_t v)
{
  // Both steps are single binary32 operations (the scale by a power of two is exact), so every build agrees.
  const float scaled = std::ldexp(static_cast<float>(v), static_cast<int>(c.stepLog2));
  return scaled + c.minHeight;
}

// =====================================================================================================================
// PLAY
// =====================================================================================================================

bool DecodePlay(const std::uint8_t* d, std::size_t n, ChunkCtx&, PlayChunk& out, std::string& err)
{
  Rd rd(d, n);
  PlayChunk c;
  c.x0 = rd.i32();
  c.z0 = rd.i32();
  c.x1 = rd.i32();
  c.z1 = rd.i32();
  c.borderMode = rd.u8();
  const std::uint32_t pc = rd.count(8, 1024, "polygon");
  if (rd.ok() && (c.x1 <= c.x0 || c.z1 <= c.z0)) rd.bad("rectangle needs x1 > x0 and z1 > z0");
  if (rd.ok() && c.borderMode > 2) rd.bad("unknown borderMode");
  if (rd.ok() && (pc == 1 || pc == 2)) rd.bad("polygon needs 0 or 3..1024 points");
  for (std::uint32_t i = 0; i < pc && rd.ok(); ++i) c.polygon.push_back(ReadFx2(rd));
  if (!Finish(rd, "PLAY", err)) return false;
  if (!PlayPolygonInsideRect(c)) return Fail(err, "PLAY", "polygon leaves the rectangle");
  out = std::move(c);
  return true;
}

void DumpPlay(TextDump& d, const PlayChunk& c)
{
  d.I("PLAY.x0", c.x0);
  d.I("PLAY.z0", c.z0);
  d.I("PLAY.x1", c.x1);
  d.I("PLAY.z1", c.z1);
  d.U("PLAY.borderMode", c.borderMode);
  d.Count("PLAY.polygon", c.polygon.size());
  for (std::size_t i = 0; i < c.polygon.size(); ++i) DumpFx2(d, TextDump::Idx("PLAY.polygon", i), c.polygon[i]);
}

// =====================================================================================================================
// GPLY
// =====================================================================================================================

bool DecodeGply(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, GplyChunk& out, std::string& err)
{
  if (ctx.cellsX == 0 || ctx.cellsZ == 0) return Fail(err, "GPLY", "GRID must be decoded first");
  Rd rd(d, n);
  GplyChunk c;
  c.width = ctx.cellsX;
  c.height = ctx.cellsZ;
  c.legacyTerrainIds = rd.u8();
  if (rd.ok() && c.legacyTerrainIds > 1) rd.bad("legacyTerrainIds must be 0 or 1");
  const std::uint32_t ns = rd.count(12, 1024, "surfaces");
  std::vector<std::uint8_t> seen(65536, 0);
  for (std::uint32_t i = 0; i < ns && rd.ok(); ++i) {
    GplySurface s;
    s.id = rd.u16();
    s.name = rd.str();
    s.flags = rd.u32();
    s.speedMul = rd.u16();
    s.effectsKey = rd.str();
    if (rd.ok() && (s.flags & ~0xFU)) rd.bad("surface flags use undefined bits");
    if (rd.ok() && seen[s.id]) rd.bad("duplicate surface id");
    seen[s.id] = 1;
    c.surfaces.push_back(std::move(s));
  }
  c.idWidth = rd.u8();
  if (rd.ok() && c.idWidth != 1 && c.idWidth != 2) rd.bad("idWidth must be 1 or 2");
  c.idsPredictor = rd.u8();
  std::vector<std::uint8_t> raw;
  if (rd.ok()) ReadPlane(rd, c.width, c.height, c.idWidth, c.idsPredictor, raw);
  if (rd.ok()) {
    c.ids.resize(static_cast<std::size_t>(c.width) * c.height);
    if (c.idWidth == 1) {
      for (std::size_t i = 0; i < c.ids.size(); ++i) c.ids[i] = raw[i];
    } else {
      c.ids = Widen16(raw);
    }
    raw.clear();
    raw.shrink_to_fit();
    for (std::uint16_t id : c.ids) {
      if (!seen[id]) {
        rd.bad("surface id in the plane is not in the table");
        break;
      }
    }
  }
  const std::uint32_t nm = rd.count(3, 64, "masks");
  for (std::uint32_t i = 0; i < nm && rd.ok(); ++i) {
    GplyMask m;
    m.name = rd.str();
    m.kind = rd.u8();
    if (rd.ok() && m.name.empty()) rd.bad("mask with an empty name");
    for (const GplyMask& o : c.masks)
      if (rd.ok() && o.name == m.name) rd.bad("duplicate mask name");
    if (rd.ok()) {
      if (m.kind == 1) {
        const std::uint64_t bytes = BitmaskBytes(c.width, c.height);
        if (bytes > rd.r.remaining()) {
          rd.bad("bitmask larger than the remaining payload");
        } else {
          const std::uint8_t* p = rd.r.bytes(bytes);
          if (p) m.data.assign(p, p + static_cast<std::size_t>(bytes));
        }
      } else if (m.kind == 8) {
        m.predictor = rd.u8();
        if (rd.ok()) ReadPlane(rd, c.width, c.height, 1, m.predictor, m.data);
      } else {
        rd.bad("unknown mask kind");
      }
    }
    c.masks.push_back(std::move(m));
  }
  if (!Finish(rd, "GPLY", err)) return false;
  out = std::move(c);
  return true;
}

void DumpGply(TextDump& d, const GplyChunk& c)
{
  d.U("GPLY.legacyTerrainIds", c.legacyTerrainIds);
  d.Count("GPLY.surfaces", c.surfaces.size());
  for (std::size_t i = 0; i < c.surfaces.size(); ++i) {
    const std::string p = TextDump::Idx("GPLY.surfaces", i);
    d.U(p + ".id", c.surfaces[i].id);
    d.Str(p + ".name", c.surfaces[i].name);
    d.U(p + ".flags", c.surfaces[i].flags);
    d.U(p + ".speedMul", c.surfaces[i].speedMul);
    d.Str(p + ".effectsKey", c.surfaces[i].effectsKey);
  }
  d.U("GPLY.idWidth", c.idWidth);
  std::vector<std::uint8_t> raw;
  if (c.idWidth == 1) {
    raw.resize(c.ids.size());
    for (std::size_t i = 0; i < c.ids.size(); ++i) raw[i] = static_cast<std::uint8_t>(c.ids[i]);
  } else {
    raw = Narrow16(c.ids);
  }
  d.Plane("GPLY.ids", c.width, c.height, DataOf(raw), raw.size());
  d.Count("GPLY.masks", c.masks.size());
  for (std::size_t i = 0; i < c.masks.size(); ++i) {
    const std::string p = TextDump::Idx("GPLY.masks", i);
    d.Str(p + ".name", c.masks[i].name);
    d.U(p + ".kind", c.masks[i].kind);
    if (c.masks[i].kind == 8) {
      d.Plane(p + ".data", c.width, c.height, DataOf(c.masks[i].data), c.masks[i].data.size());
    } else {
      d.Bytes(p + ".data", DataOf(c.masks[i].data), c.masks[i].data.size());
    }
  }
}

// =====================================================================================================================
// WBOD
// =====================================================================================================================

bool DecodeWbod(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WbodChunk& out, std::string& err)
{
  Rd rd(d, n);
  WbodChunk c;
  const std::uint32_t nb = rd.count(10, 256, "bodies");
  if (rd.ok() && nb == 0) rd.bad("empty body array is not allowed");
  std::vector<std::uint8_t> seen(65536, 0);
  for (std::uint32_t i = 0; i < nb && rd.ok(); ++i) {
    WbodBody b;
    b.id = rd.u16();
    b.name = rd.str();
    b.kind = rd.u8();
    b.level = rd.f();
    b.extentKind = rd.u8();
    if (rd.ok() && b.kind > 2) rd.bad("unknown body kind");
    if (rd.ok() && seen[b.id]) rd.bad("duplicate body id");
    seen[b.id] = 1;
    if (rd.ok()) {
      if (b.extentKind == 1) {
        if (ctx.cellsX == 0 || ctx.cellsZ == 0) {
          rd.bad("GRID must be decoded first for a mask extent");
        } else {
          const std::uint64_t bytes = BitmaskBytes(ctx.cellsX, ctx.cellsZ);
          if (bytes > rd.r.remaining()) {
            rd.bad("mask larger than the remaining payload");
          } else {
            const std::uint8_t* p = rd.r.bytes(bytes);
            if (p) b.mask.assign(p, p + static_cast<std::size_t>(bytes));
          }
        }
      } else if (b.extentKind == 2) {
        const std::uint32_t pc = rd.count(8, 4096, "polygon");
        if (rd.ok() && pc < 3) rd.bad("polygon needs 3..4096 points");
        for (std::uint32_t k = 0; k < pc && rd.ok(); ++k) b.polygon.push_back(ReadFx2(rd));
      } else if (b.extentKind != 0) {
        rd.bad("unknown extentKind");
      }
    }
    c.bodies.push_back(std::move(b));
  }
  if (!Finish(rd, "WBOD", err)) return false;
  out = std::move(c);
  return true;
}

void DumpWbod(TextDump& d, const WbodChunk& c)
{
  d.Count("WBOD.bodies", c.bodies.size());
  for (std::size_t i = 0; i < c.bodies.size(); ++i) {
    const WbodBody& b = c.bodies[i];
    const std::string p = TextDump::Idx("WBOD.bodies", i);
    d.U(p + ".id", b.id);
    d.Str(p + ".name", b.name);
    d.U(p + ".kind", b.kind);
    d.F32(p + ".level", b.level);
    d.U(p + ".extentKind", b.extentKind);
    if (b.extentKind == 1) {
      d.Bytes(p + ".mask", DataOf(b.mask), b.mask.size());
    } else if (b.extentKind == 2) {
      d.Count(p + ".polygon", b.polygon.size());
      for (std::size_t k = 0; k < b.polygon.size(); ++k) DumpFx2(d, TextDump::Idx(p + ".polygon", k), b.polygon[k]);
    }
  }
}

// =====================================================================================================================
// LEVL
// =====================================================================================================================

bool DecodeLevl(const std::uint8_t* d, std::size_t n, ChunkCtx&, LevlChunk& out, std::string& err)
{
  Rd rd(d, n);
  LevlChunk c;
  const std::uint32_t nd = rd.count(42, 1024, "decks");
  std::vector<std::uint8_t> seen(65536, 0);
  for (std::uint32_t i = 0; i < nd && rd.ok(); ++i) {
    LevlDeck k;
    k.id = rd.u16();
    k.name = rd.str();
    k.x0 = rd.i32();
    k.z0 = rd.i32();
    k.x1 = rd.i32();
    k.z1 = rd.i32();
    k.mode = rd.u8();
    k.h0 = rd.f();
    k.h1 = rd.f();
    k.axis = rd.u8();
    if (rd.ok()) {
      if (k.id == 0xFFFF) rd.bad("deck id 0xFFFF is reserved for the ground");
      else if (seen[k.id]) rd.bad("duplicate deck id");
      else if (k.x1 < k.x0 || k.z1 < k.z0) rd.bad("deck rectangle is empty");
      else if (k.mode > 2) rd.bad("unknown deck mode");
      else if (k.axis > 1) rd.bad("unknown axis");
      seen[k.id] = 1;
    }
    if (rd.ok() && k.mode == 2) {
      const std::uint64_t w = static_cast<std::uint64_t>(static_cast<std::int64_t>(k.x1) - k.x0 + 1);
      const std::uint64_t h = static_cast<std::uint64_t>(static_cast<std::int64_t>(k.z1) - k.z0 + 1);
      k.patchPredictor = rd.u8();
      std::vector<std::uint8_t> raw;
      if (ReadPlane(rd, w, h, 2, k.patchPredictor, raw)) k.patch = Widen16(raw);
    }
    k.clearanceBelow = rd.f();
    k.flags = rd.u32();
    if (rd.ok() && k.clearanceBelow < 0.0f) rd.bad("negative clearanceBelow");
    if (rd.ok() && (k.flags & ~0xFU)) rd.bad("deck flags use undefined bits");
    const std::uint32_t np = rd.count(18, 64, "portals");
    for (std::uint32_t q = 0; q < np && rd.ok(); ++q) {
      LevlPortal p;
      p.a = ReadFx2(rd);
      p.b = ReadFx2(rd);
      p.targetDeck = rd.u16();
      k.portals.push_back(p);
    }
    c.decks.push_back(std::move(k));
  }
  if (!Finish(rd, "LEVL", err)) return false;
  // A portal leads to the ground (0xFFFF) or to a deck of this chunk.
  for (const LevlDeck& k : c.decks)
    for (const LevlPortal& p : k.portals)
      if (p.targetDeck != 0xFFFF && !seen[p.targetDeck]) return Fail(err, "LEVL", "portal targets an unknown deck");
  out = std::move(c);
  return true;
}

void DumpLevl(TextDump& d, const LevlChunk& c)
{
  d.Count("LEVL.decks", c.decks.size());
  for (std::size_t i = 0; i < c.decks.size(); ++i) {
    const LevlDeck& k = c.decks[i];
    const std::string p = TextDump::Idx("LEVL.decks", i);
    d.U(p + ".id", k.id);
    d.Str(p + ".name", k.name);
    d.I(p + ".x0", k.x0);
    d.I(p + ".z0", k.z0);
    d.I(p + ".x1", k.x1);
    d.I(p + ".z1", k.z1);
    d.U(p + ".mode", k.mode);
    d.F32(p + ".h0", k.h0);
    d.F32(p + ".h1", k.h1);
    d.U(p + ".axis", k.axis);
    if (k.mode == 2) {
      const std::vector<std::uint8_t> raw = Narrow16(k.patch);
      d.Plane(p + ".patch", static_cast<std::uint64_t>(static_cast<std::int64_t>(k.x1) - k.x0 + 1),
              static_cast<std::uint64_t>(static_cast<std::int64_t>(k.z1) - k.z0 + 1), DataOf(raw), raw.size());
    }
    d.F32(p + ".clearanceBelow", k.clearanceBelow);
    d.U(p + ".flags", k.flags);
    d.Count(p + ".portals", k.portals.size());
    for (std::size_t q = 0; q < k.portals.size(); ++q) {
      const std::string pp = TextDump::Idx(p + ".portals", q);
      DumpFx2(d, pp + ".a", k.portals[q].a);
      DumpFx2(d, pp + ".b", k.portals[q].b);
      d.U(pp + ".targetDeck", k.portals[q].targetDeck);
    }
  }
}

// =====================================================================================================================
// MRKR
// =====================================================================================================================

bool DecodeMrkr(const std::uint8_t* d, std::size_t n, ChunkCtx&, MrkrChunk& out, std::string& err)
{
  Rd rd(d, n);
  MrkrChunk c;
  const std::uint32_t nm = rd.count(33, 65536, "markers");
  c.markers.reserve(std::min<std::uint32_t>(nm, 4096));
  for (std::uint32_t i = 0; i < nm && rd.ok(); ++i) {
    Marker m;
    m.type = rd.u8();
    m.name = rd.str();
    m.pos[0] = rd.f();
    m.pos[1] = rd.f();
    m.pos[2] = rd.f();
    m.yawDeg = rd.f();
    m.army = rd.i16();
    m.flags = rd.u32();
    if (rd.ok() && m.type > 17) rd.bad("unknown marker type");
    if (rd.ok() && m.army < -1) rd.bad("army below -1");
    if (rd.ok() && m.flags != 0) rd.bad("marker flags must be 0");
    const std::uint32_t np = rd.count(4, 32, "props");
    for (std::uint32_t q = 0; q < np && rd.ok(); ++q) {
      MarkerProp p;
      p.key = rd.str();
      p.vtype = rd.u8();
      switch (p.vtype) {
      case 0: p.strValue = rd.str(); break;
      case 1: p.intValue = rd.i32(); break;
      case 2: p.floatValue = rd.f(); break;
      case 3: {
        const std::uint8_t b = rd.u8();
        if (rd.ok() && b > 1) rd.bad("bool property must be 0 or 1");
        p.intValue = b;
        break;
      }
      default: rd.bad("unknown property value type");
      }
      m.props.push_back(std::move(p));
    }
    const std::uint32_t nl = rd.count(4, 64, "links");
    for (std::uint32_t q = 0; q < nl && rd.ok(); ++q) m.links.push_back(rd.u32());
    c.markers.push_back(std::move(m));
  }
  if (!Finish(rd, "MRKR", err)) return false;
  for (const Marker& m : c.markers)
    for (std::uint32_t l : m.links)
      if (l >= c.markers.size()) return Fail(err, "MRKR", "link index out of range");
  out = std::move(c);
  return true;
}

void DumpMrkr(TextDump& d, const MrkrChunk& c)
{
  d.Count("MRKR.markers", c.markers.size());
  for (std::size_t i = 0; i < c.markers.size(); ++i) {
    const Marker& m = c.markers[i];
    const std::string p = TextDump::Idx("MRKR.markers", i);
    d.U(p + ".type", m.type);
    d.Str(p + ".name", m.name);
    d.Vec(p + ".pos", m.pos, 3);
    d.F32(p + ".yawDeg", m.yawDeg);
    d.I(p + ".army", m.army);
    d.U(p + ".flags", m.flags);
    d.Count(p + ".props", m.props.size());
    for (std::size_t q = 0; q < m.props.size(); ++q) {
      const MarkerProp& pr = m.props[q];
      const std::string pp = TextDump::Idx(p + ".props", q);
      d.Str(pp + ".key", pr.key);
      d.U(pp + ".vtype", pr.vtype);
      switch (pr.vtype) {
      case 0: d.Str(pp + ".value", pr.strValue); break;
      case 2: d.F32(pp + ".value", pr.floatValue); break;
      default: d.I(pp + ".value", pr.intValue);
      }
    }
    d.Count(p + ".links", m.links.size());
    for (std::size_t q = 0; q < m.links.size(); ++q) d.U(TextDump::Idx(p + ".links", q), m.links[q]);
  }
}

// =====================================================================================================================
// AREA
// =====================================================================================================================

bool DecodeArea(const std::uint8_t* d, std::size_t n, ChunkCtx&, AreaChunk& out, std::string& err)
{
  Rd rd(d, n);
  AreaChunk c;
  const std::uint32_t na = rd.count(20, 4096, "areas");
  for (std::uint32_t i = 0; i < na && rd.ok(); ++i) {
    Area a;
    a.name = rd.str();
    ReadShape2D(rd, a.shape, "area shape");
    a.flags = rd.u8();
    if (rd.ok() && (a.flags & ~1U)) rd.bad("area flags use undefined bits");
    if (rd.ok() && (a.flags & 1U)) {
      a.yMin = rd.f();
      a.yMax = rd.f();
      if (rd.ok() && a.yMin > a.yMax) rd.bad("yMin above yMax");
    }
    const std::uint32_t nt = rd.count(2, 16, "tags");
    for (std::uint32_t q = 0; q < nt && rd.ok(); ++q) a.tags.push_back(rd.str());
    c.areas.push_back(std::move(a));
  }
  if (!Finish(rd, "AREA", err)) return false;
  out = std::move(c);
  return true;
}

void DumpArea(TextDump& d, const AreaChunk& c)
{
  d.Count("AREA.areas", c.areas.size());
  for (std::size_t i = 0; i < c.areas.size(); ++i) {
    const Area& a = c.areas[i];
    const std::string p = TextDump::Idx("AREA.areas", i);
    d.Str(p + ".name", a.name);
    DumpShape2D(d, p + ".shape", a.shape);
    d.U(p + ".flags", a.flags);
    if (a.flags & 1U) {
      d.F32(p + ".yMin", a.yMin);
      d.F32(p + ".yMax", a.yMax);
    }
    d.Count(p + ".tags", a.tags.size());
    for (std::size_t q = 0; q < a.tags.size(); ++q) d.Str(TextDump::Idx(p + ".tags", q), a.tags[q]);
  }
}

// =====================================================================================================================
// PROP
// =====================================================================================================================

bool DecodeProp(const std::uint8_t* d, std::size_t n, ChunkCtx&, PropChunk& out, std::string& err)
{
  Rd rd(d, n);
  PropChunk c;
  const std::uint32_t nb = rd.count(2, 65535, "blueprints");
  for (std::uint32_t i = 0; i < nb && rd.ok(); ++i) {
    std::string s = rd.str();
    if (rd.ok() && !IsLowerVfsPath(s)) rd.bad("blueprint must be a lower case VFS path starting with /");
    c.blueprints.push_back(std::move(s));
  }
  const std::uint32_t np = rd.count(48, 1000000, "props");
  c.props.reserve(std::min<std::uint32_t>(np, 65536));
  for (std::uint32_t i = 0; i < np && rd.ok(); ++i) {
    PropItem p;
    p.blueprintIndex = rd.u32();
    for (float& v : p.pos) v = rd.f();
    for (float& v : p.rot) v = rd.f();
    for (float& v : p.scale) v = rd.f();
    p.flags = rd.u32();
    if (rd.ok() && p.blueprintIndex >= c.blueprints.size()) rd.bad("blueprint index out of range");
    if (rd.ok() && p.flags != 0) rd.bad("prop flags must be 0");
    c.props.push_back(p);
  }
  if (!Finish(rd, "PROP", err)) return false;
  out = std::move(c);
  return true;
}

void DumpProp(TextDump& d, const PropChunk& c)
{
  d.Count("PROP.blueprints", c.blueprints.size());
  for (std::size_t i = 0; i < c.blueprints.size(); ++i) d.Str(TextDump::Idx("PROP.blueprints", i), c.blueprints[i]);
  d.Count("PROP.props", c.props.size());
  for (std::size_t i = 0; i < c.props.size(); ++i) {
    const PropItem& q = c.props[i];
    const std::string p = TextDump::Idx("PROP.props", i);
    d.U(p + ".blueprintIndex", q.blueprintIndex);
    d.Vec(p + ".pos", q.pos, 3);
    d.Vec(p + ".rot", q.rot, 4);
    d.Vec(p + ".scale", q.scale, 3);
    d.U(p + ".flags", q.flags);
  }
}

// =====================================================================================================================
// HINT
// =====================================================================================================================

bool DecodeHint(const std::uint8_t* d, std::size_t n, ChunkCtx&, HintChunk& out, std::string& err)
{
  Rd rd(d, n);
  HintChunk c;
  const std::uint32_t nr = rd.count(23, 4096, "regions");
  for (std::uint32_t i = 0; i < nr && rd.ok(); ++i) {
    HintRegion r;
    r.id = rd.u32();
    r.name = rd.str();
    r.kind = rd.u8();
    r.area = rd.f();
    r.centroid[0] = rd.f();
    r.centroid[1] = rd.f();
    if (rd.ok() && r.kind > 5) rd.bad("unknown region kind");
    const std::uint32_t nn = rd.count(4, 64, "neighbors");
    for (std::uint32_t q = 0; q < nn && rd.ok(); ++q) r.neighbors.push_back(rd.u32());
    c.regions.push_back(std::move(r));
  }
  const std::uint32_t nc = rd.count(21, 4096, "chokes");
  for (std::uint32_t i = 0; i < nc && rd.ok(); ++i) {
    HintChoke k;
    k.pos[0] = rd.f();
    k.pos[1] = rd.f();
    k.width = rd.f();
    k.regionA = rd.u32();
    k.regionB = rd.u32();
    k.layerMask = rd.u8();
    if (rd.ok() && (k.layerMask & ~0xFU)) rd.bad("layerMask uses undefined bits");
    c.chokes.push_back(k);
  }
  const std::uint32_t nk = rd.count(17, 4096, "candidates");
  for (std::uint32_t i = 0; i < nk && rd.ok(); ++i) {
    HintCandidate k;
    k.pos[0] = rd.f();
    k.pos[1] = rd.f();
    k.layer = rd.u8();
    k.score = rd.f();
    const std::uint32_t nm = rd.count(4, 32, "markerIds");
    for (std::uint32_t q = 0; q < nm && rd.ok(); ++q) k.markerIds.push_back(rd.u32());
    c.candidates.push_back(std::move(k));
  }
  if (!Finish(rd, "HINT", err)) return false;
  std::vector<std::uint32_t> ids;
  for (const HintRegion& r : c.regions) ids.push_back(r.id);
  std::sort(ids.begin(), ids.end());
  if (std::adjacent_find(ids.begin(), ids.end()) != ids.end()) return Fail(err, "HINT", "duplicate region id");
  const auto known = [&ids](std::uint32_t id) { return std::binary_search(ids.begin(), ids.end(), id); };
  for (const HintRegion& r : c.regions)
    for (std::uint32_t nb : r.neighbors)
      if (!known(nb)) return Fail(err, "HINT", "neighbor references an unknown region");
  for (const HintChoke& k : c.chokes)
    if (!known(k.regionA) || !known(k.regionB)) return Fail(err, "HINT", "choke references an unknown region");
  out = std::move(c);
  return true;
}

void DumpHint(TextDump& d, const HintChunk& c)
{
  d.Count("HINT.regions", c.regions.size());
  for (std::size_t i = 0; i < c.regions.size(); ++i) {
    const HintRegion& r = c.regions[i];
    const std::string p = TextDump::Idx("HINT.regions", i);
    d.U(p + ".id", r.id);
    d.Str(p + ".name", r.name);
    d.U(p + ".kind", r.kind);
    d.F32(p + ".area", r.area);
    d.Vec(p + ".centroid", r.centroid, 2);
    d.Count(p + ".neighbors", r.neighbors.size());
    for (std::size_t q = 0; q < r.neighbors.size(); ++q) d.U(TextDump::Idx(p + ".neighbors", q), r.neighbors[q]);
  }
  d.Count("HINT.chokes", c.chokes.size());
  for (std::size_t i = 0; i < c.chokes.size(); ++i) {
    const HintChoke& k = c.chokes[i];
    const std::string p = TextDump::Idx("HINT.chokes", i);
    d.Vec(p + ".pos", k.pos, 2);
    d.F32(p + ".width", k.width);
    d.U(p + ".regionA", k.regionA);
    d.U(p + ".regionB", k.regionB);
    d.U(p + ".layerMask", k.layerMask);
  }
  d.Count("HINT.candidates", c.candidates.size());
  for (std::size_t i = 0; i < c.candidates.size(); ++i) {
    const HintCandidate& k = c.candidates[i];
    const std::string p = TextDump::Idx("HINT.candidates", i);
    d.Vec(p + ".pos", k.pos, 2);
    d.U(p + ".layer", k.layer);
    d.F32(p + ".score", k.score);
    d.Count(p + ".markerIds", k.markerIds.size());
    for (std::size_t q = 0; q < k.markerIds.size(); ++q) d.U(TextDump::Idx(p + ".markerIds", q), k.markerIds[q]);
  }
}

// =====================================================================================================================
// WRLD
// =====================================================================================================================

bool DecodeWrld(const std::uint8_t* d, std::size_t n, ChunkCtx& ctx, WrldChunk& out, std::string& err)
{
  Rd rd(d, n);
  WrldChunk c;
  c.originX = rd.f64();
  c.originY = rd.f64();
  c.originZ = rd.f64();
  for (float& v : c.boundsMin) v = rd.f();
  for (float& v : c.boundsMax) v = rd.f();
  c.cellSize = rd.f();
  c.cellsX = rd.u32();
  c.cellsY = rd.u32();
  c.cellsZ = rd.u32();
  c.upAxis = rd.u8();
  c.unitsPerMeter = rd.f();
  c.flags = rd.u8();
  if (rd.ok()) {
    bool boundsOk = true;
    bool large = c.originX != 0.0 || c.originY != 0.0 || c.originZ != 0.0;
    for (int i = 0; i < 3; ++i) {
      if (c.boundsMin[i] > c.boundsMax[i]) boundsOk = false;
      if (std::fabs(c.boundsMin[i]) > 1048576.0f || std::fabs(c.boundsMax[i]) > 1048576.0f) large = true;
    }
    if (!boundsOk) rd.bad("boundsMin above boundsMax");
    else if (c.cellSize < 32.0f || c.cellSize > 4096.0f) rd.bad("cellSize must be 32..4096");
    else if (c.cellsX < 1 || c.cellsY < 1 || c.cellsZ < 1) rd.bad("cell counts must be at least 1");
    else if (static_cast<std::uint64_t>(c.cellsX) * c.cellsY * c.cellsZ > (1ULL << 22) ||
             c.cellsX > (1U << 22) || c.cellsY > (1U << 22) || c.cellsZ > (1U << 22))
      rd.bad("cell count above 2^22");
    else if (c.upAxis != 1) rd.bad("upAxis must be 1 (Y)");
    else if (c.unitsPerMeter <= 0.0f) rd.bad("unitsPerMeter must be positive");
    else if (c.flags & ~1U) rd.bad("WRLD flags use undefined bits");
    else if (large && !(c.flags & 1U)) rd.bad("LARGE_COORDS flag missing for a non-zero origin or bounds above 2^20");
  }
  if (!Finish(rd, "WRLD", err)) return false;
  ctx.worldCells = static_cast<std::uint64_t>(c.cellsX) * c.cellsY * c.cellsZ;
  out = c;
  return true;
}

void DumpWrld(TextDump& d, const WrldChunk& c)
{
  d.F64("WRLD.originX", c.originX);
  d.F64("WRLD.originY", c.originY);
  d.F64("WRLD.originZ", c.originZ);
  d.Vec("WRLD.boundsMin", c.boundsMin, 3);
  d.Vec("WRLD.boundsMax", c.boundsMax, 3);
  d.F32("WRLD.cellSize", c.cellSize);
  d.U("WRLD.cellsX", c.cellsX);
  d.U("WRLD.cellsY", c.cellsY);
  d.U("WRLD.cellsZ", c.cellsZ);
  d.U("WRLD.upAxis", c.upAxis);
  d.F32("WRLD.unitsPerMeter", c.unitsPerMeter);
  d.U("WRLD.flags", c.flags);
}

// =====================================================================================================================
// SLYR
// =====================================================================================================================

bool DecodeSlyr(const std::uint8_t* d, std::size_t n, ChunkCtx&, SlyrChunk& out, std::string& err)
{
  Rd rd(d, n);
  SlyrChunk c;
  const std::uint32_t nl = rd.count(3, 64, "layers");
  for (std::uint32_t i = 0; i < nl && rd.ok(); ++i) {
    SlyrLayer l;
    l.name = rd.str();
    l.defaultOn = rd.u8();
    if (rd.ok() && l.name.empty()) rd.bad("layer with an empty name");
    if (rd.ok() && l.defaultOn > 1) rd.bad("defaultOn must be 0 or 1");
    for (const SlyrLayer& o : c.layers)
      if (rd.ok() && o.name == l.name) rd.bad("duplicate layer name");
    c.layers.push_back(std::move(l));
  }
  if (!Finish(rd, "SLYR", err)) return false;
  out = std::move(c);
  return true;
}

void DumpSlyr(TextDump& d, const SlyrChunk& c)
{
  d.Count("SLYR.layers", c.layers.size());
  for (std::size_t i = 0; i < c.layers.size(); ++i) {
    const std::string p = TextDump::Idx("SLYR.layers", i);
    d.Str(p + ".name", c.layers[i].name);
    d.U(p + ".defaultOn", c.layers[i].defaultOn);
  }
}

// =====================================================================================================================
// COLL
// =====================================================================================================================

namespace {
constexpr std::uint16_t kCollBlockBits = 0x7F; // GROUND PROJECTILES AIR NAVAL BUILD VISION BEAMS
}

bool DecodeColl(const std::uint8_t* d, std::size_t n, ChunkCtx&, CollChunk& out, std::string& err)
{
  Rd rd(d, n);
  CollChunk c;
  const std::uint32_t nt = rd.count(15, 4096, "tris");
  for (std::uint32_t i = 0; i < nt && rd.ok(); ++i) {
    CollTri t;
    // `u32 vertexCount, array fx10vec3 vertices`: the count is the one u32, the elements follow directly.
    const std::uint32_t nv = rd.count(12, kNoLimit, "vertices");
    t.vertices.reserve(std::min<std::uint32_t>(nv, 65536));
    for (std::uint32_t q = 0; q < nv && rd.ok(); ++q) t.vertices.push_back(ReadFx3(rd));
    const std::uint32_t ni = rd.count(4, kNoLimit, "indices");
    if (rd.ok() && ni % 3 != 0) rd.bad("indexCount is not a multiple of 3");
    t.indices.reserve(std::min<std::uint32_t>(ni, 65536));
    for (std::uint32_t q = 0; q < ni && rd.ok(); ++q) {
      const std::uint32_t idx = rd.u32();
      if (rd.ok() && idx >= nv) rd.bad("triangle index out of range");
      t.indices.push_back(idx);
    }
    t.surfaceMode = rd.u8();
    t.surface = rd.u16();
    if (rd.ok() && t.surfaceMode > 1) rd.bad("unknown surfaceMode");
    if (rd.ok() && t.surfaceMode == 1) {
      const std::uint32_t nt3 = ni / 3;
      if (!rd.fits(nt3, 2)) {
        rd.bad("per-triangle surfaces do not fit in the payload");
      } else {
        for (std::uint32_t q = 0; q < nt3 && rd.ok(); ++q) t.triSurfaces.push_back(rd.u16());
      }
    }
    t.blocks = rd.u16();
    t.simLayer = rd.u16();
    if (rd.ok() && (t.blocks & ~kCollBlockBits)) rd.bad("blocks uses undefined bits");
    c.tris.push_back(std::move(t));
  }
  const std::uint32_t nh = rd.count(58, 4096, "hulls");
  for (std::uint32_t i = 0; i < nh && rd.ok(); ++i) {
    CollHull h;
    const std::uint32_t np = rd.count(12, 256, "hull points");
    if (rd.ok() && np < 4) rd.bad("hull needs 4..256 points");
    for (std::uint32_t q = 0; q < np && rd.ok(); ++q) h.points.push_back(ReadFx3(rd));
    h.surface = rd.u16();
    h.blocks = rd.u16();
    h.simLayer = rd.u16();
    if (rd.ok() && (h.blocks & ~kCollBlockBits)) rd.bad("blocks uses undefined bits");
    c.hulls.push_back(std::move(h));
  }
  const std::uint32_t npr = rd.count(23, 65535, "prims");
  for (std::uint32_t i = 0; i < npr && rd.ok(); ++i) {
    CollPrim p;
    ReadShape3D(rd, p.shape, "prim shape");
    p.surface = rd.u16();
    p.blocks = rd.u16();
    p.simLayer = rd.u16();
    if (rd.ok() && (p.blocks & ~kCollBlockBits)) rd.bad("blocks uses undefined bits");
    c.prims.push_back(std::move(p));
  }
  if (!Finish(rd, "COLL", err)) return false;
  out = std::move(c);
  return true;
}

void DumpColl(TextDump& d, const CollChunk& c)
{
  d.Count("COLL.tris", c.tris.size());
  for (std::size_t i = 0; i < c.tris.size(); ++i) {
    const CollTri& t = c.tris[i];
    const std::string p = TextDump::Idx("COLL.tris", i);
    d.U(p + ".vertexCount", t.vertices.size());
    DumpFx3Array(d, p + ".vertices", t.vertices);
    d.U(p + ".indexCount", t.indices.size());
    DumpScalarArray(d, p + ".indices", t.indices);
    d.U(p + ".surfaceMode", t.surfaceMode);
    d.U(p + ".surface", t.surface);
    if (t.surfaceMode == 1) {
      DumpScalarArray(d, p + ".triangleSurfaces", t.triSurfaces);
    }
    d.U(p + ".blocks", t.blocks);
    d.U(p + ".simLayer", t.simLayer);
  }
  d.Count("COLL.hulls", c.hulls.size());
  for (std::size_t i = 0; i < c.hulls.size(); ++i) {
    const CollHull& h = c.hulls[i];
    const std::string p = TextDump::Idx("COLL.hulls", i);
    DumpFx3Array(d, p + ".vertices", h.points);
    d.U(p + ".surface", h.surface);
    d.U(p + ".blocks", h.blocks);
    d.U(p + ".simLayer", h.simLayer);
  }
  d.Count("COLL.prims", c.prims.size());
  for (std::size_t i = 0; i < c.prims.size(); ++i) {
    const CollPrim& pr = c.prims[i];
    const std::string p = TextDump::Idx("COLL.prims", i);
    DumpShape3D(d, p + ".shape", pr.shape);
    d.U(p + ".surface", pr.surface);
    d.U(p + ".blocks", pr.blocks);
    d.U(p + ".simLayer", pr.simLayer);
  }
}

// =====================================================================================================================
// NAVS
// =====================================================================================================================

bool DecodeNavs(const std::uint8_t* d, std::size_t n, ChunkCtx&, NavsChunk& out, std::string& err)
{
  Rd rd(d, n);
  NavsChunk c;
  std::vector<std::uint8_t> seen(65536, 0);
  const std::uint32_t ns = rd.count(20, 4096, "surfaces");
  for (std::uint32_t i = 0; i < ns && rd.ok(); ++i) {
    NavsSurface s;
    s.id = rd.u16();
    s.name = rd.str();
    s.kind = rd.u8();
    s.moveMask = rd.u8();
    s.clearance = rd.i32();
    s.simLayer = rd.u16();
    if (rd.ok()) {
      if (s.id == 0) rd.bad("surface id 0 is the implicit heightfield");
      else if (seen[s.id]) rd.bad("duplicate surface id");
      else if (s.kind > 1) rd.bad("unknown surface kind");
      else if (s.moveMask & ~0xFU) rd.bad("moveMask uses undefined bits");
      else if (s.clearance < 0) rd.bad("negative clearance");
      seen[s.id] = 1;
    }
    if (rd.ok() && s.kind == 0) {
      s.x0 = rd.i32();
      s.z0 = rd.i32();
      s.x1 = rd.i32();
      s.z1 = rd.i32();
      if (rd.ok() && (s.x1 < s.x0 || s.z1 < s.z0)) rd.bad("patch rectangle is empty");
      if (rd.ok()) {
        const std::uint64_t w = static_cast<std::uint64_t>(static_cast<std::int64_t>(s.x1) - s.x0 + 1);
        const std::uint64_t h = static_cast<std::uint64_t>(static_cast<std::int64_t>(s.z1) - s.z0 + 1);
        s.heightsPredictor = rd.u8();
        std::vector<std::uint8_t> raw;
        if (ReadPlane(rd, w, h, 2, s.heightsPredictor, raw)) {
          s.heights = Widen16(raw);
          const std::uint64_t mb = BitmaskBytes(static_cast<std::uint32_t>(w), static_cast<std::uint32_t>(h));
          if (mb > rd.r.remaining()) {
            rd.bad("walkable mask larger than the remaining payload");
          } else {
            const std::uint8_t* p = rd.r.bytes(mb);
            if (p) s.walkable.assign(p, p + static_cast<std::size_t>(mb));
          }
        }
      }
    } else if (rd.ok()) {
      const std::uint32_t nv = rd.count(12, kNoLimit, "vertices");
      s.vertices.reserve(std::min<std::uint32_t>(nv, 65536));
      for (std::uint32_t q = 0; q < nv && rd.ok(); ++q) s.vertices.push_back(ReadFx3(rd));
      const std::uint32_t ni = rd.count(4, kNoLimit, "indices");
      if (rd.ok() && ni % 3 != 0) rd.bad("indexCount is not a multiple of 3");
      s.indices.reserve(std::min<std::uint32_t>(ni, 65536));
      for (std::uint32_t q = 0; q < ni && rd.ok(); ++q) {
        const std::uint32_t idx = rd.u32();
        if (rd.ok() && idx >= nv) rd.bad("triangle index out of range");
        s.indices.push_back(idx);
      }
    }
    c.surfaces.push_back(std::move(s));
  }
  const std::uint32_t nl = rd.count(35, 65535, "links");
  c.links.reserve(std::min<std::uint32_t>(nl, 65536));
  for (std::uint32_t i = 0; i < nl && rd.ok(); ++i) {
    NavsLink l;
    l.fromSurface = rd.u16();
    l.from = ReadFx3(rd);
    l.toSurface = rd.u16();
    l.to = ReadFx3(rd);
    l.kind = rd.u8();
    l.moveMask = rd.u8();
    l.cost = rd.i32();
    l.bidirectional = rd.u8();
    if (rd.ok()) {
      if (l.kind > 4) rd.bad("unknown link kind");
      else if (l.moveMask & ~0xFU) rd.bad("moveMask uses undefined bits");
      else if (l.cost < 0) rd.bad("negative link cost");
      else if (l.bidirectional > 1) rd.bad("bidirectional must be 0 or 1");
      else if ((l.fromSurface != 0 && !seen[l.fromSurface]) || (l.toSurface != 0 && !seen[l.toSurface]))
        rd.bad("link references an unknown surface");
    }
    c.links.push_back(l);
  }
  if (!Finish(rd, "NAVS", err)) return false;
  out = std::move(c);
  return true;
}

void DumpNavs(TextDump& d, const NavsChunk& c)
{
  d.Count("NAVS.surfaces", c.surfaces.size());
  for (std::size_t i = 0; i < c.surfaces.size(); ++i) {
    const NavsSurface& s = c.surfaces[i];
    const std::string p = TextDump::Idx("NAVS.surfaces", i);
    d.U(p + ".id", s.id);
    d.Str(p + ".name", s.name);
    d.U(p + ".kind", s.kind);
    d.U(p + ".moveMask", s.moveMask);
    d.I(p + ".clearance", s.clearance);
    d.U(p + ".simLayer", s.simLayer);
    if (s.kind == 0) {
      d.I(p + ".x0", s.x0);
      d.I(p + ".z0", s.z0);
      d.I(p + ".x1", s.x1);
      d.I(p + ".z1", s.z1);
      const std::vector<std::uint8_t> raw = Narrow16(s.heights);
      d.Plane(p + ".heights", static_cast<std::uint64_t>(static_cast<std::int64_t>(s.x1) - s.x0 + 1),
              static_cast<std::uint64_t>(static_cast<std::int64_t>(s.z1) - s.z0 + 1), DataOf(raw), raw.size());
      d.Bytes(p + ".walkable", DataOf(s.walkable), s.walkable.size());
    } else {
      DumpFx3Array(d, p + ".vertices", s.vertices);
      d.U(p + ".indexCount", s.indices.size());
      DumpScalarArray(d, p + ".indices", s.indices);
    }
  }
  d.Count("NAVS.links", c.links.size());
  for (std::size_t i = 0; i < c.links.size(); ++i) {
    const NavsLink& l = c.links[i];
    const std::string p = TextDump::Idx("NAVS.links", i);
    d.U(p + ".fromSurface", l.fromSurface);
    DumpFx3(d, p + ".from", l.from);
    d.U(p + ".toSurface", l.toSurface);
    DumpFx3(d, p + ".to", l.to);
    d.U(p + ".kind", l.kind);
    d.U(p + ".moveMask", l.moveMask);
    d.I(p + ".cost", l.cost);
    d.U(p + ".bidirectional", l.bidirectional);
  }
}

// =====================================================================================================================
// VOLS
// =====================================================================================================================

bool DecodeVols(const std::uint8_t* d, std::size_t n, ChunkCtx&, VolsChunk& out, std::string& err)
{
  Rd rd(d, n);
  VolsChunk c;
  const std::uint32_t nv = rd.count(29, 4096, "volumes");
  for (std::uint32_t i = 0; i < nv && rd.ok(); ++i) {
    VolsVolume v;
    v.name = rd.str();
    ReadShape3D(rd, v.shape, "volume shape");
    v.flags = rd.u32();
    v.army = rd.i16();
    if (rd.ok() && (v.flags & ~0xFU)) rd.bad("volume flags use undefined bits");
    if (rd.ok() && v.army < -1) rd.bad("army below -1");
    const std::uint32_t nt = rd.count(2, 16, "tags");
    for (std::uint32_t q = 0; q < nt && rd.ok(); ++q) v.tags.push_back(rd.str());
    c.volumes.push_back(std::move(v));
  }
  if (!Finish(rd, "VOLS", err)) return false;
  out = std::move(c);
  return true;
}

void DumpVols(TextDump& d, const VolsChunk& c)
{
  d.Count("VOLS.volumes", c.volumes.size());
  for (std::size_t i = 0; i < c.volumes.size(); ++i) {
    const VolsVolume& v = c.volumes[i];
    const std::string p = TextDump::Idx("VOLS.volumes", i);
    d.Str(p + ".name", v.name);
    DumpShape3D(d, p + ".shape", v.shape);
    d.U(p + ".flags", v.flags);
    d.I(p + ".army", v.army);
    d.Count(p + ".tags", v.tags.size());
    for (std::size_t q = 0; q < v.tags.size(); ++q) d.Str(TextDump::Idx(p + ".tags", q), v.tags[q]);
  }
}

// =====================================================================================================================
// Family entry point
// =====================================================================================================================

namespace {

template <typename Chunk, typename DecodeFn, typename DumpFn>
DecodeStatus RunChunk(DecodeFn decode, DumpFn dumpFn, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx,
                      TextDump& dump, std::string& err)
{
  Chunk c;
  if (!decode(data, size, ctx, c, err)) return DecodeStatus::Error;
  dumpFn(dump, c);
  return DecodeStatus::Ok;
}

} // namespace

DecodeStatus DumpChunkSim(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size,
                          ChunkCtx& ctx, TextDump& dump, std::string& err)
{
  static const char* const kIds[] = {"GRID", "HGHT", "PLAY", "GPLY", "WBOD", "LEVL", "MRKR", "AREA",
                                     "PROP", "HINT", "WRLD", "SLYR", "COLL", "NAVS", "VOLS"};
  bool mine = false;
  for (const char* k : kIds) mine = mine || id == k;
  if (!mine) return DecodeStatus::NotMine;
  if (version != 1) {
    err = id + ": unsupported chunk version " + std::to_string(version) + " (this reader knows 1)";
    return DecodeStatus::Error;
  }
  // Decoding appends nothing to `dump` unless it succeeds, so build into a scratch dump first.
  TextDump scratch;
  DecodeStatus st = DecodeStatus::Error;
  if (id == "GRID") st = RunChunk<GridChunk>(DecodeGrid, DumpGrid, data, size, ctx, scratch, err);
  else if (id == "HGHT") st = RunChunk<HghtChunk>(DecodeHght, DumpHght, data, size, ctx, scratch, err);
  else if (id == "PLAY") st = RunChunk<PlayChunk>(DecodePlay, DumpPlay, data, size, ctx, scratch, err);
  else if (id == "GPLY") st = RunChunk<GplyChunk>(DecodeGply, DumpGply, data, size, ctx, scratch, err);
  else if (id == "WBOD") st = RunChunk<WbodChunk>(DecodeWbod, DumpWbod, data, size, ctx, scratch, err);
  else if (id == "LEVL") st = RunChunk<LevlChunk>(DecodeLevl, DumpLevl, data, size, ctx, scratch, err);
  else if (id == "MRKR") st = RunChunk<MrkrChunk>(DecodeMrkr, DumpMrkr, data, size, ctx, scratch, err);
  else if (id == "AREA") st = RunChunk<AreaChunk>(DecodeArea, DumpArea, data, size, ctx, scratch, err);
  else if (id == "PROP") st = RunChunk<PropChunk>(DecodeProp, DumpProp, data, size, ctx, scratch, err);
  else if (id == "HINT") st = RunChunk<HintChunk>(DecodeHint, DumpHint, data, size, ctx, scratch, err);
  else if (id == "WRLD") st = RunChunk<WrldChunk>(DecodeWrld, DumpWrld, data, size, ctx, scratch, err);
  else if (id == "SLYR") st = RunChunk<SlyrChunk>(DecodeSlyr, DumpSlyr, data, size, ctx, scratch, err);
  else if (id == "COLL") st = RunChunk<CollChunk>(DecodeColl, DumpColl, data, size, ctx, scratch, err);
  else if (id == "NAVS") st = RunChunk<NavsChunk>(DecodeNavs, DumpNavs, data, size, ctx, scratch, err);
  else if (id == "VOLS") st = RunChunk<VolsChunk>(DecodeVols, DumpVols, data, size, ctx, scratch, err);
  if (st == DecodeStatus::Ok) dump.out += scratch.out;
  return st;
}

// =====================================================================================================================
// Cross-chunk validation
// =====================================================================================================================

namespace {

bool VFail(std::string& err, const std::string& msg)
{
  err = msg;
  return false;
}

std::string At(const char* chunk, std::size_t i, const char* what)
{
  return std::string(chunk) + "[" + std::to_string(i) + "]: " + what;
}

} // namespace

bool ValidateSimData(const MapSimData& m, std::string& err)
{
  // Rule 1: every Extended map has the five required sim chunks.
  if (!m.grid) return VFail(err, "missing required chunk GRID");
  if (!m.hght) return VFail(err, "missing required chunk HGHT");
  if (!m.play) return VFail(err, "missing required chunk PLAY");
  if (!m.gply) return VFail(err, "missing required chunk GPLY");
  if (!m.wbod) return VFail(err, "missing required chunk WBOD");
  if (m.container == 4 && !m.wrld) return VFail(err, "missing required chunk WRLD (container 4)");
  if (m.container != 4 && (m.wrld || m.slyr || !m.coll.empty() || m.navs || m.vols))
    return VFail(err, "Full3D sim chunks (WRLD SLYR COLL NAVS VOLS) are only valid in container 4");

  const GridChunk& g = *m.grid;
  if (g.cellsX < 1 || g.cellsX > kMaxAxisCells || g.cellsZ < 1 || g.cellsZ > kMaxAxisCells ||
      (static_cast<std::uint64_t>(g.cellsX) + 1) * (static_cast<std::uint64_t>(g.cellsZ) + 1) > kMaxSamples)
    return VFail(err, "GRID: dimensions out of range");
  const std::int64_t cx = g.cellsX;
  const std::int64_t cz = g.cellsZ;

  // HGHT sample count against GRID, and GRID's min/max must bound every sample.
  const HghtChunk& h = *m.hght;
  if (h.width != g.cellsX + 1ULL || h.height != g.cellsZ + 1ULL ||
      h.samples.size() != static_cast<std::uint64_t>(h.width) * h.height)
    return VFail(err, "HGHT: sample count does not match GRID ((cellsX+1)*(cellsZ+1))");
  if (!h.samples.empty()) {
    const auto mm = std::minmax_element(h.samples.begin(), h.samples.end());
    if (DecodeHeight(h, *mm.first) < g.minElevation || DecodeHeight(h, *mm.second) > g.maxElevation)
      return VFail(err, "HGHT: samples leave the GRID minElevation..maxElevation range");
  }

  // PLAY rectangle inside the grid, polygon inside the rectangle.
  const PlayChunk& p = *m.play;
  if (p.x1 <= p.x0 || p.z1 <= p.z0) return VFail(err, "PLAY: empty rectangle");
  if (p.x0 < 0 || p.z0 < 0 || p.x1 > cx || p.z1 > cz) return VFail(err, "PLAY: rectangle leaves the grid");
  if (!p.polygon.empty() && (p.polygon.size() < 3 || p.polygon.size() > 1024))
    return VFail(err, "PLAY: polygon needs 3..1024 points");
  if (!PlayPolygonInsideRect(p)) return VFail(err, "PLAY: polygon leaves the rectangle");

  // GPLY: plane size and ids against the table, mask sizes.
  const GplyChunk& gp = *m.gply;
  if (gp.width != g.cellsX || gp.height != g.cellsZ ||
      gp.ids.size() != static_cast<std::uint64_t>(g.cellsX) * g.cellsZ)
    return VFail(err, "GPLY: surface id plane does not match the GRID size");
  if (gp.idWidth != 1 && gp.idWidth != 2) return VFail(err, "GPLY: idWidth must be 1 or 2");
  {
    std::vector<std::uint8_t> seen(65536, 0);
    for (const GplySurface& s : gp.surfaces) {
      if (seen[s.id]) return VFail(err, "GPLY: duplicate surface id");
      seen[s.id] = 1;
    }
    const std::vector<std::uint8_t> table = IdTable(gp.surfaces);
    for (std::uint16_t id : gp.ids) {
      if (!table[id]) return VFail(err, "GPLY: surface id in the plane is not in the table");
      if (gp.idWidth == 1 && id > 255) return VFail(err, "GPLY: surface id above 255 with idWidth 1");
    }
  }
  for (std::size_t i = 0; i < gp.masks.size(); ++i) {
    const GplyMask& k = gp.masks[i];
    const std::uint64_t want = k.kind == 1 ? BitmaskBytes(g.cellsX, g.cellsZ)
                                           : static_cast<std::uint64_t>(g.cellsX) * g.cellsZ;
    if ((k.kind != 1 && k.kind != 8) || k.data.size() != want)
      return VFail(err, At("GPLY.masks", i, "mask does not match the GRID size"));
  }

  // WBOD: extents inside the grid.
  const WbodChunk& w = *m.wbod;
  if (w.bodies.empty()) return VFail(err, "WBOD: empty body array");
  for (std::size_t i = 0; i < w.bodies.size(); ++i) {
    const WbodBody& b = w.bodies[i];
    if (b.extentKind == 1) {
      if (b.mask.size() != BitmaskBytes(g.cellsX, g.cellsZ))
        return VFail(err, At("WBOD.bodies", i, "mask does not match the GRID size"));
    } else if (b.extentKind == 2) {
      if (b.polygon.size() < 3 || b.polygon.size() > 4096)
        return VFail(err, At("WBOD.bodies", i, "polygon needs 3..4096 points"));
      for (const FxVec2& v : b.polygon)
        if (v.x < 0 || v.z < 0 || v.x > cx * 256 || v.z > cz * 256)
          return VFail(err, At("WBOD.bodies", i, "polygon leaves the grid"));
    } else if (b.extentKind != 0) {
      return VFail(err, At("WBOD.bodies", i, "unknown extentKind"));
    }
  }

  // LEVL: rectangles inside the grid, patch sample counts, portal targets.
  if (m.levl) {
    const LevlChunk& l = *m.levl;
    for (std::size_t i = 0; i < l.decks.size(); ++i) {
      const LevlDeck& k = l.decks[i];
      if (k.x0 < 0 || k.z0 < 0 || k.x1 < k.x0 || k.z1 < k.z0 || k.x1 >= cx || k.z1 >= cz)
        return VFail(err, At("LEVL.decks", i, "rectangle leaves the grid"));
      if (k.mode == 2) {
        const std::uint64_t cnt = static_cast<std::uint64_t>(k.x1 - k.x0 + 1) * static_cast<std::uint64_t>(k.z1 - k.z0 + 1);
        if (k.patch.size() != cnt) return VFail(err, At("LEVL.decks", i, "patch sample count does not match the rectangle"));
      } else if (!k.patch.empty()) {
        return VFail(err, At("LEVL.decks", i, "patch samples on a deck that is not a patch"));
      }
      for (const LevlPortal& q : k.portals) {
        if (q.targetDeck == 0xFFFF) continue;
        bool found = false;
        for (const LevlDeck& o : l.decks) found = found || o.id == q.targetDeck;
        if (!found) return VFail(err, At("LEVL.decks", i, "portal targets an unknown deck"));
      }
    }
  }

  // MRKR links.
  if (m.mrkr) {
    const MrkrChunk& mk = *m.mrkr;
    for (std::size_t i = 0; i < mk.markers.size(); ++i)
      for (std::uint32_t link : mk.markers[i].links)
        if (link >= mk.markers.size()) return VFail(err, At("MRKR.markers", i, "link index out of range"));
  }

  // PROP blueprint indices.
  if (m.prop) {
    const PropChunk& pr = *m.prop;
    for (std::size_t i = 0; i < pr.props.size(); ++i)
      if (pr.props[i].blueprintIndex >= pr.blueprints.size())
        return VFail(err, At("PROP.props", i, "blueprint index out of range"));
  }

  // HINT region ids, and candidate marker ids against MRKR.
  if (m.hint) {
    const HintChunk& hi = *m.hint;
    std::vector<std::uint32_t> ids;
    for (const HintRegion& r : hi.regions) ids.push_back(r.id);
    std::sort(ids.begin(), ids.end());
    if (std::adjacent_find(ids.begin(), ids.end()) != ids.end()) return VFail(err, "HINT: duplicate region id");
    const auto known = [&ids](std::uint32_t id) { return std::binary_search(ids.begin(), ids.end(), id); };
    for (std::size_t i = 0; i < hi.regions.size(); ++i)
      for (std::uint32_t nb : hi.regions[i].neighbors)
        if (!known(nb)) return VFail(err, At("HINT.regions", i, "neighbor references an unknown region"));
    for (std::size_t i = 0; i < hi.chokes.size(); ++i)
      if (!known(hi.chokes[i].regionA) || !known(hi.chokes[i].regionB))
        return VFail(err, At("HINT.chokes", i, "choke references an unknown region"));
    const std::size_t nMarkers = m.mrkr ? m.mrkr->markers.size() : 0;
    for (std::size_t i = 0; i < hi.candidates.size(); ++i)
      for (std::uint32_t id : hi.candidates[i].markerIds)
        if (id >= nMarkers) return VFail(err, At("HINT.candidates", i, "marker id out of range of MRKR"));
  }

  // Full3D.
  const std::size_t layerCount = m.slyr ? m.slyr->layers.size() : 0;
  if (m.slyr && m.slyr->layers.size() > 64) return VFail(err, "SLYR: more than 64 layers");
  if (m.wrld) {
    const WrldChunk& wr = *m.wrld;
    const std::uint64_t cells = static_cast<std::uint64_t>(wr.cellsX) * wr.cellsY * wr.cellsZ;
    if (wr.cellsX < 1 || wr.cellsY < 1 || wr.cellsZ < 1 || cells > (1ULL << 22) || wr.cellsX > (1U << 22) ||
        wr.cellsY > (1U << 22) || wr.cellsZ > (1U << 22))
      return VFail(err, "WRLD: cell counts out of range");
    for (const MapSimData::CollEntry& e : m.coll)
      if (e.instance >= cells) return VFail(err, "COLL: instance is not a cell of WRLD");
  }
  for (std::size_t e = 0; e < m.coll.size(); ++e) {
    const CollChunk& c = m.coll[e].chunk;
    for (std::size_t i = 0; i < c.tris.size(); ++i) {
      const CollTri& t = c.tris[i];
      if (t.indices.size() % 3 != 0) return VFail(err, At("COLL.tris", i, "index count is not a multiple of 3"));
      for (std::uint32_t idx : t.indices)
        if (idx >= t.vertices.size()) return VFail(err, At("COLL.tris", i, "index out of range"));
      if (t.surfaceMode > 1) return VFail(err, At("COLL.tris", i, "unknown surfaceMode"));
      if (t.surfaceMode == 1 && t.triSurfaces.size() != t.indices.size() / 3)
        return VFail(err, At("COLL.tris", i, "per-triangle surface count does not match"));
      if (t.surfaceMode == 0 && !t.triSurfaces.empty())
        return VFail(err, At("COLL.tris", i, "per-triangle surfaces with surfaceMode 0"));
      if (t.simLayer > layerCount) return VFail(err, At("COLL.tris", i, "simLayer above the SLYR layer count"));
    }
    for (std::size_t i = 0; i < c.hulls.size(); ++i) {
      if (c.hulls[i].points.size() < 4 || c.hulls[i].points.size() > 256)
        return VFail(err, At("COLL.hulls", i, "hull needs 4..256 points"));
      if (c.hulls[i].simLayer > layerCount) return VFail(err, At("COLL.hulls", i, "simLayer above the SLYR layer count"));
    }
    for (std::size_t i = 0; i < c.prims.size(); ++i)
      if (c.prims[i].simLayer > layerCount) return VFail(err, At("COLL.prims", i, "simLayer above the SLYR layer count"));
  }
  if (m.navs) {
    const NavsChunk& nv = *m.navs;
    std::vector<std::uint8_t> ids(65536, 0);
    for (std::size_t i = 0; i < nv.surfaces.size(); ++i) {
      const NavsSurface& s = nv.surfaces[i];
      if (s.id == 0) return VFail(err, At("NAVS.surfaces", i, "id 0 is the implicit heightfield"));
      if (ids[s.id]) return VFail(err, At("NAVS.surfaces", i, "duplicate surface id"));
      ids[s.id] = 1;
      if (s.simLayer > layerCount) return VFail(err, At("NAVS.surfaces", i, "simLayer above the SLYR layer count"));
      if (s.kind == 0) {
        if (s.x1 < s.x0 || s.z1 < s.z0) return VFail(err, At("NAVS.surfaces", i, "empty patch rectangle"));
        const std::uint64_t w = static_cast<std::uint64_t>(static_cast<std::int64_t>(s.x1) - s.x0 + 1);
        const std::uint64_t hh = static_cast<std::uint64_t>(static_cast<std::int64_t>(s.z1) - s.z0 + 1);
        if (w > kMaxAxisCells || hh > kMaxAxisCells || s.heights.size() != w * hh ||
            s.walkable.size() != BitmaskBytes(static_cast<std::uint32_t>(w), static_cast<std::uint32_t>(hh)))
          return VFail(err, At("NAVS.surfaces", i, "patch sample or mask count does not match the rectangle"));
      } else if (s.kind == 1) {
        if (s.indices.size() % 3 != 0) return VFail(err, At("NAVS.surfaces", i, "index count is not a multiple of 3"));
        for (std::uint32_t idx : s.indices)
          if (idx >= s.vertices.size()) return VFail(err, At("NAVS.surfaces", i, "index out of range"));
      } else {
        return VFail(err, At("NAVS.surfaces", i, "unknown surface kind"));
      }
    }
    for (std::size_t i = 0; i < nv.links.size(); ++i) {
      const NavsLink& l = nv.links[i];
      if ((l.fromSurface != 0 && !ids[l.fromSurface]) || (l.toSurface != 0 && !ids[l.toSurface]))
        return VFail(err, At("NAVS.links", i, "references an unknown surface"));
    }
  }
  return true;
}

std::uint64_t RequiredFeatureMaskFor(const MapSimData& m)
{
  std::uint64_t f = 0;
  if (m.grid) {
    if (m.grid->cellsX != m.grid->cellsZ) f |= kFeat_GridNonSquare;
    if (m.grid->cellsX > 4096 || m.grid->cellsZ > 4096) f |= kFeat_GridLarge;
  }
  if (m.hght && m.hght->stepLog2 < -7) f |= kFeat_HeightFine;
  if (m.play && !m.play->polygon.empty()) f |= kFeat_PlayablePolygon;
  if (m.gply) {
    static const char* const kKnown[] = {"buildable_override", "walk_land", "walk_hover", "walk_amphib",
                                         "air_block", "no_fog", "vision_block", "reclaim_ok"};
    for (const GplySurface& s : m.gply->surfaces)
      if (s.speedMul != 256) f |= kFeat_SurfaceLayers;
    for (const GplyMask& k : m.gply->masks)
      for (const char* name : kKnown)
        if (k.name == name) f |= kFeat_SurfaceLayers;
  }
  if (m.wbod) {
    const bool classic = m.wbod->bodies.size() == 1 && m.wbod->bodies[0].kind == 0 && m.wbod->bodies[0].extentKind == 0;
    if (!classic) f |= kFeat_WaterBodies;
  }
  if (m.levl && !m.levl->decks.empty()) f |= kFeat_Levels;
  // Decided by chunk presence only: the writer cannot tell "authoritative" from the data.
  if (m.mrkr || m.area) f |= kFeat_MarkersBinary;
  if (m.prop) f |= kFeat_PropsBinary;
  if (m.hint) f |= kFeat_Hints;
  if (m.wrld) {
    const WrldChunk& w = *m.wrld;
    if (static_cast<std::uint64_t>(w.cellsX) * w.cellsY * w.cellsZ > 1) f |= kFeat_WorldCells;
    if (w.flags & 1U) f |= kFeat_WorldLargeCoords;
  }
  if (!m.coll.empty()) f |= kFeat_WorldCollision;
  if (m.navs) f |= kFeat_WorldNav3d;
  if (m.vols) f |= kFeat_WorldVolumesSim;
  return f;
}

std::vector<std::string> RequiredFeatureBitsFor(const MapSimData& m) { return FeatureNames(RequiredFeatureMaskFor(m)); }

} // namespace moho::mapformat
