// Full3D sim chunks: WRLD SLYR COLL NAVS VOLS, their cross references and the container 4 feature bits.
#include <cstring>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/SimChunks.h"

using namespace moho::mapformat;
using Buf = std::vector<std::uint8_t>;

namespace {

struct Rng
{
  std::uint32_t s;
  std::uint32_t next()
  {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
  }
};

bool HasLine(const std::string& dump, const std::string& line)
{
  const std::string needle = line + "\n";
  const std::size_t at = dump.find(needle);
  return at != std::string::npos && (at == 0 || dump[at - 1] == '\n');
}

DecodeStatus RunCase(const std::string& id, const Buf& b, std::string* dump = nullptr, std::string* err = nullptr,
                 std::uint16_t version = 1)
{
  ChunkCtx ctx;
  ctx.cellsX = 4;
  ctx.cellsZ = 3;
  ctx.container = 4;
  TextDump td;
  std::string e;
  const DecodeStatus st = DumpChunkSim(id, version, b.empty() ? nullptr : b.data(), b.size(), ctx, td, e);
  if (dump) *dump = td.out;
  if (err) *err = e;
  return st;
}

/// Decoding must fail and the message must contain `needle`.
bool ExpectErr(const std::string& id, const Buf& b, const char* needle)
{
  std::string err;
  if (RunCase(id, b, nullptr, &err) != DecodeStatus::Error) {
    std::printf("  %s: payload was accepted, wanted an error containing '%s'\n", id.c_str(), needle);
    return false;
  }
  if (err.find(needle) == std::string::npos) {
    std::printf("  %s: error '%s' does not contain '%s'\n", id.c_str(), err.c_str(), needle);
    return false;
  }
  return true;
}

void Put32(Buf& b, std::size_t off, std::uint32_t v)
{
  for (int i = 0; i < 4 && off + static_cast<std::size_t>(i) < b.size(); ++i)
    b[off + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}

Buf Pred16(const std::vector<std::uint16_t>& v, std::uint32_t cols, std::uint32_t rows, std::uint8_t pred)
{
  Buf raw(v.size() * 2), enc(v.size() * 2);
  for (std::size_t i = 0; i < v.size(); ++i) {
    raw[2 * i] = static_cast<std::uint8_t>(v[i]);
    raw[2 * i + 1] = static_cast<std::uint8_t>(v[i] >> 8);
  }
  PredictPlane(raw.data(), enc.data(), rows, cols, 1, 2, pred);
  return enc;
}

std::string Sha16(const std::vector<std::uint16_t>& v)
{
  Buf raw(v.size() * 2);
  for (std::size_t i = 0; i < v.size(); ++i) {
    raw[2 * i] = static_cast<std::uint8_t>(v[i]);
    raw[2 * i + 1] = static_cast<std::uint8_t>(v[i] >> 8);
  }
  return Sha256Hex(raw.data(), raw.size());
}

void Fx3(ByteWriter& w, std::int32_t x, std::int32_t y, std::int32_t z)
{
  w.i32(x);
  w.i32(y);
  w.i32(z);
}

void Fx2(ByteWriter& w, std::int32_t x, std::int32_t z)
{
  w.i32(x);
  w.i32(z);
}

/// shape3d writer: 0 box, 1 sphere, 2 convex, 3 extruded polygon, 4 capsule.
void WShape(ByteWriter& w, int kind)
{
  w.u8(static_cast<std::uint8_t>(kind));
  switch (kind) {
  case 0:
    Fx3(w, 1024, 2048, 3072);
    Fx3(w, 512, 512, 512);
    w.i16(0);
    w.i16(0);
    w.i16(0);
    w.i16(32767);
    break;
  case 1:
    Fx3(w, 0, 1024, 0);
    w.i32(5120);
    break;
  case 2:
    w.u32(4);
    Fx3(w, 0, 0, 0);
    Fx3(w, 1024, 0, 0);
    Fx3(w, 0, 1024, 0);
    Fx3(w, 0, 0, 1024);
    break;
  case 3:
    w.u32(3);
    Fx2(w, 0, 0);
    Fx2(w, 256, 0);
    Fx2(w, 0, 256);
    w.i32(-1024);
    w.i32(2048);
    break;
  default:
    Fx3(w, 0, 0, 0);
    Fx3(w, 0, 3072, 0);
    w.i32(512);
  }
}

// ---- payload builders (follow FULL3D.md) ----------------------------------------------------------------------------------

Buf BuildWrld(double ox = 0.0, std::uint8_t flags = 0, float cellSize = 256.0f, std::uint32_t cx = 4,
              std::uint32_t cy = 1, std::uint32_t cz = 4, std::uint8_t up = 1)
{
  ByteWriter w;
  w.f64(ox);
  w.f64(0.0);
  w.f64(0.0);
  w.vec3(-512, -100, -512);
  w.vec3(512, 400, 512);
  w.f32(cellSize);
  w.u32(cx);
  w.u32(cy);
  w.u32(cz);
  w.u8(up);
  w.f32(1.0f);
  w.u8(flags);
  return w.buf;
}

Buf BuildSlyr()
{
  ByteWriter w;
  w.u32(2);
  w.str("bridge");
  w.u8(1);
  w.str("door");
  w.u8(0);
  return w.buf;
}

Buf BuildColl()
{
  ByteWriter w;
  w.u32(2);
  // tri 0: quad, per-triangle surfaces
  w.u32(4);
  Fx3(w, 0, 0, 0);
  Fx3(w, 1024, 0, 0);
  Fx3(w, 1024, 0, 1024);
  Fx3(w, 0, 0, 1024);
  w.u32(6);
  for (std::uint32_t i : {0u, 1u, 2u, 0u, 2u, 3u}) w.u32(i);
  w.u8(1);
  w.u16(5);
  w.u16(5);
  w.u16(6);
  w.u16(0x03);
  w.u16(1);
  // tri 1: one triangle, one surface
  w.u32(3);
  Fx3(w, 0, 0, 0);
  Fx3(w, 100, 0, 0);
  Fx3(w, 0, 0, 100);
  w.u32(3);
  for (std::uint32_t i : {0u, 1u, 2u}) w.u32(i);
  w.u8(0);
  w.u16(2);
  w.u16(0x7F);
  w.u16(0);
  // hulls
  w.u32(1);
  w.u32(4);
  Fx3(w, 0, 0, 0);
  Fx3(w, 1024, 0, 0);
  Fx3(w, 0, 1024, 0);
  Fx3(w, 0, 0, 1024);
  w.u16(1);
  w.u16(1);
  w.u16(2);
  // prims: one of each kind
  w.u32(5);
  for (int k = 0; k < 5; ++k) {
    WShape(w, k);
    w.u16(static_cast<std::uint16_t>(10 + k));
    w.u16(static_cast<std::uint16_t>(1u << k));
    w.u16(static_cast<std::uint16_t>(k % 3));
  }
  return w.buf;
}

Buf BuildNavs()
{
  ByteWriter w;
  w.u32(2);
  // surface 1: height patch 2 x 2
  w.u16(1);
  w.str("deck");
  w.u8(0);
  w.u8(0x0B);
  w.i32(3 * 65536);
  w.u16(1);
  w.i32(0);
  w.i32(0);
  w.i32(1);
  w.i32(1);
  w.u8(2); // predictor up
  const Buf enc = Pred16({10, 20, 30, 40}, 2, 2, 2);
  w.bytes(enc.data(), enc.size());
  w.u8(0x03);
  w.u8(0x01);
  // surface 2: triangle mesh
  w.u16(2);
  w.str("ramp");
  w.u8(1);
  w.u8(1);
  w.i32(0);
  w.u16(0);
  w.u32(3);
  Fx3(w, 0, 0, 0);
  Fx3(w, 1024, 512, 0);
  Fx3(w, 0, 512, 1024);
  w.u32(3);
  for (std::uint32_t i : {0u, 1u, 2u}) w.u32(i);
  // links
  w.u32(2);
  w.u16(0);
  Fx3(w, 10, 20, 30);
  w.u16(1);
  Fx3(w, 40, 50, 60);
  w.u8(0);
  w.u8(1);
  w.i32(65536);
  w.u8(0);
  w.u16(1);
  Fx3(w, 0, 0, 0);
  w.u16(2);
  Fx3(w, 1, 1, 1);
  w.u8(4);
  w.u8(0x0F);
  w.i32(2 * 65536);
  w.u8(1);
  return w.buf;
}

Buf BuildVols()
{
  ByteWriter w;
  w.u32(5);
  const char* names[5] = {"box", "sphere", "hull", "prism", "capsule"};
  for (int k = 0; k < 5; ++k) {
    w.str(names[k]);
    WShape(w, k);
    w.u32(static_cast<std::uint32_t>(k == 0 ? 3 : 4));
    w.i16(static_cast<std::int16_t>(k == 1 ? 2 : -1));
    if (k == 0) {
      w.u32(2);
      w.str("start");
      w.str("zone");
    } else {
      w.u32(0);
    }
  }
  return w.buf;
}

struct Case
{
  const char* id;
  Buf valid;
};

std::vector<Case> Cases()
{
  return {{"WRLD", BuildWrld()}, {"SLYR", BuildSlyr()}, {"COLL", BuildColl()}, {"NAVS", BuildNavs()}, {"VOLS", BuildVols()}};
}

// ---- decoded map for the validator --------------------------------------------------------------------------------------------

MapSimData BuildMap()
{
  // Extended base (4 x 3 cells) decoded from hand-written payloads, then the Full3D chunks.
  MapSimData m;
  m.container = 4;
  ChunkCtx ctx;
  ctx.container = 4;
  std::string err;
  {
    ByteWriter w;
    w.u32(4);
    w.u32(3);
    w.f32(1.0f);
    w.f32(0);
    w.f32(0);
    w.f32(0);
    w.f32(512.0f);
    w.u8(0);
    GridChunk g;
    EXPECT_TRUE(DecodeGrid(w.buf.data(), w.buf.size(), ctx, g, err));
    m.grid = g;
  }
  {
    ByteWriter w;
    w.f32(0);
    w.i8(-7);
    w.u8(0);
    w.u16(0);
    for (int i = 0; i < 20; ++i) w.u16(static_cast<std::uint16_t>(i * 100));
    HghtChunk h;
    EXPECT_TRUE(DecodeHght(w.buf.data(), w.buf.size(), ctx, h, err));
    m.hght = h;
  }
  {
    ByteWriter w;
    w.i32(0);
    w.i32(0);
    w.i32(4);
    w.i32(3);
    w.u8(0);
    w.u32(0);
    PlayChunk p;
    EXPECT_TRUE(DecodePlay(w.buf.data(), w.buf.size(), ctx, p, err));
    m.play = p;
  }
  {
    ByteWriter w;
    w.u8(0);
    w.u32(1);
    w.u16(0);
    w.str("Land");
    w.u32(0);
    w.u16(256);
    w.str("");
    w.u8(1);
    w.u8(0);
    for (int i = 0; i < 12; ++i) w.u8(0);
    w.u32(0);
    GplyChunk gp;
    EXPECT_TRUE(DecodeGply(w.buf.data(), w.buf.size(), ctx, gp, err));
    m.gply = gp;
  }
  {
    ByteWriter w;
    w.u32(1);
    w.u16(0);
    w.str("sea");
    w.u8(0);
    w.f32(10.0f);
    w.u8(0);
    WbodChunk wb;
    EXPECT_TRUE(DecodeWbod(w.buf.data(), w.buf.size(), ctx, wb, err));
    m.wbod = wb;
  }
  Buf b = BuildWrld();
  WrldChunk wr;
  EXPECT_TRUE(DecodeWrld(b.data(), b.size(), ctx, wr, err));
  m.wrld = wr;
  SlyrChunk sl;
  b = BuildSlyr();
  EXPECT_TRUE(DecodeSlyr(b.data(), b.size(), ctx, sl, err));
  m.slyr = sl;
  MapSimData::CollEntry ce;
  ce.instance = 0;
  b = BuildColl();
  EXPECT_TRUE(DecodeColl(b.data(), b.size(), ctx, ce.chunk, err));
  m.coll.push_back(ce);
  ce.instance = 15;
  m.coll.push_back(ce);
  NavsChunk nv;
  b = BuildNavs();
  EXPECT_TRUE(DecodeNavs(b.data(), b.size(), ctx, nv, err));
  m.navs = nv;
  VolsChunk vo;
  b = BuildVols();
  EXPECT_TRUE(DecodeVols(b.data(), b.size(), ctx, vo, err));
  m.vols = vo;
  return m;
}

bool Invalid(const MapSimData& m, const char* needle)
{
  std::string err;
  if (ValidateSimData(m, err)) {
    std::printf("  validator accepted data that should fail (%s)\n", needle);
    return false;
  }
  if (err.find(needle) == std::string::npos) {
    std::printf("  wrong validator message '%s', wanted '%s'\n", err.c_str(), needle);
    return false;
  }
  return true;
}

} // namespace

TEST(MapFormatWorld3DSim, Checks)
{
  std::string dump, err;

  // ---- WRLD ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(BuildWrld().size(), 70U);
    EXPECT_EQ(RunCase("WRLD", BuildWrld(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "WRLD.originX = f64:0000000000000000"));
    EXPECT_TRUE(HasLine(dump, "WRLD.boundsMin = [f32:c4000000, f32:c2c80000, f32:c4000000]"));
    EXPECT_TRUE(HasLine(dump, "WRLD.boundsMax = [f32:44000000, f32:43c80000, f32:44000000]"));
    EXPECT_TRUE(HasLine(dump, "WRLD.cellSize = f32:43800000"));
    EXPECT_TRUE(HasLine(dump, "WRLD.cellsX = 4"));
    EXPECT_TRUE(HasLine(dump, "WRLD.cellsY = 1"));
    EXPECT_TRUE(HasLine(dump, "WRLD.cellsZ = 4"));
    EXPECT_TRUE(HasLine(dump, "WRLD.upAxis = 1"));
    EXPECT_TRUE(HasLine(dump, "WRLD.unitsPerMeter = f32:3f800000"));
    EXPECT_TRUE(HasLine(dump, "WRLD.flags = 0"));
    // Non-zero origin needs the LARGE_COORDS flag; with it the map is fine.
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(1.0e6), "LARGE_COORDS"));
    EXPECT_EQ(RunCase("WRLD", BuildWrld(1.0e6, 1), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "WRLD.originX = f64:412e848000000000"));
    // Bounds above 2^20 need the flag too.
    {
      Buf b = BuildWrld();
      Put32(b, 24 + 12, 0x4A800000); // boundsMax.x = 4194304
      EXPECT_TRUE(ExpectErr("WRLD", b, "LARGE_COORDS"));
      b[70 - 1] = 1;
      EXPECT_EQ(RunCase("WRLD", b), DecodeStatus::Ok);
    }
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 0, 31.0f), "cellSize"));
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 0, 4097.0f), "cellSize"));
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 0, 256.0f, 0, 1, 4), "cell counts"));
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 0, 256.0f, 2048, 2, 2048), "2^22"));
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 0, 256.0f, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu), "2^22"));
    EXPECT_EQ(RunCase("WRLD", BuildWrld(0, 0, 256.0f, 2048, 1, 2048), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 0, 256.0f, 4, 1, 4, 2), "upAxis"));
    EXPECT_TRUE(ExpectErr("WRLD", BuildWrld(0, 2), "flags"));
    Buf b = BuildWrld();
    Put32(b, 24, 0x7F800000); // boundsMin.x = inf
    EXPECT_TRUE(ExpectErr("WRLD", b, "non-finite"));
    b = BuildWrld();
    b[7] = 0x7F; // originX high byte: double NaN / inf
    b[6] = 0xF0;
    EXPECT_TRUE(ExpectErr("WRLD", b, "non-finite"));
  }

  // ---- SLYR ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("SLYR", BuildSlyr(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "SLYR.layers.count = 2"));
    EXPECT_TRUE(HasLine(dump, "SLYR.layers[0].name = \"bridge\""));
    EXPECT_TRUE(HasLine(dump, "SLYR.layers[0].defaultOn = 1"));
    EXPECT_TRUE(HasLine(dump, "SLYR.layers[1].defaultOn = 0"));
    ByteWriter dup;
    dup.u32(2);
    for (int i = 0; i < 2; ++i) {
      dup.str("x");
      dup.u8(0);
    }
    EXPECT_TRUE(ExpectErr("SLYR", dup.buf, "duplicate"));
    ByteWriter many;
    many.u32(65);
    for (int i = 0; i < 65; ++i) {
      many.str("l" + std::to_string(i));
      many.u8(0);
    }
    EXPECT_TRUE(ExpectErr("SLYR", many.buf, "above limit"));
    ByteWriter ok64;
    ok64.u32(64);
    for (int i = 0; i < 64; ++i) {
      ok64.str("l" + std::to_string(i));
      ok64.u8(1);
    }
    EXPECT_EQ(RunCase("SLYR", ok64.buf), DecodeStatus::Ok);
    Buf b = BuildSlyr();
    b[b.size() - 1] = 2;
    EXPECT_TRUE(ExpectErr("SLYR", b, "defaultOn"));
  }

  // ---- COLL ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("COLL", BuildColl(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "COLL.tris.count = 2"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[0].vertexCount = 4"));
    {
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].vertices.count = 4"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].vertices[0] = [0, 0, 0]"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].vertices[2] = [1024, 0, 1024]"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].vertices[3] = [0, 0, 1024]"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].indices.count = 6"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].indices[4] = 2"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].indices[5] = 3"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].triangleSurfaces.count = 2"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].triangleSurfaces[0] = 5"));
      EXPECT_TRUE(HasLine(dump, "COLL.tris[0].triangleSurfaces[1] = 6"));
    }
    EXPECT_TRUE(HasLine(dump, "COLL.tris[0].indexCount = 6"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[0].surfaceMode = 1"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[0].surface = 5"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[0].blocks = 3"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[0].simLayer = 1"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[1].surfaceMode = 0"));
    EXPECT_TRUE(HasLine(dump, "COLL.tris[1].blocks = 127"));
    EXPECT_TRUE(dump.find("COLL.tris[1].triangleSurfaces") == std::string::npos);
    EXPECT_TRUE(HasLine(dump, "COLL.hulls.count = 1"));
    EXPECT_TRUE(HasLine(dump, "COLL.hulls[0].vertices.count = 4"));
    EXPECT_TRUE(HasLine(dump, "COLL.hulls[0].vertices[1] = [1024, 0, 0]"));
    EXPECT_TRUE(HasLine(dump, "COLL.hulls[0].simLayer = 2"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims.count = 5"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[0].shape.kind = 0"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[0].shape.center = [1024, 2048, 3072]"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[0].shape.halfExtents = [512, 512, 512]"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[0].shape.rot = [0, 0, 0, 32767]"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[1].shape.radius = 5120"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[2].shape.vertices.count = 4"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[3].shape.polygon[1] = [256, 0]"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[3].shape.yMin = -1024"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[4].shape.b = [0, 3072, 0]"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[4].blocks = 16"));
    EXPECT_TRUE(HasLine(dump, "COLL.prims[4].simLayer = 1"));
    // Index out of range, indexCount not a multiple of 3, hostile vertex count, undefined block bit, unknown mode.
    // tris[0]: count(4) then vertexCount(4), 48 bytes of vertices, indexCount(4), indices (24).
    Buf b = BuildColl();
    Put32(b, 4 + 4 + 48 + 4 + 5 * 4, 4); // last index 3 -> 4
    EXPECT_TRUE(ExpectErr("COLL", b, "triangle index out of range"));
    b = BuildColl();
    Put32(b, 4 + 4 + 48, 5);
    EXPECT_TRUE(ExpectErr("COLL", b, "multiple of 3"));
    b = BuildColl();
    Put32(b, 4, 0xFFFFFFFFu);
    EXPECT_TRUE(ExpectErr("COLL", b, "vertices"));
    b = BuildColl();
    Put32(b, 4 + 4 + 48, 0xFFFFFFFFu);
    EXPECT_TRUE(ExpectErr("COLL", b, "indices"));
    b = BuildColl();
    b[4 + 4 + 48 + 4 + 24] = 2; // surfaceMode
    EXPECT_TRUE(ExpectErr("COLL", b, "surfaceMode"));
    b = BuildColl();
    b[4 + 4 + 48 + 4 + 24 + 1 + 2 + 4 + 1] = 0x80; // blocks high byte (after per-triangle surfaces) -> bit 15
    EXPECT_TRUE(ExpectErr("COLL", b, "blocks"));
    // A hull with 3 points; a prim with an unknown shape kind.
    {
      ByteWriter w;
      w.u32(0);
      w.u32(1);
      w.u32(3);
      Fx3(w, 0, 0, 0);
      Fx3(w, 1, 0, 0);
      Fx3(w, 0, 1, 0);
      w.u16(0);
      w.u16(0);
      w.u16(0);
      w.u32(0);
      // count(58) fails first because 3 points do not even fit the minimum element: still an error.
      EXPECT_EQ(RunCase("COLL", w.buf), DecodeStatus::Error);
    }
    {
      ByteWriter w;
      w.u32(0);
      w.u32(0);
      w.u32(1);
      w.u8(9);
      for (int i = 0; i < 40; ++i) w.u8(0);
      EXPECT_TRUE(ExpectErr("COLL", w.buf, "shape3d kind"));
    }
  }

  // ---- NAVS ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("NAVS", BuildNavs(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces.count = 2"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].id = 1"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].name = \"deck\""));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].moveMask = 11"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].clearance = 196608"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].x1 = 1"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].heights = plane[2x2] sha256:" + Sha16({10, 20, 30, 40})));
    {
      const std::uint8_t m[2] = {3, 1};
      EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[0].walkable = bytes[2] sha256:" + Sha256Hex(m, 2)));
      EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].vertices[1] = [1024, 512, 0]"));
      EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].vertices[2] = [0, 512, 1024]"));
      EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].indices.count = 3"));
      EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].indices[2] = 2"));
    }
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].kind = 1"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].vertices.count = 3"));
    EXPECT_TRUE(HasLine(dump, "NAVS.surfaces[1].indexCount = 3"));
    EXPECT_TRUE(HasLine(dump, "NAVS.links.count = 2"));
    EXPECT_TRUE(HasLine(dump, "NAVS.links[0].fromSurface = 0"));
    EXPECT_TRUE(HasLine(dump, "NAVS.links[0].from = [10, 20, 30]"));
    EXPECT_TRUE(HasLine(dump, "NAVS.links[0].cost = 65536"));
    EXPECT_TRUE(HasLine(dump, "NAVS.links[1].kind = 4"));
    EXPECT_TRUE(HasLine(dump, "NAVS.links[1].bidirectional = 1"));
    // Predictors 0..3 for the patch.
    for (std::uint8_t pred = 0; pred <= 3; ++pred) {
      ByteWriter w;
      w.u32(1);
      w.u16(7);
      w.str("p");
      w.u8(0);
      w.u8(1);
      w.i32(0);
      w.u16(0);
      w.i32(-2);
      w.i32(5);
      w.i32(0);
      w.i32(6);
      w.u8(pred);
      const std::vector<std::uint16_t> h = {1, 60000, 2, 3, 4, 5, 65535, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 100, 200, 300, 400, 500, 600};
      // rect x -2..0 (3), z 5..6 (2): 6 samples
      const std::vector<std::uint16_t> hs(h.begin(), h.begin() + 6);
      const Buf enc = Pred16(hs, 3, 2, pred);
      w.bytes(enc.data(), enc.size());
      w.u8(0x07);
      w.u8(0x05);
      w.u32(0);
      NavsChunk n;
      ChunkCtx ctx;
      EXPECT_TRUE(DecodeNavs(w.buf.data(), w.buf.size(), ctx, n, err));
      EXPECT_TRUE(n.surfaces[0].heights == hs);
    }
    // Surface id 0, duplicate, link to unknown surface, bad kind, mesh index out of range, hostile counts.
    Buf b = BuildNavs();
    b[4] = 0;
    EXPECT_TRUE(ExpectErr("NAVS", b, "implicit heightfield"));
    b = BuildNavs();
    // second surface id -> 1: offset = 4 + first surface (2+2+4+1+1+4+2 + 16 + 1 + 8 + 2) = 4 + 43
    b[4 + 43] = 1;
    EXPECT_TRUE(ExpectErr("NAVS", b, "duplicate"));
    b = BuildNavs();
    b[b.size() - 35] = 9; // links[1].fromSurface (a link record is 35 bytes)
    EXPECT_TRUE(ExpectErr("NAVS", b, "unknown surface"));
    b = BuildNavs();
    Put32(b, 0, 0xFFFFFFFFu);
    EXPECT_TRUE(ExpectErr("NAVS", b, "above limit"));
    b = BuildNavs();
    b[b.size() - 35 * 2 - 4 - 3 * 4] = 3; // indices[0] of the mesh -> 3 (vertex count is 3)
    EXPECT_TRUE(ExpectErr("NAVS", b, "triangle index out of range"));
    b = BuildNavs();
    Put32(b, 4 + 43 + 2 + 2 + 4 + 1 + 1 + 4 + 2, 0xFFFFFFFFu); // mesh vertex count
    EXPECT_TRUE(ExpectErr("NAVS", b, "vertices"));
    {
      // Patch rectangle larger than any grid: refused by arithmetic.
      ByteWriter w;
      w.u32(1);
      w.u16(1);
      w.str("big");
      w.u8(0);
      w.u8(1);
      w.i32(0);
      w.u16(0);
      w.i32(-0x7FFFFFFF);
      w.i32(0);
      w.i32(0x7FFFFFFF);
      w.i32(0);
      w.u8(0);
      for (int i = 0; i < 16; ++i) w.u8(0);
      w.u32(0);
      EXPECT_TRUE(ExpectErr("NAVS", w.buf, "plane dimensions"));
    }
  }

  // ---- VOLS ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("VOLS", BuildVols(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes.count = 5"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].name = \"box\""));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].shape.kind = 0"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].shape.center = [1024, 2048, 3072]"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].flags = 3"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].army = -1"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].tags.count = 2"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[0].tags[1] = \"zone\""));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[1].army = 2"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[1].shape.radius = 5120"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[2].shape.vertices[3] = [0, 0, 1024]"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[3].shape.yMax = 2048"));
    EXPECT_TRUE(HasLine(dump, "VOLS.volumes[4].shape.a = [0, 0, 0]"));
    // Army -2, flags bit 4, tag count 17.
    Buf b = BuildVols();
    const std::size_t army0 = 4 + 2 + 3 + 1 + 12 + 12 + 8 + 4;
    b[army0] = 0xFE;
    b[army0 + 1] = 0xFF;
    EXPECT_TRUE(ExpectErr("VOLS", b, "army"));
    b = BuildVols();
    b[army0 - 4] = 0x10;
    EXPECT_TRUE(ExpectErr("VOLS", b, "flags"));
    b = BuildVols();
    Put32(b, army0 + 2, 17);
    EXPECT_TRUE(ExpectErr("VOLS", b, "above limit"));
  }

  // ---- generic strictness and fuzz ------------------------------------------------------------------------------------------
  for (const Case& c : Cases()) {
    std::string e;
    EXPECT_EQ(RunCase(c.id, c.valid, nullptr, &e), DecodeStatus::Ok);
    Buf shorter(c.valid.begin(), c.valid.end() - 1);
    EXPECT_EQ(RunCase(c.id, shorter), DecodeStatus::Error);
    Buf longer = c.valid;
    longer.push_back(0);
    EXPECT_TRUE(ExpectErr(c.id, longer, "trailing"));
    for (std::size_t n = 0; n < c.valid.size(); ++n) {
      const Buf prefix(c.valid.begin(), c.valid.begin() + static_cast<std::ptrdiff_t>(n));
      if (RunCase(c.id, prefix) != DecodeStatus::Error) {
        ADD_FAILURE() << c.id << ": truncation to " << n << " bytes was accepted";
        break;
      }
    }
    EXPECT_EQ(RunCase(c.id, c.valid, nullptr, &e, 0), DecodeStatus::Error);
    EXPECT_EQ(RunCase(c.id, c.valid, nullptr, &e, 2), DecodeStatus::Error);
    if (std::strcmp(c.id, "WRLD") != 0) {
      Buf huge = c.valid;
      Put32(huge, 0, 0xFFFFFFFFu);
      EXPECT_EQ(RunCase(c.id, huge), DecodeStatus::Error);
      Put32(huge, 0, 0x10000000u);
      EXPECT_EQ(RunCase(c.id, huge), DecodeStatus::Error);
    }
  }
  {
    Rng rng{0x9E3779B9u};
    long okCount = 0;
    for (const Case& c : Cases()) {
      for (int i = 0; i < 2000; ++i) {
        Buf b(rng.next() % (c.valid.size() * 2 + 8));
        for (std::size_t k = 0; k < b.size(); ++k)
          b[k] = (rng.next() & 1) && k < c.valid.size() ? c.valid[k] : static_cast<std::uint8_t>(rng.next());
        okCount += RunCase(c.id, b) == DecodeStatus::Ok;
        Buf m = c.valid;
        const std::uint32_t edits = 1 + rng.next() % 3;
        for (std::uint32_t k = 0; k < edits; ++k) m[rng.next() % m.size()] = static_cast<std::uint8_t>(rng.next());
        okCount += RunCase(c.id, m) == DecodeStatus::Ok;
        const Buf cut(c.valid.begin(), c.valid.begin() + static_cast<std::ptrdiff_t>(rng.next() % c.valid.size()));
        EXPECT_TRUE(RunCase(c.id, cut) == DecodeStatus::Error);
      }
      for (std::size_t off = 0; off + 4 <= c.valid.size(); ++off) {
        for (std::uint32_t v : {0xFFFFFFFFu, 0x80000000u, 0x00010000u, 0x7FFFFFFFu}) {
          Buf m = c.valid;
          Put32(m, off, v);
          okCount += RunCase(c.id, m) == DecodeStatus::Ok;
        }
      }
    }
    std::printf("fuzz: %ld mutated payloads still decoded (informational)\n", okCount);
  }

  // ---- Full3D validator --------------------------------------------------------------------------------------------------
  {
    MapSimData m = BuildMap();
    err.clear();
    EXPECT_TRUE(ValidateSimData(m, err));
    if (!err.empty()) std::printf("  unexpected message: %s\n", err.c_str());

    { MapSimData x = BuildMap(); x.wrld.reset(); EXPECT_TRUE(Invalid(x, "missing required chunk WRLD")); }
    { MapSimData x = BuildMap(); x.wrld->cellsX = 0; EXPECT_TRUE(Invalid(x, "WRLD: cell counts")); }
    { MapSimData x = BuildMap(); x.coll[1].instance = 16; EXPECT_TRUE(Invalid(x, "COLL: instance")); }
    { MapSimData x = BuildMap(); x.coll[0].chunk.tris[0].indices[5] = 4; EXPECT_TRUE(Invalid(x, "COLL.tris[0]: index out of range")); }
    { MapSimData x = BuildMap(); x.coll[0].chunk.tris[0].indices.push_back(0); EXPECT_TRUE(Invalid(x, "multiple of 3")); }
    { MapSimData x = BuildMap(); x.coll[0].chunk.tris[0].triSurfaces.pop_back(); EXPECT_TRUE(Invalid(x, "per-triangle surface count")); }
    { MapSimData x = BuildMap(); x.coll[0].chunk.tris[0].simLayer = 3; EXPECT_TRUE(Invalid(x, "simLayer above")); }
    { MapSimData x = BuildMap(); x.coll[0].chunk.hulls[0].points.pop_back(); EXPECT_TRUE(Invalid(x, "hull needs 4..256")); }
    { MapSimData x = BuildMap(); x.coll[0].chunk.prims[0].simLayer = 9; EXPECT_TRUE(Invalid(x, "COLL.prims[0]: simLayer")); }
    { MapSimData x = BuildMap(); x.slyr.reset(); EXPECT_TRUE(Invalid(x, "simLayer above")); } // layers referenced, none defined
    { MapSimData x = BuildMap(); x.navs->links[1].toSurface = 9; EXPECT_TRUE(Invalid(x, "NAVS.links[1]")); }
    { MapSimData x = BuildMap(); x.navs->surfaces[0].id = 0; EXPECT_TRUE(Invalid(x, "implicit heightfield")); }
    { MapSimData x = BuildMap(); x.navs->surfaces[1].id = 1; EXPECT_TRUE(Invalid(x, "duplicate surface id")); }
    { MapSimData x = BuildMap(); x.navs->surfaces[0].heights.pop_back(); EXPECT_TRUE(Invalid(x, "patch sample or mask count")); }
    { MapSimData x = BuildMap(); x.navs->surfaces[0].walkable.push_back(0); EXPECT_TRUE(Invalid(x, "patch sample or mask count")); }
    { MapSimData x = BuildMap(); x.navs->surfaces[1].indices[2] = 3; EXPECT_TRUE(Invalid(x, "NAVS.surfaces[1]: index out of range")); }
    { MapSimData x = BuildMap(); x.navs->surfaces[0].simLayer = 3; EXPECT_TRUE(Invalid(x, "NAVS.surfaces[0]: simLayer")); }
    {
      MapSimData x = BuildMap();
      x.slyr->layers.resize(65);
      EXPECT_TRUE(Invalid(x, "more than 64 layers"));
    }
    // A container 3 map with sim layers is refused; the same data as container 4 passes.
    { MapSimData x = BuildMap(); x.container = 3; EXPECT_TRUE(Invalid(x, "only valid in container 4")); }
    // Without WRLD cells (instance must still be 0) the Extended base alone is fine in container 4 only with WRLD.
    { MapSimData x = BuildMap(); x.coll[1].instance = 0; EXPECT_TRUE(ValidateSimData(x, err)); }
  }

  // ---- features of a Full3D map ----------------------------------------------------------------------------------------------
  {
    MapSimData m = BuildMap();
    const std::uint64_t f = RequiredFeatureMaskFor(m);
    EXPECT_TRUE((f & kFeat_WorldCells) != 0);
    EXPECT_TRUE((f & kFeat_WorldCollision) != 0);
    EXPECT_TRUE((f & kFeat_WorldNav3d) != 0);
    EXPECT_TRUE((f & kFeat_WorldVolumesSim) != 0);
    EXPECT_TRUE((f & kFeat_WorldLargeCoords) == 0);
    EXPECT_TRUE((f & kFeat_WorldLightmaps) == 0);
    const std::vector<std::string> names = RequiredFeatureBitsFor(m);
    bool hasNav = false;
    for (const std::string& n : names) hasNav = hasNav || n == "WORLD_NAV3D";
    EXPECT_TRUE(hasNav);
    m.wrld->flags = 1;
    EXPECT_TRUE((RequiredFeatureMaskFor(m) & kFeat_WorldLargeCoords) != 0);
    m.coll.clear();
    m.navs.reset();
    m.vols.reset();
    m.wrld->cellsX = m.wrld->cellsZ = 1;
    m.wrld->flags = 0;
    EXPECT_EQ(RequiredFeatureMaskFor(m) & 0xFFFFFFFF00000000ULL, 0ULL);
    EXPECT_EQ(kFeat_WorldVolumesSim, 1ULL << 37);
    EXPECT_TRUE(FeatureName(33) == "WORLD_COLLISION");
    EXPECT_TRUE(FeatureName(34) == "WORLD_NAV3D");
  }
}
