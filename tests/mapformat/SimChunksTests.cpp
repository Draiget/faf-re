// Extended sim chunks: GRID HGHT PLAY GPLY WBOD LEVL MRKR AREA PROP HINT, the cross-chunk validator and feature bits.
#include <cmath>
#include <cstring>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/SimChunks.h"

using namespace moho::mapformat;
using Buf = std::vector<std::uint8_t>;

namespace {

constexpr std::uint32_t kCx = 4; // test grid: 4 x 3 cells, 5 x 4 samples
constexpr std::uint32_t kCz = 3;

// ---- tiny helpers -----------------------------------------------------------------------------------------------------

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

ChunkCtx GridCtx();
DecodeStatus RunCase(const std::string& id, const Buf& b, std::string* dump, std::string* err, std::uint16_t version,
                 ChunkCtx ctx);

/// Decoding must fail and the message must contain `needle` (so a test cannot pass for an unrelated reason).
bool ExpectErr(const std::string& id, const Buf& b, const char* needle)
{
  std::string err;
  if (RunCase(id, b, nullptr, &err, 1, GridCtx()) != DecodeStatus::Error) {
    std::printf("  %s: payload was accepted, wanted an error containing '%s'\n", id.c_str(), needle);
    return false;
  }
  if (err.find(needle) == std::string::npos) {
    std::printf("  %s: error '%s' does not contain '%s'\n", id.c_str(), err.c_str(), needle);
    return false;
  }
  return true;
}

ChunkCtx GridCtx()
{
  ChunkCtx c;
  c.cellsX = kCx;
  c.cellsZ = kCz;
  return c;
}

DecodeStatus RunCase(const std::string& id, const Buf& b, std::string* dump = nullptr, std::string* err = nullptr,
                 std::uint16_t version = 1, ChunkCtx ctx = GridCtx())
{
  TextDump td;
  std::string e;
  const DecodeStatus st = DumpChunkSim(id, version, b.empty() ? nullptr : b.data(), b.size(), ctx, td, e);
  if (dump) *dump = td.out;
  if (err) *err = e;
  return st;
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

Buf Pred8(const Buf& raw, std::uint32_t cols, std::uint32_t rows, std::uint8_t pred)
{
  Buf enc(raw.size());
  PredictPlane(raw.data(), enc.data(), rows, cols, 1, 1, pred);
  return enc;
}

std::vector<std::uint16_t> TestSamples(std::uint32_t n)
{
  std::vector<std::uint16_t> v(n);
  for (std::uint32_t i = 0; i < n; ++i) v[i] = static_cast<std::uint16_t>((i * 517u + 13u) * 31u);
  return v;
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

void Fx2(ByteWriter& w, std::int32_t x, std::int32_t z)
{
  w.i32(x);
  w.i32(z);
}

// ---- payload builders (follow EXTENDED.md) --------------------------------------------------------------------------------

Buf BuildGrid(std::uint32_t cx = kCx, std::uint32_t cz = kCz, float minE = -2.5f, float maxE = 512.0f)
{
  ByteWriter w;
  w.u32(cx);
  w.u32(cz);
  w.f32(1.0f);
  w.f32(0.0f);
  w.f32(0.0f);
  w.f32(minE);
  w.f32(maxE);
  w.u8(0);
  return w.buf;
}

Buf BuildHght(std::uint8_t pred, std::int8_t step = -7, float minH = 0.0f, std::vector<std::uint16_t> s = {})
{
  if (s.empty()) s = TestSamples((kCx + 1) * (kCz + 1));
  ByteWriter w;
  w.f32(minH);
  w.i8(step);
  w.u8(pred);
  w.u16(0);
  const Buf enc = Pred16(s, kCx + 1, kCz + 1, pred);
  w.bytes(enc.data(), enc.size());
  return w.buf;
}

Buf BuildPlay(bool polygon = true)
{
  ByteWriter w;
  w.i32(1);
  w.i32(0);
  w.i32(4);
  w.i32(3);
  w.u8(1);
  if (polygon) {
    w.u32(3);
    Fx2(w, 256, 0);
    Fx2(w, 1024, 0);
    Fx2(w, 512, 768);
  } else {
    w.u32(0);
  }
  return w.buf;
}

Buf BuildGply(std::uint8_t idWidth = 1, std::uint8_t pred = 0)
{
  ByteWriter w;
  w.u8(1); // legacyTerrainIds
  w.u32(2);
  w.u16(0);
  w.str("Land");
  w.u32(0);
  w.u16(256);
  w.str("");
  w.u16(7);
  w.str("Water");
  w.u32(8);
  w.u16(128);
  w.str("Water");
  w.u8(idWidth);
  w.u8(pred);
  std::vector<std::uint16_t> ids(kCx * kCz);
  for (std::size_t i = 0; i < ids.size(); ++i) ids[i] = (i % 3 == 0) ? 7 : 0;
  if (idWidth == 1) {
    Buf raw(ids.size());
    for (std::size_t i = 0; i < ids.size(); ++i) raw[i] = static_cast<std::uint8_t>(ids[i]);
    const Buf enc = Pred8(raw, kCx, kCz, pred);
    w.bytes(enc.data(), enc.size());
  } else {
    const Buf enc = Pred16(ids, kCx, kCz, pred);
    w.bytes(enc.data(), enc.size());
  }
  w.u32(2);
  w.str("walk_land");
  w.u8(1);
  for (std::uint32_t z = 0; z < kCz; ++z) w.u8(static_cast<std::uint8_t>(0x0F ^ z)); // 1 byte per row
  w.str("no_fog");
  w.u8(8);
  w.u8(2); // predictor up
  Buf plane(kCx * kCz);
  for (std::size_t i = 0; i < plane.size(); ++i) plane[i] = static_cast<std::uint8_t>(i * 5);
  const Buf enc = Pred8(plane, kCx, kCz, 2);
  w.bytes(enc.data(), enc.size());
  return w.buf;
}

Buf BuildWbod()
{
  ByteWriter w;
  w.u32(3);
  w.u16(1);
  w.str("sea");
  w.u8(0);
  w.f32(25.0f);
  w.u8(0);
  w.u16(2);
  w.str("lake");
  w.u8(1);
  w.f32(30.5f);
  w.u8(1);
  for (std::uint32_t z = 0; z < kCz; ++z) w.u8(0x05);
  w.u16(3);
  w.str("river");
  w.u8(2);
  w.f32(31.0f);
  w.u8(2);
  w.u32(3);
  Fx2(w, 0, 0);
  Fx2(w, 1024, 0);
  Fx2(w, 512, 768);
  return w.buf;
}

Buf BuildLevl()
{
  ByteWriter w;
  w.u32(3);
  // flat
  w.u16(1);
  w.str("bridge");
  w.i32(0);
  w.i32(0);
  w.i32(3);
  w.i32(0);
  w.u8(0);
  w.f32(40.0f);
  w.f32(40.0f);
  w.u8(0);
  w.f32(2.5f);
  w.u32(3);
  w.u32(1);
  Fx2(w, 0, 0);
  Fx2(w, 256, 0);
  w.u16(0xFFFF);
  // ramp
  w.u16(2);
  w.str("ramp");
  w.i32(0);
  w.i32(1);
  w.i32(3);
  w.i32(1);
  w.u8(1);
  w.f32(10.0f);
  w.f32(20.0f);
  w.u8(0);
  w.f32(0.0f);
  w.u32(1);
  w.u32(0);
  // patch 2 x 2
  w.u16(3);
  w.str("cave");
  w.i32(1);
  w.i32(1);
  w.i32(2);
  w.i32(2);
  w.u8(2);
  w.f32(0.0f);
  w.f32(0.0f);
  w.u8(1);
  w.u8(3); // predictor Paeth
  const Buf enc = Pred16({100, 200, 300, 65535}, 2, 2, 3);
  w.bytes(enc.data(), enc.size());
  w.f32(1.0f);
  w.u32(5);
  w.u32(1);
  Fx2(w, 512, 512);
  Fx2(w, 768, 512);
  w.u16(1); // deck id 1
  return w.buf;
}

Buf BuildMrkr()
{
  ByteWriter w;
  w.u32(3);
  // 0: mass with amount, links to 1 and 2
  w.u8(2);
  w.str("Mass 1");
  w.vec3(10.5f, 20.0f, 30.0f);
  w.f32(90.0f);
  w.i16(-1);
  w.u32(0);
  w.u32(2);
  w.str("amount");
  w.u8(2);
  w.f32(100.0f);
  w.str("note");
  w.u8(0);
  w.str("hi \"there\"");
  w.u32(2);
  w.u32(1);
  w.u32(2);
  // 1: start with every vtype
  w.u8(1);
  w.str("ARMY_1");
  w.vec3(1, 2, 3);
  w.f32(0);
  w.i16(0);
  w.u32(0);
  w.u32(2);
  w.str("n");
  w.u8(1);
  w.i32(-5);
  w.str("flag");
  w.u8(3);
  w.u8(1);
  w.u32(0);
  // 2: plain
  w.u8(0);
  w.str("");
  w.vec3(0, 0, 0);
  w.f32(0);
  w.i16(3);
  w.u32(0);
  w.u32(0);
  w.u32(0);
  return w.buf;
}

void WriteShape2D(ByteWriter& w, int kind)
{
  w.u8(static_cast<std::uint8_t>(kind));
  if (kind == 0) {
    w.f32(1);
    w.f32(2);
    w.f32(3);
    w.f32(4);
  } else if (kind == 1) {
    w.u32(3);
    w.f32(0);
    w.f32(0);
    w.f32(4);
    w.f32(0);
    w.f32(2);
    w.f32(3);
  } else {
    w.f32(2);
    w.f32(1.5f);
    w.f32(0.75f);
  }
}

Buf BuildArea()
{
  ByteWriter w;
  w.u32(3);
  w.str("rect");
  WriteShape2D(w, 0);
  w.u8(0);
  w.u32(0);
  w.str("poly");
  WriteShape2D(w, 1);
  w.u8(1);
  w.f32(-1.0f);
  w.f32(5.0f);
  w.u32(2);
  w.str("a");
  w.str("b");
  w.str("circ");
  WriteShape2D(w, 2);
  w.u8(0);
  w.u32(0);
  return w.buf;
}

Buf BuildProp()
{
  ByteWriter w;
  w.u32(2);
  w.str("/env/common/props/rock01_prop.bp");
  w.str("/env/tree.bp");
  w.u32(2);
  for (int i = 0; i < 2; ++i) {
    w.u32(static_cast<std::uint32_t>(i));
    w.vec3(1.0f + static_cast<float>(i), 2, 3);
    w.f32(0);
    w.f32(0);
    w.f32(0);
    w.f32(1);
    w.vec3(1, 1, 1);
    w.u32(0);
  }
  return w.buf;
}

Buf BuildHint()
{
  ByteWriter w;
  w.u32(2);
  w.u32(10);
  w.str("main");
  w.u8(0);
  w.f32(1000.0f);
  w.f32(1);
  w.f32(2);
  w.u32(1);
  w.u32(20);
  w.u32(20);
  w.str("isle");
  w.u8(1);
  w.f32(5.0f);
  w.f32(3);
  w.f32(4);
  w.u32(1);
  w.u32(10);
  w.u32(1);
  w.f32(2);
  w.f32(2);
  w.f32(6.0f);
  w.u32(10);
  w.u32(20);
  w.u8(0x0B);
  w.u32(1);
  w.f32(1);
  w.f32(1);
  w.u8(2);
  w.f32(0.5f);
  w.u32(2);
  w.u32(0);
  w.u32(1);
  return w.buf;
}

struct Case
{
  const char* id;
  Buf valid;
  bool arrayFirst; // payload starts with an array count
};

std::vector<Case> Cases()
{
  return {{"GRID", BuildGrid(), false}, {"HGHT", BuildHght(1), false}, {"PLAY", BuildPlay(), false},
          {"GPLY", BuildGply(), false}, {"WBOD", BuildWbod(), true},   {"LEVL", BuildLevl(), true},
          {"MRKR", BuildMrkr(), true},  {"AREA", BuildArea(), true},   {"PROP", BuildProp(), true},
          {"HINT", BuildHint(), true}};
}

void Put32(Buf& b, std::size_t off, std::uint32_t v)
{
  for (int i = 0; i < 4 && off + static_cast<std::size_t>(i) < b.size(); ++i)
    b[off + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}

// ---- decoded sample map for the validator -----------------------------------------------------------------------------

MapSimData BuildMap()
{
  MapSimData m;
  ChunkCtx ctx;
  std::string err;
  GridChunk g;
  EXPECT_TRUE(DecodeGrid(BuildGrid().data(), 29, ctx, g, err));
  m.grid = g;
  HghtChunk h;
  const Buf hb = BuildHght(3);
  EXPECT_TRUE(DecodeHght(hb.data(), hb.size(), ctx, h, err));
  m.hght = h;
  PlayChunk p;
  const Buf pb = BuildPlay();
  EXPECT_TRUE(DecodePlay(pb.data(), pb.size(), ctx, p, err));
  m.play = p;
  GplyChunk gp;
  const Buf gb = BuildGply();
  EXPECT_TRUE(DecodeGply(gb.data(), gb.size(), ctx, gp, err));
  m.gply = gp;
  WbodChunk wb;
  const Buf wbb = BuildWbod();
  EXPECT_TRUE(DecodeWbod(wbb.data(), wbb.size(), ctx, wb, err));
  m.wbod = wb;
  return m;
}

MapSimData BuildFullMap()
{
  MapSimData m = BuildMap();
  ChunkCtx ctx = GridCtx();
  std::string err;
  LevlChunk l;
  Buf b = BuildLevl();
  EXPECT_TRUE(DecodeLevl(b.data(), b.size(), ctx, l, err));
  m.levl = l;
  MrkrChunk mk;
  b = BuildMrkr();
  EXPECT_TRUE(DecodeMrkr(b.data(), b.size(), ctx, mk, err));
  m.mrkr = mk;
  AreaChunk a;
  b = BuildArea();
  EXPECT_TRUE(DecodeArea(b.data(), b.size(), ctx, a, err));
  m.area = a;
  PropChunk pr;
  b = BuildProp();
  EXPECT_TRUE(DecodeProp(b.data(), b.size(), ctx, pr, err));
  m.prop = pr;
  HintChunk hi;
  b = BuildHint();
  EXPECT_TRUE(DecodeHint(b.data(), b.size(), ctx, hi, err));
  m.hint = hi;
  return m;
}

bool Invalid(const MapSimData& m, const char* needle)
{
  std::string err;
  const bool ok = ValidateSimData(m, err);
  if (ok) {
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

TEST(MapFormatSimChunks, Checks)
{
  std::string dump, err;

  // ---- GRID ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(BuildGrid().size(), 29U);
    EXPECT_EQ(RunCase("GRID", BuildGrid(), &dump, &err), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "GRID.cellsX = 4"));
    EXPECT_TRUE(HasLine(dump, "GRID.cellsZ = 3"));
    EXPECT_TRUE(HasLine(dump, "GRID.cellSize = f32:3f800000"));
    EXPECT_TRUE(HasLine(dump, "GRID.originX = f32:00000000"));
    EXPECT_TRUE(HasLine(dump, "GRID.minElevation = f32:c0200000"));
    EXPECT_TRUE(HasLine(dump, "GRID.maxElevation = f32:44000000"));
    EXPECT_TRUE(HasLine(dump, "GRID.reserved = 0"));
    // GRID fills the context.
    ChunkCtx ctx;
    TextDump td;
    const Buf g = BuildGrid(640, 480);
    EXPECT_EQ(DumpChunkSim("GRID", 1, g.data(), g.size(), ctx, td, err), DecodeStatus::Ok);
    EXPECT_EQ(ctx.cellsX, 640U);
    EXPECT_EQ(ctx.cellsZ, 480U);
    // Rejections: zero, above 65536, sample count above 2^30, non-1.0 cell size, min above max.
    ChunkCtx c2;
    EXPECT_EQ(RunCase("GRID", BuildGrid(0, 3), nullptr, &err), DecodeStatus::Error);
    EXPECT_EQ(RunCase("GRID", BuildGrid(65537, 3)), DecodeStatus::Error);
    EXPECT_EQ(RunCase("GRID", BuildGrid(40000, 40000)), DecodeStatus::Error);
    EXPECT_EQ(RunCase("GRID", BuildGrid(4, 3, 5.0f, 1.0f)), DecodeStatus::Error);
    Buf bad = BuildGrid();
    Put32(bad, 8, 0x40000000); // cellSize 2.0
    EXPECT_EQ(RunCase("GRID", bad), DecodeStatus::Error);
    bad = BuildGrid();
    Put32(bad, 12, 0x7FC00000); // NaN origin
    EXPECT_EQ(RunCase("GRID", bad), DecodeStatus::Error);
    (void)c2;
  }

  // ---- HGHT ---------------------------------------------------------------------------------------------------------
  {
    const std::vector<std::uint16_t> s = TestSamples((kCx + 1) * (kCz + 1));
    for (std::uint8_t pred = 0; pred <= 3; ++pred) {
      const Buf b = BuildHght(pred);
      ChunkCtx ctx = GridCtx();
      HghtChunk h;
      EXPECT_TRUE(DecodeHght(b.data(), b.size(), ctx, h, err));
      EXPECT_TRUE(h.samples == s); // predictor round trip
      EXPECT_EQ(h.predictor, pred);
      EXPECT_EQ(RunCase("HGHT", b, &dump), DecodeStatus::Ok);
      EXPECT_TRUE(HasLine(dump, "HGHT.samples = plane[5x4] sha256:" + Sha16(s)));
      EXPECT_TRUE(HasLine(dump, "HGHT.predictor = " + std::to_string(pred)));
    }
    EXPECT_EQ(RunCase("HGHT", BuildHght(0), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "HGHT.minHeight = f32:00000000"));
    EXPECT_TRUE(HasLine(dump, "HGHT.stepLog2 = -7"));
    EXPECT_TRUE(HasLine(dump, "HGHT.tileSize = 0"));
    // stepLog2 range, predictor, tileSize, NaN minHeight.
    EXPECT_EQ(RunCase("HGHT", BuildHght(0, -17)), DecodeStatus::Error);
    EXPECT_EQ(RunCase("HGHT", BuildHght(0, 1)), DecodeStatus::Error);
    EXPECT_EQ(RunCase("HGHT", BuildHght(0, -16)), DecodeStatus::Ok);
    Buf bad = BuildHght(0);
    bad[5] = 4; // predictor
    EXPECT_EQ(RunCase("HGHT", bad), DecodeStatus::Error);
    bad = BuildHght(0);
    bad[6] = 1; // tileSize
    EXPECT_EQ(RunCase("HGHT", bad), DecodeStatus::Error);
    bad = BuildHght(0);
    Put32(bad, 0, 0x7F800000); // infinity
    EXPECT_EQ(RunCase("HGHT", bad), DecodeStatus::Error);
    // Needs the grid; a huge grid with a tiny payload must fail by arithmetic, not by allocating.
    ChunkCtx none;
    EXPECT_EQ(RunCase("HGHT", BuildHght(0), nullptr, &err, 1, none), DecodeStatus::Error);
    ChunkCtx huge;
    huge.cellsX = 65536;
    huge.cellsZ = 65536;
    EXPECT_EQ(RunCase("HGHT", BuildHght(0), nullptr, &err, 1, huge), DecodeStatus::Error);
    huge.cellsX = 0xFFFFFFFFu;
    huge.cellsZ = 0xFFFFFFFFu;
    EXPECT_EQ(RunCase("HGHT", BuildHght(0), nullptr, &err, 1, huge), DecodeStatus::Error);
  }

  // ---- DecodeHeight ---------------------------------------------------------------------------------------------------
  {
    HghtChunk h;
    h.minHeight = 0.0f;
    h.stepLog2 = -7;
    int mismatches = 0;
    for (std::uint32_t v = 0; v < 65536; ++v) {
      const float a = DecodeHeight(h, static_cast<std::uint16_t>(v));
      const float b = static_cast<float>(v) / 128.0f;
      if (std::memcmp(&a, &b, 4) != 0) ++mismatches;
    }
    EXPECT_EQ(mismatches, 0);
    h.minHeight = 1.5f;
    h.stepLog2 = -16;
    EXPECT_TRUE(DecodeHeight(h, 65535) == 1.5f + 65535.0f / 65536.0f);
    EXPECT_TRUE(DecodeHeight(h, 0) == 1.5f);
    h.stepLog2 = 0;
    EXPECT_TRUE(DecodeHeight(h, 7) == 8.5f);
  }

  // ---- PLAY ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("PLAY", BuildPlay(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "PLAY.x0 = 1"));
    EXPECT_TRUE(HasLine(dump, "PLAY.x1 = 4"));
    EXPECT_TRUE(HasLine(dump, "PLAY.borderMode = 1"));
    EXPECT_TRUE(HasLine(dump, "PLAY.polygon.count = 3"));
    EXPECT_TRUE(HasLine(dump, "PLAY.polygon[0] = [256, 0]"));
    EXPECT_TRUE(HasLine(dump, "PLAY.polygon[2] = [512, 768]"));
    EXPECT_EQ(RunCase("PLAY", BuildPlay(false), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "PLAY.polygon.count = 0"));
    // x1 <= x0, polygon with 2 points, polygon outside the rectangle, unknown border mode.
    Buf b = BuildPlay(false);
    Put32(b, 8, 1);
    EXPECT_TRUE(ExpectErr("PLAY", b, "x1 > x0"));
    b = BuildPlay();
    Put32(b, 17, 2); // polygon count
    b.resize(21 + 16);
    EXPECT_TRUE(ExpectErr("PLAY", b, "0 or 3..1024"));
    b = BuildPlay();
    Put32(b, 21, static_cast<std::uint32_t>(-256)); // polygon[0].x below x0
    EXPECT_TRUE(ExpectErr("PLAY", b, "polygon leaves the rectangle"));
    b = BuildPlay();
    b[16] = 3;
    EXPECT_TRUE(ExpectErr("PLAY", b, "borderMode"));
  }

  // ---- GPLY ---------------------------------------------------------------------------------------------------------
  {
    for (int width = 1; width <= 2; ++width) {
      for (std::uint8_t pred = 0; pred <= 3; ++pred) {
        const Buf b = BuildGply(static_cast<std::uint8_t>(width), pred);
        ChunkCtx ctx = GridCtx();
        GplyChunk g;
        EXPECT_TRUE(DecodeGply(b.data(), b.size(), ctx, g, err));
        EXPECT_EQ(g.ids.size(), static_cast<std::size_t>(kCx * kCz));
        bool same = true;
        for (std::size_t i = 0; i < g.ids.size(); ++i) same = same && g.ids[i] == ((i % 3 == 0) ? 7 : 0);
        EXPECT_TRUE(same);
        EXPECT_EQ(g.masks.size(), 2U);
        EXPECT_EQ(g.masks[1].data[7], 35); // u8 plane survived its predictor
      }
    }
    EXPECT_EQ(RunCase("GPLY", BuildGply(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "GPLY.legacyTerrainIds = 1"));
    EXPECT_TRUE(HasLine(dump, "GPLY.surfaces.count = 2"));
    EXPECT_TRUE(HasLine(dump, "GPLY.surfaces[0].name = \"Land\""));
    EXPECT_TRUE(HasLine(dump, "GPLY.surfaces[1].id = 7"));
    EXPECT_TRUE(HasLine(dump, "GPLY.surfaces[1].flags = 8"));
    EXPECT_TRUE(HasLine(dump, "GPLY.surfaces[1].speedMul = 128"));
    EXPECT_TRUE(HasLine(dump, "GPLY.surfaces[1].effectsKey = \"Water\""));
    EXPECT_TRUE(HasLine(dump, "GPLY.idWidth = 1"));
    EXPECT_TRUE(HasLine(dump, "GPLY.masks.count = 2"));
    EXPECT_TRUE(HasLine(dump, "GPLY.masks[0].name = \"walk_land\""));
    EXPECT_TRUE(HasLine(dump, "GPLY.masks[1].kind = 8"));
    {
      Buf ids(kCx * kCz);
      for (std::size_t i = 0; i < ids.size(); ++i) ids[i] = (i % 3 == 0) ? 7 : 0;
      EXPECT_TRUE(HasLine(dump, "GPLY.ids = plane[4x3] sha256:" + Sha256Hex(ids.data(), ids.size())));
      const std::uint8_t m0[3] = {0x0F, 0x0E, 0x0D};
      EXPECT_TRUE(HasLine(dump, "GPLY.masks[0].data = bytes[3] sha256:" + Sha256Hex(m0, 3)));
    }
    // The dump is independent of the predictor and of idWidth only through the decoded values: same ids, same plane
    // line for predictors, different line for the 2 byte width.
    std::string d0, d3, w2;
    RunCase("GPLY", BuildGply(1, 0), &d0);
    RunCase("GPLY", BuildGply(1, 3), &d3);
    EXPECT_TRUE(d0 == d3); // the plane's own predictor byte is not dumped...
    const std::size_t p0 = d0.find("GPLY.ids = "), p3 = d3.find("GPLY.ids = ");
    EXPECT_TRUE(d0.substr(p0, d0.find('\n', p0) - p0) == d3.substr(p3, d3.find('\n', p3) - p3)); // ...the plane hash does not
    // Id not in the table, unknown idWidth, mask size, duplicate ids, missing grid.
    Buf b = BuildGply();
    ChunkCtx none;
    EXPECT_EQ(RunCase("GPLY", BuildGply(), nullptr, &err, 1, none), DecodeStatus::Error);
    ChunkCtx other;
    other.cellsX = 5; // plane no longer fits
    other.cellsZ = 3;
    EXPECT_EQ(RunCase("GPLY", BuildGply(), nullptr, &err, 1, other), DecodeStatus::Error);
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
    for (std::uint32_t i = 0; i < kCx * kCz; ++i) w.u8(i == 5 ? 9 : 0); // 9 is not in the table
    w.u32(0);
    EXPECT_TRUE(ExpectErr("GPLY", w.buf, "not in the table"));
    w.buf[w.buf.size() - 4 - 7] = 0; // repair the id, now valid
    EXPECT_EQ(RunCase("GPLY", w.buf), DecodeStatus::Ok);
    w.buf[1 + 4 + 2 + 2 + 4 + 4 + 2 + 2] = 3; // idWidth 3
    EXPECT_TRUE(ExpectErr("GPLY", w.buf, "idWidth"));
    (void)b;
  }

  // ---- WBOD ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("WBOD", BuildWbod(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies.count = 3"));
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[0].name = \"sea\""));
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[0].level = f32:41c80000"));
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[1].extentKind = 1"));
    const std::uint8_t mask[3] = {5, 5, 5};
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[1].mask = bytes[3] sha256:" + Sha256Hex(mask, 3)));
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[2].polygon.count = 3"));
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[2].polygon[2] = [512, 768]"));
    // Empty array not allowed; "no water" body (-1e6, global) is fine.
    ByteWriter w;
    w.u32(0);
    EXPECT_TRUE(ExpectErr("WBOD", w.buf, "empty"));
    ByteWriter nw;
    nw.u32(1);
    nw.u16(0);
    nw.str("none");
    nw.u8(0);
    nw.f32(-1e6f);
    nw.u8(0);
    EXPECT_EQ(RunCase("WBOD", nw.buf, &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "WBOD.bodies[0].level = f32:c9742400"));
    // Mask extent needs the grid; polygon with two points; duplicate ids.
    ChunkCtx none;
    EXPECT_EQ(RunCase("WBOD", BuildWbod(), nullptr, &err, 1, none), DecodeStatus::Error);
    EXPECT_EQ(RunCase("WBOD", nw.buf, nullptr, &err, 1, none), DecodeStatus::Ok);
    Buf b = BuildWbod();
    b[b.size() - 4 * 6 - 4] = 2; // polygon count 3 -> 2
    EXPECT_TRUE(ExpectErr("WBOD", b, "3..4096"));
    ByteWriter dup;
    dup.u32(2);
    for (int i = 0; i < 2; ++i) {
      dup.u16(1);
      dup.str("x");
      dup.u8(0);
      dup.f32(1);
      dup.u8(0);
    }
    EXPECT_TRUE(ExpectErr("WBOD", dup.buf, "duplicate body id"));
  }

  // ---- LEVL ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("LEVL", BuildLevl(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "LEVL.decks.count = 3"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].name = \"bridge\""));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].x1 = 3"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].h0 = f32:42200000"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].clearanceBelow = f32:40200000"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].flags = 3"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].portals[0].b = [256, 0]"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[0].portals[0].targetDeck = 65535"));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[1].mode = 1"));
    EXPECT_TRUE(!HasLine(dump, "LEVL.decks[2].patch.predictor = 3")); // not dumped: the decoded plane is what counts
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[2].patch = plane[2x2] sha256:" + Sha16({100, 200, 300, 65535})));
    EXPECT_TRUE(HasLine(dump, "LEVL.decks[2].portals[0].targetDeck = 1"));
    for (std::uint8_t pred = 0; pred <= 3; ++pred) {
      Buf b = BuildLevl();
      // Rebuild the patch with another predictor: find it (predictor byte before 8 bytes of plane).
      ByteWriter w;
      w.u32(1);
      w.u16(3);
      w.str("cave");
      w.i32(1);
      w.i32(1);
      w.i32(2);
      w.i32(2);
      w.u8(2);
      w.f32(0);
      w.f32(0);
      w.u8(0);
      w.u8(pred);
      const Buf enc = Pred16({100, 200, 300, 65535}, 2, 2, pred);
      w.bytes(enc.data(), enc.size());
      w.f32(0);
      w.u32(0);
      w.u32(0);
      LevlChunk l;
      ChunkCtx ctx = GridCtx();
      EXPECT_TRUE(DecodeLevl(w.buf.data(), w.buf.size(), ctx, l, err));
      EXPECT_TRUE(l.decks[0].patch == std::vector<std::uint16_t>({100, 200, 300, 65535}));
      (void)b;
    }
    // Duplicate ids, empty rectangle, unknown mode, portal to an unknown deck, huge patch rectangle.
    ByteWriter w;
    w.u32(1);
    w.u16(1);
    w.str("d");
    w.i32(0);
    w.i32(0);
    w.i32(0x7FFFFFFF);
    w.i32(0x7FFFFFFF);
    w.u8(2);
    w.f32(0);
    w.f32(0);
    w.u8(0); // axis
    w.u8(0); // predictor
    w.f32(0);
    w.u32(0);
    w.u32(0);
    EXPECT_TRUE(ExpectErr("LEVL", w.buf, "plane dimensions"));
    Buf b = BuildLevl();
    b[b.size() - 2] = 9; // portal target -> deck 9 does not exist
    b[b.size() - 1] = 0;
    EXPECT_TRUE(ExpectErr("LEVL", b, "unknown deck"));
  }

  // ---- MRKR ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("MRKR", BuildMrkr(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "MRKR.markers.count = 3"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].type = 2"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].name = \"Mass 1\""));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].pos = [f32:41280000, f32:41a00000, f32:41f00000]"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].props[0].key = \"amount\""));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].props[0].value = f32:42c80000"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].props[1].value = \"hi \\\"there\\\"\""));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].links.count = 2"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[0].links[1] = 2"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[1].props[0].value = -5"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[1].props[1].vtype = 3"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[1].props[1].value = 1"));
    EXPECT_TRUE(HasLine(dump, "MRKR.markers[1].army = 0"));
    // Link out of range, unknown type, army -2, bool 2, nonzero flags, > 32 props, > 64 links.
    Buf b = BuildMrkr();
    Put32(b, 4 + 1 + 2 + 6 + 12 + 4 + 2 + 4 + 4 + (2 + 6 + 1 + 4) + (2 + 4 + 1 + 2 + 10) + 4 + 4, 3); // links[1] = 3
    EXPECT_TRUE(ExpectErr("MRKR", b, "link index"));
    b = BuildMrkr();
    b[4] = 18;
    EXPECT_TRUE(ExpectErr("MRKR", b, "marker type"));
    b = BuildMrkr();
    Put32(b, 4 + 1 + 2 + 6 + 12 + 4, 0xFFFE); // army = -2 (i16 0xFFFE), flags bytes 0
    EXPECT_TRUE(ExpectErr("MRKR", b, "army"));
  }

  // ---- AREA ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("AREA", BuildArea(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "AREA.areas.count = 3"));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[0].name = \"rect\""));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[0].shape.kind = 0"));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[0].shape.x0 = f32:3f800000"));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[1].shape.points.count = 3"));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[1].shape.points[2] = [f32:40000000, f32:40400000]"));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[1].yMin = f32:bf800000"));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[1].tags[1] = \"b\""));
    EXPECT_TRUE(HasLine(dump, "AREA.areas[2].shape.r = f32:3f400000"));
    EXPECT_TRUE(!HasLine(dump, "AREA.areas[0].yMin = f32:00000000"));
    // Unknown shape kind, polygon with 2 points, circle with negative radius, flags bit1.
    Buf b = BuildArea();
    b[4 + 2 + 4] = 7; // kind of the first shape
    EXPECT_TRUE(ExpectErr("AREA", b, "shape kind"));
    b = BuildArea();
    b[4 + 2 + 4 + 17] = 2;
    EXPECT_TRUE(ExpectErr("AREA", b, "flags"));
  }

  // ---- PROP ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("PROP", BuildProp(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "PROP.blueprints.count = 2"));
    EXPECT_TRUE(HasLine(dump, "PROP.blueprints[1] = \"/env/tree.bp\""));
    EXPECT_TRUE(HasLine(dump, "PROP.props.count = 2"));
    EXPECT_TRUE(HasLine(dump, "PROP.props[1].blueprintIndex = 1"));
    EXPECT_TRUE(HasLine(dump, "PROP.props[1].pos = [f32:40000000, f32:40000000, f32:40400000]"));
    EXPECT_TRUE(HasLine(dump, "PROP.props[0].rot = [f32:00000000, f32:00000000, f32:00000000, f32:3f800000]"));
    EXPECT_TRUE(HasLine(dump, "PROP.props[0].flags = 0"));
    // Blueprint index out of range, upper case path, flags.
    Buf b = BuildProp();
    const std::size_t propsAt = 4 + (2 + std::strlen("/env/common/props/rock01_prop.bp")) + (2 + std::strlen("/env/tree.bp"));
    Put32(b, propsAt + 4 + 48 + 0, 2); // props[1].blueprintIndex
    EXPECT_TRUE(ExpectErr("PROP", b, "blueprint index"));
    b = BuildProp();
    b[4 + 2 + 1] = 'E';
    EXPECT_TRUE(ExpectErr("PROP", b, "lower case"));
    b = BuildProp();
    Put32(b, propsAt + 4 + 44, 1); // flags of props[0]
    EXPECT_TRUE(ExpectErr("PROP", b, "flags"));
  }

  // ---- HINT ---------------------------------------------------------------------------------------------------------
  {
    EXPECT_EQ(RunCase("HINT", BuildHint(), &dump), DecodeStatus::Ok);
    EXPECT_TRUE(HasLine(dump, "HINT.regions.count = 2"));
    EXPECT_TRUE(HasLine(dump, "HINT.regions[0].id = 10"));
    EXPECT_TRUE(HasLine(dump, "HINT.regions[0].name = \"main\""));
    EXPECT_TRUE(HasLine(dump, "HINT.regions[0].centroid = [f32:3f800000, f32:40000000]"));
    EXPECT_TRUE(HasLine(dump, "HINT.regions[1].neighbors[0] = 10"));
    EXPECT_TRUE(HasLine(dump, "HINT.chokes[0].regionB = 20"));
    EXPECT_TRUE(HasLine(dump, "HINT.chokes[0].layerMask = 11"));
    EXPECT_TRUE(HasLine(dump, "HINT.candidates[0].layer = 2"));
    EXPECT_TRUE(HasLine(dump, "HINT.candidates[0].markerIds[1] = 1"));
    // Neighbor referencing a missing region; layerMask bit 4.
    Buf b = BuildHint();
    Put32(b, 4 + 4 + (2 + 4) + 1 + 4 + 8 + 4, 99); // region 0 neighbor
    EXPECT_TRUE(ExpectErr("HINT", b, "neighbor"));
    b = BuildHint();
    // chokes[0].layerMask is the 12th byte from the end of the choke record, which precedes the candidate record.
    const std::size_t candBytes = 4 + 8 + 1 + 4 + 4 + 8;
    b[b.size() - candBytes - 1] = 0x10;
    EXPECT_TRUE(ExpectErr("HINT", b, "layerMask"));
  }

  // ---- generic strictness: one byte missing, one byte extra, every truncation, hostile counts ----------------------------
  for (const Case& c : Cases()) {
    std::string e;
    EXPECT_EQ(RunCase(c.id, c.valid, nullptr, &e), DecodeStatus::Ok);
    Buf shorter(c.valid.begin(), c.valid.end() - 1);
    EXPECT_EQ(RunCase(c.id, shorter), DecodeStatus::Error);
    Buf longer = c.valid;
    longer.push_back(0);
    EXPECT_EQ(RunCase(c.id, longer, nullptr, &e), DecodeStatus::Error);
    EXPECT_TRUE(e.find("trailing") != std::string::npos);
    for (std::size_t n = 0; n < c.valid.size(); ++n) {
      const Buf prefix(c.valid.begin(), c.valid.begin() + static_cast<std::ptrdiff_t>(n));
      if (RunCase(c.id, prefix) != DecodeStatus::Error) {
        ADD_FAILURE() << c.id << ": truncation to " << n << " bytes was accepted";
        break;
      }
    }
    EXPECT_EQ(RunCase(c.id, c.valid, nullptr, &e, 0), DecodeStatus::Error);
    EXPECT_EQ(RunCase(c.id, c.valid, nullptr, &e, 2), DecodeStatus::Error);
    if (c.arrayFirst) {
      Buf huge = c.valid;
      Put32(huge, 0, 0xFFFFFFFFu);
      EXPECT_EQ(RunCase(c.id, huge, nullptr, &e), DecodeStatus::Error);
      Put32(huge, 0, 0x10000000u);
      EXPECT_EQ(RunCase(c.id, huge), DecodeStatus::Error);
    }
  }
  EXPECT_EQ(RunCase("ZZZZ", Buf{1, 2, 3}), DecodeStatus::NotMine);
  EXPECT_EQ(RunCase("META", Buf{}), DecodeStatus::NotMine);
  EXPECT_EQ(RunCase("WRLD", Buf{}), DecodeStatus::Error); // mine, malformed

  // ---- fuzz: random buffers, mutated valid payloads, hostile u32 values at every offset ------------------------------------
  {
    Rng rng{0x2545F491u};
    long okCount = 0;
    for (const Case& c : Cases()) {
      for (int i = 0; i < 2000; ++i) {
        // 1: random bytes, sometimes seeded from the valid payload so decoding gets past the first fields.
        Buf b(rng.next() % (c.valid.size() * 2 + 8));
        for (std::size_t k = 0; k < b.size(); ++k)
          b[k] = (rng.next() & 1) && k < c.valid.size() ? c.valid[k] : static_cast<std::uint8_t>(rng.next());
        okCount += RunCase(c.id, b) == DecodeStatus::Ok;
        // 2: valid payload with a few random bytes replaced.
        Buf m = c.valid;
        const std::uint32_t edits = 1 + rng.next() % 3;
        for (std::uint32_t k = 0; k < edits; ++k) m[rng.next() % m.size()] = static_cast<std::uint8_t>(rng.next());
        okCount += RunCase(c.id, m) == DecodeStatus::Ok;
        // 3: valid payload cut at a random place.
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

  // ---- cross-chunk validator ----------------------------------------------------------------------------------------------
  {
    MapSimData m = BuildFullMap();
    err.clear();
    EXPECT_TRUE(ValidateSimData(m, err));
    if (!err.empty()) std::printf("  unexpected message: %s\n", err.c_str());
    EXPECT_TRUE(ValidateSimData(BuildMap(), err));

    { MapSimData x = BuildMap(); x.grid.reset(); EXPECT_TRUE(Invalid(x, "missing required chunk GRID")); }
    { MapSimData x = BuildMap(); x.hght.reset(); EXPECT_TRUE(Invalid(x, "missing required chunk HGHT")); }
    { MapSimData x = BuildMap(); x.play.reset(); EXPECT_TRUE(Invalid(x, "missing required chunk PLAY")); }
    { MapSimData x = BuildMap(); x.gply.reset(); EXPECT_TRUE(Invalid(x, "missing required chunk GPLY")); }
    { MapSimData x = BuildMap(); x.wbod.reset(); EXPECT_TRUE(Invalid(x, "missing required chunk WBOD")); }
    // HGHT.
    { MapSimData x = BuildMap(); x.hght->samples.pop_back(); EXPECT_TRUE(Invalid(x, "HGHT: sample count")); }
    { MapSimData x = BuildMap(); x.hght->width += 1; EXPECT_TRUE(Invalid(x, "HGHT: sample count")); }
    { MapSimData x = BuildMap(); x.grid->maxElevation = 1.0f; EXPECT_TRUE(Invalid(x, "minElevation..maxElevation")); }
    { MapSimData x = BuildMap(); x.grid->minElevation = 400.0f; x.grid->maxElevation = 500.0f; EXPECT_TRUE(Invalid(x, "minElevation..maxElevation")); }
    // PLAY.
    { MapSimData x = BuildMap(); x.play->x1 = kCx + 1; EXPECT_TRUE(Invalid(x, "PLAY: rectangle leaves the grid")); }
    { MapSimData x = BuildMap(); x.play->z0 = -1; EXPECT_TRUE(Invalid(x, "PLAY: rectangle leaves the grid")); }
    { MapSimData x = BuildMap(); x.play->polygon[1].x = 5 * 256; EXPECT_TRUE(Invalid(x, "PLAY: polygon leaves the rectangle")); }
    { MapSimData x = BuildMap(); x.play->polygon.pop_back(); EXPECT_TRUE(Invalid(x, "PLAY: polygon needs")); }
    // GPLY.
    { MapSimData x = BuildMap(); x.gply->ids.pop_back(); EXPECT_TRUE(Invalid(x, "GPLY: surface id plane")); }
    { MapSimData x = BuildMap(); x.gply->width = 5; EXPECT_TRUE(Invalid(x, "GPLY: surface id plane")); }
    { MapSimData x = BuildMap(); x.gply->ids[2] = 99; EXPECT_TRUE(Invalid(x, "not in the table")); }
    { MapSimData x = BuildMap(); x.gply->masks[0].data.pop_back(); EXPECT_TRUE(Invalid(x, "GPLY.masks[0]")); }
    { MapSimData x = BuildMap(); x.gply->masks[1].data.push_back(0); EXPECT_TRUE(Invalid(x, "GPLY.masks[1]")); }
    { MapSimData x = BuildMap(); x.gply->surfaces[1].id = 0; EXPECT_TRUE(Invalid(x, "duplicate surface id")); }
    // WBOD.
    { MapSimData x = BuildMap(); x.wbod->bodies[2].polygon[0].x = -1; EXPECT_TRUE(Invalid(x, "WBOD.bodies[2]: polygon leaves the grid")); }
    { MapSimData x = BuildMap(); x.wbod->bodies[2].polygon[1].z = (kCz + 1) * 256; EXPECT_TRUE(Invalid(x, "polygon leaves the grid")); }
    { MapSimData x = BuildMap(); x.wbod->bodies[1].mask.pop_back(); EXPECT_TRUE(Invalid(x, "WBOD.bodies[1]: mask")); }
    { MapSimData x = BuildMap(); x.wbod->bodies.clear(); EXPECT_TRUE(Invalid(x, "WBOD: empty")); }
    // LEVL.
    { MapSimData x = BuildFullMap(); x.levl->decks[0].x1 = kCx; EXPECT_TRUE(Invalid(x, "LEVL.decks[0]: rectangle leaves the grid")); }
    { MapSimData x = BuildFullMap(); x.levl->decks[1].z0 = -1; EXPECT_TRUE(Invalid(x, "rectangle leaves the grid")); }
    { MapSimData x = BuildFullMap(); x.levl->decks[2].patch.pop_back(); EXPECT_TRUE(Invalid(x, "patch sample count")); }
    { MapSimData x = BuildFullMap(); x.levl->decks[2].portals[0].targetDeck = 77; EXPECT_TRUE(Invalid(x, "portal targets an unknown deck")); }
    // PROP, MRKR, HINT.
    { MapSimData x = BuildFullMap(); x.prop->props[1].blueprintIndex = 2; EXPECT_TRUE(Invalid(x, "PROP.props[1]: blueprint index")); }
    { MapSimData x = BuildFullMap(); x.mrkr->markers[0].links[1] = 3; EXPECT_TRUE(Invalid(x, "MRKR.markers[0]: link index")); }
    { MapSimData x = BuildFullMap(); x.hint->regions[0].neighbors[0] = 99; EXPECT_TRUE(Invalid(x, "HINT.regions[0]")); }
    { MapSimData x = BuildFullMap(); x.hint->chokes[0].regionA = 99; EXPECT_TRUE(Invalid(x, "HINT.chokes[0]")); }
    { MapSimData x = BuildFullMap(); x.hint->regions[1].id = 10; EXPECT_TRUE(Invalid(x, "duplicate region id")); }
    { MapSimData x = BuildFullMap(); x.hint->candidates[0].markerIds[0] = 3; EXPECT_TRUE(Invalid(x, "HINT.candidates[0]")); }
    { MapSimData x = BuildFullMap(); x.mrkr.reset(); EXPECT_TRUE(Invalid(x, "HINT.candidates[0]")); }
    // Full3D chunks in a container 3 map are refused.
    { MapSimData x = BuildMap(); x.slyr = SlyrChunk(); EXPECT_TRUE(Invalid(x, "only valid in container 4")); }
    { MapSimData x = BuildMap(); x.container = 4; EXPECT_TRUE(Invalid(x, "missing required chunk WRLD")); }
  }

  // ---- feature bits ---------------------------------------------------------------------------------------------------------
  {
    MapSimData m = BuildMap();
    // 4 x 3 grid -> non-square; wbod has 3 bodies -> WATER_BODIES; play polygon; gply has speedMul 128 and walk_land.
    const std::uint64_t f = RequiredFeatureMaskFor(m);
    EXPECT_TRUE((f & kFeat_GridNonSquare) != 0);
    EXPECT_TRUE((f & kFeat_GridLarge) == 0);
    EXPECT_TRUE((f & kFeat_HeightFine) == 0);
    EXPECT_TRUE((f & kFeat_SurfaceLayers) != 0);
    EXPECT_TRUE((f & kFeat_WaterBodies) != 0);
    EXPECT_TRUE((f & kFeat_PlayablePolygon) != 0);
    EXPECT_TRUE((f & (kFeat_Levels | kFeat_MarkersBinary | kFeat_PropsBinary | kFeat_Hints)) == 0);
    const std::vector<std::string> names = RequiredFeatureBitsFor(m);
    EXPECT_EQ(names.size(), 4U);
    EXPECT_TRUE(names[0] == "GRID_NONSQUARE" && names[1] == "SURFACE_LAYERS" && names[2] == "WATER_BODIES" &&
             names[3] == "PLAYABLE_POLYGON");
    // The classic shape: square grid, one global sea, rectangle, no masks, speed 1.0.
    MapSimData c = BuildMap();
    c.grid->cellsZ = c.grid->cellsX;
    c.play->polygon.clear();
    c.wbod->bodies.resize(1);
    c.gply->masks.clear();
    c.gply->surfaces[1].speedMul = 256;
    EXPECT_EQ(RequiredFeatureMaskFor(c), 0ULL);
    c.grid->cellsX = c.grid->cellsZ = 5000;
    EXPECT_EQ(RequiredFeatureMaskFor(c), kFeat_GridLarge);
    c.hght->stepLog2 = -8;
    c.wbod->bodies[0].extentKind = 1;
    c.levl = LevlChunk();
    EXPECT_EQ(RequiredFeatureMaskFor(c), kFeat_GridLarge | kFeat_HeightFine | kFeat_WaterBodies);
    c.levl->decks.push_back(LevlDeck());
    c.mrkr = MrkrChunk();
    c.prop = PropChunk();
    c.hint = HintChunk();
    EXPECT_TRUE((RequiredFeatureMaskFor(c) & (kFeat_Levels | kFeat_MarkersBinary | kFeat_PropsBinary | kFeat_Hints)) ==
             (kFeat_Levels | kFeat_MarkersBinary | kFeat_PropsBinary | kFeat_Hints));
    EXPECT_TRUE(FeatureName(5) == "LEVELS");
    EXPECT_TRUE(FeatureName(37) == "WORLD_VOLUMES_SIM");
    EXPECT_TRUE(FeatureName(63) == "EXTENDED_FEATURES");
    EXPECT_TRUE(FeatureName(20) == "BIT_20");
    EXPECT_EQ(kFeat_WorldCells, 1ULL << 32);
  }
}
