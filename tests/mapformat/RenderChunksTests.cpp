// Extended METADATA + RENDER chunks: round trips against payloads built with ByteWriter following
// docs/mapformat/EXTENDED.md, exact dump lines, strictness (one byte missing / extra, huge counts), predictor
// round trips for the planes, and a fuzz loop over every decoder.
#include <functional>
#include <map>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/RenderChunks.h"

using namespace moho::mapformat;

namespace {

using Bytes = std::vector<std::uint8_t>;

// ByteWriter that remembers where array counts / length fields were written (to overwrite them with 0xFFFFFFFF).
struct W : ByteWriter
{
  std::vector<std::size_t> counts;
  void count(std::uint32_t n)
  {
    counts.push_back(buf.size());
    u32(n);
  }
  template <class... A>
  void fs(A... a)
  {
    (f32(static_cast<float>(a)), ...);
  }
  void v3(float x, float y, float z) { fs(x, y, z); }
  void raw(std::size_t n, std::uint8_t seed)
  {
    for (std::size_t i = 0; i < n; ++i) u8(static_cast<std::uint8_t>(seed + i * 7));
  }
};

std::string Dump(const std::string& id, const Bytes& p, std::uint32_t cx = 0, std::uint32_t cz = 0,
                 DecodeStatus* st = nullptr, std::string* errOut = nullptr, std::uint16_t ver = 1)
{
  ChunkCtx ctx;
  ctx.cellsX = cx;
  ctx.cellsZ = cz;
  TextDump d;
  std::string err;
  const DecodeStatus s = DumpChunkRender(id, ver, p.data(), p.size(), ctx, d, err);
  if (st) *st = s;
  if (errOut) *errOut = err;
  return d.out;
}

bool Has(const std::string& dump, const std::string& line) { return ("\n" + dump).find("\n" + line + "\n") != std::string::npos; }

std::string F(float f) { return TextDump::F32Text(f); }

// Strictness: valid payload decodes; one byte less and one byte more are errors; a huge count / length is an error.
void Strict(const std::string& id, const W& w, std::uint32_t cx = 0, std::uint32_t cz = 0)
{
  DecodeStatus st;
  std::string err;
  Dump(id, w.buf, cx, cz, &st, &err);
  if (st != DecodeStatus::Ok) std::printf("  [%s] valid payload rejected: %s\n", id.c_str(), err.c_str());
  EXPECT_TRUE(st == DecodeStatus::Ok);
  Bytes less(w.buf.begin(), w.buf.end() - 1);
  Dump(id, less, cx, cz, &st, &err);
  EXPECT_TRUE(st == DecodeStatus::Error);
  EXPECT_TRUE(err.rfind(id + ":", 0) == 0);
  Bytes more = w.buf;
  more.push_back(0);
  Dump(id, more, cx, cz, &st, &err);
  EXPECT_TRUE(st == DecodeStatus::Error);
  for (std::size_t off : w.counts) {
    Bytes big = w.buf;
    for (int i = 0; i < 4; ++i) big[off + i] = 0xFF;
    const std::string d = Dump(id, big, cx, cz, &st, &err);
    EXPECT_TRUE(st == DecodeStatus::Error);
    EXPECT_TRUE(d.empty()); // nothing is dumped for a failed chunk
  }
  Dump(id, w.buf, cx, cz, &st, &err, 2); // unsupported version
  EXPECT_TRUE(st == DecodeStatus::Error);
  Dump(id, w.buf, cx, cz, &st, &err, 0);
  EXPECT_TRUE(st == DecodeStatus::Error);
  Dump(id, Bytes(), cx, cz, &st, &err); // empty payload
  EXPECT_TRUE(st == DecodeStatus::Error);
}

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
};

/// RGBA weights that sum to 255 per texel (EXTENDED.md appendix A); n = 4 * texels.
Bytes RandomWeights(std::size_t n, std::uint64_t seed)
{
  Xs r{seed};
  Bytes b(n);
  for (std::size_t i = 0; i + 3 < n; i += 4) {
    const unsigned a = static_cast<unsigned>(r.next() % 256);
    const unsigned c = static_cast<unsigned>(r.next() % (256 - a));
    const unsigned d = static_cast<unsigned>(r.next() % (256 - a - c));
    b[i] = static_cast<std::uint8_t>(a);
    b[i + 1] = static_cast<std::uint8_t>(c);
    b[i + 2] = static_cast<std::uint8_t>(d);
    b[i + 3] = static_cast<std::uint8_t>(255 - a - c - d);
  }
  return b;
}

Bytes RandomPlane(std::size_t n, std::uint64_t seed)
{
  Xs r{seed};
  Bytes b(n);
  for (auto& x : b) x = static_cast<std::uint8_t>(r.next());
  return b;
}

// ---------------------------------------------------------------------------------------------- builders

W BuildMeta()
{
  W w;
  w.str("Test Map");
  w.count(2);
  w.str("de"), w.str("Testkarte"), w.str("Beschreibung");
  w.str("fr"), w.str("Carte"), w.str("Desc \"q\"");
  w.str("Marlo"), w.str("1.0.3"), w.str("CC0"), w.str("https://example.org");
  w.count(2);
  w.str("2v2"), w.str("hilly");
  w.u8(2), w.u8(2), w.u8(8);
  w.count(1);
  w.str("mod"), w.str("abc"), w.str("1.2");
  w.u64(1700000000000ULL), w.u64(1700000001234ULL);
  w.str("FAF Studio"), w.str("0.5.0");
  return w;
}

const std::uint8_t kPrevData[5] = {1, 2, 3, 4, 5};
W BuildPrev()
{
  W w;
  w.u8(1), w.u32(64), w.u32(32);
  w.count(5);
  w.bytes(kPrevData, 5);
  return w;
}

W BuildGenr()
{
  W w;
  w.str("gen"), w.str("1.2"), w.u64(0xFEDCBA9876543210ULL);
  w.count(11);
  w.bytes(reinterpret_cast<const std::uint8_t*>("{\"a\":[1,2]}"), 11);
  w.count(2);
  w.str("k1"), w.str("v1"), w.str("k2"), w.str("");
  return w;
}

W BuildSign()
{
  W w;
  w.u8(1);
  w.raw(32, 1);
  w.raw(64, 9);
  w.str("key1");
  return w;
}

W BuildAsst()
{
  W w;
  w.count(2);
  w.str("textures/a.dds"), w.u8(0), w.u64(4), w.raw(4, 3);
  w.str("data/x.json"), w.u8(5), w.u64(2), w.raw(2, 5);
  return w;
}

W BuildLayr()
{
  W w;
  w.count(2);
  w.str("trees"), w.u8(1), w.u8(0);
  w.str("debris"), w.u8(0), w.u8(0);
  return w;
}

W BuildMatl()
{
  W w;
  w.count(2);
  for (int i = 0; i < 2; ++i) {
    w.u16(static_cast<std::uint16_t>(10 + i));
    w.str(i ? "rock" : "grass");
    w.str("/env/a.dds"), w.str("/env/n.dds"), w.str(i ? "/env/orm.dds" : ""), w.str("");
    w.u16(0x13);
    w.fs(8.0f, 15.0f, 1.0f, 0.5f, 0.25f, 0.0f, 4.0f, 0.75f);
    w.u16(i ? 0xFFFF : 3);
  }
  return w;
}

W BuildSplt0(std::uint8_t p0 = 0, std::uint8_t p1 = 0, const Bytes* idx = nullptr, const Bytes* wt = nullptr)
{
  W w;
  w.u32(3), w.u32(2), w.u8(0);
  const Bytes a = idx ? *idx : RandomPlane(24, 1), b = wt ? *wt : RandomWeights(24, 2);
  Bytes ea(24), eb(24);
  PredictPlane(a.data(), ea.data(), 2, 3, 4, 1, p0);
  PredictPlane(b.data(), eb.data(), 2, 3, 4, 1, p1);
  w.u8(p0), w.bytes(ea.data(), 24);
  w.u8(p1), w.bytes(eb.data(), 24);
  return w;
}

W BuildSplt1(std::uint8_t p = 0, const std::vector<Bytes>* planes = nullptr)
{
  W w;
  w.u32(3), w.u32(2), w.u8(1);
  w.u8(2);
  w.count(2);
  w.u16(7), w.u16(9);
  for (int i = 0; i < 2; ++i) {
    const Bytes a = planes ? (*planes)[i] : RandomPlane(6, 10 + i);
    Bytes e(6);
    PredictPlane(a.data(), e.data(), 2, 3, 1, 1, p);
    w.u8(p), w.bytes(e.data(), 6);
  }
  return w;
}

W BuildNrml(std::uint8_t fmt)
{
  W w;
  w.u32(5), w.u32(3), w.u8(fmt);
  w.raw(fmt == 0 ? 30 : 32, 4);
  return w;
}

W BuildAomp(std::uint8_t fmt)
{
  W w;
  w.u32(4), w.u32(4), w.u8(1), w.u8(fmt);
  w.raw(fmt == 0 ? 16 : 8, 6);
  return w;
}

W BuildMacr(std::uint8_t fmt)
{
  W w;
  w.u32(2), w.u32(2), w.u8(fmt), w.f32(0.5f);
  w.raw(fmt == 0 ? 12 : 8, 8);
  return w;
}

// grid 4x3, log2Mult 1 => 9 x 7 i16 samples
W BuildHdet(std::uint8_t pred, const Bytes* plain = nullptr)
{
  W w;
  w.u8(1), w.f32(0.01f), w.u8(pred);
  const Bytes a = plain ? *plain : RandomPlane(9 * 7 * 2, 21);
  Bytes e(a.size());
  PredictPlane(a.data(), e.data(), 7, 9, 1, 2, pred);
  w.bytes(e.data(), e.size());
  return w;
}

W BuildHole() // grid 10x3 => 2 bytes per row
{
  W w;
  w.raw(6, 11);
  return w;
}

W BuildLite()
{
  W w;
  w.v3(0.0f, 1.0f, 0.0f), w.v3(1.0f, 0.9f, 0.8f), w.f32(1.0f), w.f32(0.5f);
  w.u8(1);
  w.v3(0.0f, 0.5f, 0.5f), w.v3(0.1f, 0.1f, 0.3f), w.f32(0.2f), w.f32(0.5f);
  w.u8(2);
  w.v3(0.4f, 0.5f, 0.6f), w.v3(0.2f, 0.2f, 0.2f), w.f32(1.5f);
  for (int i = 0; i < 27; ++i) w.f32(0.01f * i);
  w.v3(0.1f, 0.1f, 0.1f), w.f32(900.0f), w.u8(3), w.f32(0.001f), w.f32(0.8f);
  w.u8(3), w.v3(0.5f, 0.6f, 0.7f), w.fs(10.0f, 500.0f, 0.02f, 0.1f, 0.0f);
  w.u8(1), w.fs(0.5f, 0.3f, 1.0f);
  w.str("/env/grade.dds");
  return w;
}

W BuildLlgt()
{
  W w;
  w.count(2);
  for (int i = 0; i < 2; ++i) {
    w.u8(static_cast<std::uint8_t>(i));
    w.v3(1.0f * i, 2.0f, 3.0f), w.v3(0.0f, -1.0f, 0.0f), w.v3(1.0f, 0.5f, 0.25f);
    w.fs(2.0f, 30.0f, 10.0f, 25.0f);
    w.u8(0x0B);
    w.fs(0.1f, 3.0f);
    w.u16(static_cast<std::uint16_t>(i));
  }
  return w;
}

W BuildProb()
{
  W w;
  w.count(1);
  w.v3(1, 2, 3), w.v3(10, 10, 10), w.f32(0.25f), w.i16(-3), w.str("/env/cube.dds");
  w.v3(0, 0, 0), w.v3(64, 64, 64);
  w.u32(2), w.u32(1), w.u32(2);
  w.raw(2 * 1 * 2 * 27 * 2, 31);
  return w;
}

W BuildTodk()
{
  W w;
  w.f32(600.0f), w.f32(0.25f);
  w.count(3);
  for (int i = 0; i < 3; ++i) {
    w.f32(0.1f + 0.3f * i);
    w.v3(0, 1, 0), w.v3(1, 1, 1), w.f32(1.0f + i);
    w.v3(0.1f, 0.1f, 0.1f), w.v3(0.2f, 0.2f, 0.2f), w.f32(0.5f);
    w.v3(0.5f, 0.5f, 0.5f), w.f32(0.01f);
    w.v3(0.3f, 0.4f, 0.9f), w.f32(0.0f), w.f32(0.2f * i);
  }
  return w;
}

W BuildAtmo()
{
  W w;
  w.u8(1), w.str(""), w.f32(1.0f), w.f32(45.0f);
  w.fs(6360.0f, 100.0f), w.v3(5.8e-3f, 13.5e-3f, 33.1e-3f), w.fs(8.0f, 21e-3f, 0.76f, 1.2f);
  w.v3(0.65e-3f, 1.88e-3f, 0.085e-3f), w.f32(0.3f);
  w.u8(2), w.fs(0.5f, 0.8f, 2000.0f, 800.0f), w.fs(1.0f, 0.5f), w.str("/env/noise_s.dds"), w.str("/env/noise_d.dds"), w.f32(0.6f);
  w.u8(1), w.fs(0.02f, 0.7f, 0.01f, 5000.0f);
  w.count(1);
  w.str("/env/moon.dds"), w.v3(0, 0.7f, 0.7f), w.f32(5.0f), w.v3(1, 1, 1), w.f32(2.0f);
  w.f32(0.4f);
  return w;
}

W BuildWvis()
{
  W w;
  w.count(3);
  for (int m = 0; m < 3; ++m) {
    w.u16(m == 0 ? 0xFFFF : static_cast<std::uint16_t>(m));
    w.v3(0.1f, 0.5f, 0.6f), w.v3(0.0f, 0.1f, 0.3f), w.v3(0.2f, 0.1f, 0.05f);
    w.fs(10.0f, 0.8f, 0.9f);
    w.u8(static_cast<std::uint8_t>(m));
    if (m == 0) {
      w.count(2);
      w.str("/env/w1.dds"), w.fs(4.0f, 0.1f, 1.0f, 0.0f);
      w.str("/env/w2.dds"), w.fs(8.0f, -0.1f, 0.0f, 1.0f);
    } else if (m == 1) {
      w.count(3);
      for (int i = 0; i < 3; ++i) w.fs(0.5f * i, 20.0f, 0.6f, 30.0f * i, 1.0f);
    } else {
      w.fs(12.0f, 90.0f, 80.0f, 1.2f, 256.0f);
    }
    w.f32(0.5f), w.str("/env/foam.dds"), w.fs(2.0f, 0.4f), w.str("/env/caus.dds");
    w.f32(0.1f), w.u32(m == 2 ? 1u : 0xFFFFFFFFu);
    w.v3(0.0f, 0.1f, 0.2f), w.f32(0.05f);
  }
  return w;
}

W BuildWflw(std::uint8_t pred = 0, const Bytes* plain = nullptr)
{
  W w;
  w.u32(3), w.u32(2), w.f32(4.5f);
  const Bytes a = plain ? *plain : RandomPlane(12, 41);
  Bytes e(12);
  PredictPlane(a.data(), e.data(), 2, 3, 2, 1, pred);
  w.u8(pred), w.bytes(e.data(), 12);
  return w;
}

W BuildScat()
{
  W w;
  w.count(1);
  w.str("grass"), w.u64(0x1122334455667788ULL);
  w.count(2);
  w.u8(0), w.str("/props/tree1.bp"), w.fs(1.0f, 0.8f, 1.2f);
  w.u8(2), w.str("/env/grass.dds"), w.fs(3.0f, 1.0f, 1.0f);
  w.fs(2.5f, 0.0f, 35.0f, -5.0f, 120.0f);
  w.count(2);
  w.u16(1), w.u16(2);
  w.count(1);
  w.u16(4);
  w.i32(-1);
  w.f32(0.3f);
  w.u16(0x0A);
  w.fs(300.0f, 0.2f, 1.5f, 0.1f);
  w.u16(1);
  return w;
}

W BuildScdm(std::uint8_t pred = 0, const Bytes* plain = nullptr)
{
  W w;
  w.u32(4), w.u32(3);
  const Bytes a = plain ? *plain : RandomPlane(12, 51);
  Bytes e(12);
  PredictPlane(a.data(), e.data(), 3, 4, 1, 1, pred);
  w.u8(pred), w.bytes(e.data(), 12);
  return w;
}

W BuildSpln()
{
  W w;
  w.count(1);
  w.u8(0), w.str("main road"), w.u16(0x6);
  w.count(3);
  for (int i = 0; i < 3; ++i) {
    w.v3(10.0f * i, 5.0f, 3.0f), w.v3(-1, 0, 0), w.v3(1, 0, 0), w.fs(4.0f, 0.0f);
  }
  w.str("/env/road.dds"), w.str("");
  w.fs(0.25f, 6.0f);
  w.u16(3), w.u16(2);
  w.f32(2.0f);
  w.u16(0);
  return w;
}

W BuildDecl()
{
  W w;
  w.count(2);
  w.str("/env/d0.dds"), w.str("/env/d1.dds");
  w.count(2);
  for (int i = 0; i < 2; ++i) {
    w.u8(static_cast<std::uint8_t>(i));
    w.u32(static_cast<std::uint32_t>(i)), w.u32(i ? 0u : 0xFFFFFFFFu);
    w.v3(1, 2, 3), w.fs(0, 0, 0, 1), w.v3(4, 4, 4);
    w.fs(0.0f, 200.0f, 1.0f, 1.0f, 1.0f, 0.5f, 50.0f);
    w.i16(static_cast<std::int16_t>(-i)), w.u16(2), w.u8(static_cast<std::uint8_t>(i));
  }
  return w;
}

W BuildWthr()
{
  W w;
  w.u16(1);
  w.count(2);
  for (int i = 0; i < 2; ++i) w.str(i ? "rain" : "clear"), w.fs(0.5f * i, 0.0f, 1.0f, 0.2f, 3.0f, 45.0f, 0.8f, 0.5f * i);
  w.count(2);
  w.str("z1"), w.u8(1), w.count(3), w.fs(0, 0, 10, 0, 0, 10), w.u16(1), w.fs(-10.0f, 100.0f), w.str("/fx/rain.bp"), w.str(""), w.u16(0);
  w.str("z2"), w.u8(2), w.fs(5, 5, 20), w.u16(0), w.fs(0.0f, 50.0f), w.str(""), w.str("/snd/w.xsb"), w.u16(0);
  return w;
}

W BuildAudi()
{
  W w;
  w.str("bed"), w.f32(0.7f);
  w.count(1);
  w.str("z"), w.u8(0), w.fs(0, 0, 100, 100), w.str("loop1"), w.fs(0.5f, 2.0f), w.i16(-4), w.str("cave");
  w.count(2);
  w.str("combat"), w.str("c1"), w.str("idle"), w.str("c2");
  return w;
}

void WritePose(W& w, float x)
{
  w.v3(x, x + 1, x + 2), w.fs(10.0f, 60.0f, 45.0f);
}

W BuildCamr()
{
  W w;
  WritePose(w, 1);
  w.fs(10.0f, 500.0f, 20.0f, 85.0f, 0.0f, 0.0f, 512.0f, 512.0f);
  w.count(1);
  w.str("home");
  WritePose(w, 5);
  w.count(1);
  w.str("flyover"), w.f32(8.0f);
  w.count(2);
  for (int i = 0; i < 2; ++i) w.f32(0.5f * i), w.v3(1, 2, 3), w.fs(0, 0, 0, 1, 50.0f), w.u8(static_cast<std::uint8_t>(i));
  return w;
}

W BuildMini()
{
  W w;
  w.u8(1);
  w.u8(0), w.u32(8), w.u32(8), w.count(6), w.raw(6, 2);
  w.f32(10.0f);
  w.count(2);
  w.f32(0.0f), w.u8(10), w.u8(20), w.u8(30);
  w.f32(50.0f), w.u8(200), w.u8(210), w.u8(220);
  w.u8(1), w.u8(2), w.u8(3);
  w.str("classic");
  return w;
}

W BuildPost()
{
  W w;
  w.u32(1);
  w.fs(0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f);
  return w;
}

W BuildDrvd()
{
  W w;
  w.str("minmax_mips");
  w.raw(32, 77);
  w.count(8);
  w.raw(8, 1);
  return w;
}

struct Entry
{
  const char* id;
  std::function<W()> build;
  std::uint32_t cx, cz;
};

std::vector<Entry> AllEntries()
{
  return {{"META", BuildMeta, 0, 0}, {"PREV", BuildPrev, 0, 0}, {"GENR", BuildGenr, 0, 0}, {"SIGN", BuildSign, 0, 0},
          {"ASST", BuildAsst, 0, 0}, {"LAYR", BuildLayr, 0, 0}, {"MATL", BuildMatl, 0, 0},
          {"SPLT", [] { return BuildSplt0(); }, 0, 0}, {"SPLT", [] { return BuildSplt1(); }, 0, 0},
          {"NRML", [] { return BuildNrml(0); }, 0, 0}, {"NRML", [] { return BuildNrml(1); }, 0, 0},
          {"AOMP", [] { return BuildAomp(0); }, 0, 0}, {"AOMP", [] { return BuildAomp(1); }, 0, 0},
          {"HDET", [] { return BuildHdet(3); }, 4, 3}, {"HOLE", BuildHole, 10, 3},
          {"MACR", [] { return BuildMacr(0); }, 0, 0}, {"MACR", [] { return BuildMacr(1); }, 0, 0},
          {"LITE", BuildLite, 0, 0}, {"LLGT", BuildLlgt, 0, 0}, {"PROB", BuildProb, 0, 0}, {"TODK", BuildTodk, 0, 0},
          {"ATMO", BuildAtmo, 0, 0}, {"WVIS", BuildWvis, 0, 0}, {"WFLW", [] { return BuildWflw(2); }, 0, 0},
          {"SCAT", BuildScat, 0, 0}, {"SCDM", [] { return BuildScdm(1); }, 0, 0}, {"SPLN", BuildSpln, 0, 0},
          {"DECL", BuildDecl, 0, 0}, {"WTHR", BuildWthr, 0, 0}, {"AUDI", BuildAudi, 0, 0}, {"CAMR", BuildCamr, 0, 0},
          {"MINI", BuildMini, 0, 0}, {"POST", BuildPost, 0, 0}, {"DRVD", BuildDrvd, 0, 0}};
}

} // namespace

TEST(MapFormatRenderChunks, Checks)
{
  // ------------------------------------------------------------------------------------- strictness, all chunks
  for (const Entry& e : AllEntries()) Strict(e.id, e.build(), e.cx, e.cz);
  // second variants not covered above (extra formats / modes)
  {
    DecodeStatus st;
    Dump("GRID", BuildPost().buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::NotMine);
    Dump("", BuildPost().buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::NotMine);
    Dump("meta", BuildMeta().buf, 0, 0, &st); // ids are case sensitive
    EXPECT_TRUE(st == DecodeStatus::NotMine);
  }

  // ------------------------------------------------------------------------------------- META
  {
    const W w = BuildMeta();
    ChunkCtx ctx;
    MetaChunk c;
    std::string err;
    EXPECT_TRUE(DecodeMeta(w.buf.data(), w.buf.size(), ctx, c, err));
    EXPECT_EQ(c.name, std::string("Test Map"));
    EXPECT_EQ(c.loc.size(), 2u);
    EXPECT_EQ(c.loc[1].lang, std::string("fr"));
    EXPECT_EQ(c.tags.size(), 2u);
    EXPECT_EQ(c.mapType, 2);
    EXPECT_EQ(c.maxPlayers, 8);
    EXPECT_EQ(c.req[0].minVersion, std::string("1.2"));
    EXPECT_EQ(c.modifiedUtc, 1700000001234ULL);
    const std::string d = Dump("META", w.buf);
    EXPECT_TRUE(Has(d, "META.name = \"Test Map\""));
    EXPECT_TRUE(Has(d, "META.locs.count = 2"));
    EXPECT_TRUE(Has(d, "META.locs[1].description = \"Desc \\\"q\\\"\""));
    EXPECT_TRUE(Has(d, "META.tags[1] = \"hilly\""));
    EXPECT_TRUE(Has(d, "META.mapType = 2"));
    EXPECT_TRUE(Has(d, "META.reqs[0].kind = \"mod\""));
    EXPECT_TRUE(Has(d, "META.createdUtc = 1700000000000"));
    EXPECT_TRUE(Has(d, "META.toolVersion = \"0.5.0\""));
    // dump order follows the spec: name before loc before author ... toolVersion last
    EXPECT_TRUE(d.find("META.name") < d.find("META.locs.count") && d.find("META.author") < d.find("META.tags.count") &&
             d.rfind("META.toolVersion") > d.rfind("META.modifiedUtc"));
    // mapType 4 is an error, string above 4096 bytes is an error
    Bytes huge(1 << 20, 0);
    huge.resize((1 << 20) + 1);
    DecodeStatus st;
    Dump("META", huge, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    // mapType 9 rejected: rebuild with a wrong value
    W w;
    w.str("n"), w.count(0), w.str(""), w.str(""), w.str(""), w.str(""), w.count(0), w.u8(9), w.u8(1), w.u8(2), w.count(0);
    w.u64(0), w.u64(0), w.str(""), w.str("");
    DecodeStatus st;
    Dump("META", w.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    W w;
    w.str("n"), w.count(0), w.str(""), w.str(""), w.str(""), w.str(""), w.count(0), w.u8(3), w.u8(1), w.u8(2), w.count(0);
    w.u64(0), w.u64(0), w.str(""), w.str("");
    DecodeStatus st;
    Dump("META", w.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok); // minimal META
  }

  // ------------------------------------------------------------------------------------- PREV / GENR / SIGN / ASST
  {
    const std::string d = Dump("PREV", BuildPrev().buf);
    EXPECT_TRUE(Has(d, "PREV.kind = 1"));
    EXPECT_TRUE(Has(d, "PREV.width = 64"));
    EXPECT_TRUE(Has(d, "PREV.byteCount = 5"));
    EXPECT_TRUE(Has(d, "PREV.data = bytes[5] sha256:" + Sha256Hex(kPrevData, 5)));
    W w;
    w.u8(0), w.u32(4096), w.u32(8), w.count(0); // width above 2048
    DecodeStatus st;
    Dump("PREV", w.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W w2;
    w2.u8(0), w2.u32(8), w2.u32(8), w2.u32(0xFFFFFFF0u); // byteCount beyond the payload
    Dump("PREV", w2.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const std::string d = Dump("GENR", BuildGenr().buf);
    EXPECT_TRUE(Has(d, "GENR.generator = \"gen\""));
    EXPECT_TRUE(Has(d, "GENR.seed = 18364758544493064720"));
    EXPECT_TRUE(Has(d, "GENR.jsonLen = 11"));
    EXPECT_TRUE(Has(d, "GENR.json = bytes[11] sha256:" + Sha256Hex(reinterpret_cast<const std::uint8_t*>("{\"a\":[1,2]}"), 11)));
    EXPECT_TRUE(Has(d, "GENR.notes.count = 2"));
    EXPECT_TRUE(Has(d, "GENR.notes[1].value = \"\""));
    W w;
    w.str(""), w.str(""), w.u64(0), w.u32(256 * 1024 + 1);
    DecodeStatus st;
    Dump("GENR", w.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const W w = BuildSign();
    const std::string d = Dump("SIGN", w.buf);
    EXPECT_TRUE(Has(d, "SIGN.algo = 1"));
    EXPECT_TRUE(Has(d, "SIGN.publicKey = bytes[32] sha256:" + Sha256Hex(w.buf.data() + 1, 32)));
    EXPECT_TRUE(Has(d, "SIGN.signature = bytes[64] sha256:" + Sha256Hex(w.buf.data() + 33, 64)));
    EXPECT_TRUE(Has(d, "SIGN.keyName = \"key1\""));
    W bad = BuildSign();
    bad.buf[0] = 2;
    DecodeStatus st;
    Dump("SIGN", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const W w = BuildAsst();
    const std::string d = Dump("ASST", w.buf);
    EXPECT_TRUE(Has(d, "ASST.assets.count = 2"));
    EXPECT_TRUE(Has(d, "ASST.assets[0].name = \"textures/a.dds\""));
    EXPECT_TRUE(Has(d, "ASST.assets[1].kind = 5"));
    EXPECT_TRUE(Has(d, "ASST.assets[1].size = 2"));
    const char* badNames[] = {"../x.dds", "/abs.dds", "a/../b.dds", "a\\b.dds", "", "a//b", "c:x", "./x.dds"};
    for (const char* n : badNames) {
      W b;
      b.count(1), b.str(n), b.u8(0), b.u64(0);
      DecodeStatus st;
      Dump("ASST", b.buf, 0, 0, &st);
      EXPECT_TRUE(st == DecodeStatus::Error);
    }
    W b;
    b.count(1), b.str("a.dds"), b.u8(6), b.u64(0); // unknown kind
    DecodeStatus st;
    Dump("ASST", b.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W huge;
    huge.count(1), huge.str("a.dds"), huge.u8(0), huge.u64(0xFFFFFFFFFFFFFFFFULL); // size beyond the payload
    Dump("ASST", huge.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W ok;
    ok.count(1), ok.str("a/b.png"), ok.u8(1), ok.u64(0);
    Dump("ASST", ok.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok);
  }

  // ------------------------------------------------------------------------------------- LAYR / MATL
  {
    const std::string d = Dump("LAYR", BuildLayr().buf);
    EXPECT_TRUE(Has(d, "LAYR.layers.count = 2"));
    EXPECT_TRUE(Has(d, "LAYR.layers[0].name = \"trees\""));
    EXPECT_TRUE(Has(d, "LAYR.layers[0].defaultVisible = 1"));
    const std::string m = Dump("MATL", BuildMatl().buf);
    EXPECT_TRUE(Has(m, "MATL.materials.count = 2"));
    EXPECT_TRUE(Has(m, "MATL.materials[0].id = 10"));
    EXPECT_TRUE(Has(m, "MATL.materials[0].normal = \"/env/n.dds\""));
    EXPECT_TRUE(Has(m, "MATL.materials[0].flags = 19"));
    EXPECT_TRUE(Has(m, "MATL.materials[1].tileSize = " + F(8.0f)));
    EXPECT_TRUE(Has(m, "MATL.materials[1].heightBlendSharpness = " + F(4.0f)));
    EXPECT_TRUE(Has(m, "MATL.materials[1].gameplaySurface = 65535"));
    EXPECT_TRUE(Has(m, "MATL.materials[0].gameplaySurface = 3"));
  }

  // ------------------------------------------------------------------------------------- SPLT
  {
    const Bytes idx = RandomPlane(24, 1), wt = RandomWeights(24, 2);
    const std::string d = Dump("SPLT", BuildSplt0(0, 0, &idx, &wt).buf);
    EXPECT_TRUE(Has(d, "SPLT.width = 3"));
    EXPECT_TRUE(Has(d, "SPLT.mode = 0"));
    EXPECT_TRUE(Has(d, "SPLT.indices = plane[3x2] sha256:" + Sha256Hex(idx.data(), 24)));
    EXPECT_TRUE(Has(d, "SPLT.weights = plane[3x2] sha256:" + Sha256Hex(wt.data(), 24)));
    const std::string d1 = Dump("SPLT", BuildSplt1().buf);
    EXPECT_TRUE(Has(d1, "SPLT.mode = 1"));
    EXPECT_TRUE(Has(d1, "SPLT.layers = 2"));
    EXPECT_TRUE(Has(d1, "SPLT.materialIds.count = 2"));
    EXPECT_TRUE(Has(d1, "SPLT.materialIds[1] = 9"));
    EXPECT_TRUE(Has(d1, "SPLT.planes.count = 2"));
    // predictor round trips (decoded sha256 independent of the stored predictor)
    for (std::uint8_t p0 = 0; p0 < 4; ++p0)
      for (std::uint8_t p1 = 0; p1 < 4; ++p1) {
        const W w = BuildSplt0(p0, p1, &idx, &wt);
        ChunkCtx ctx;
        SpltChunk c;
        std::string err;
        EXPECT_TRUE(DecodeSplt(w.buf.data(), w.buf.size(), ctx, c, err));
        EXPECT_TRUE(c.indices == idx);
        EXPECT_TRUE(c.weights == wt);
      }
    std::vector<Bytes> planes = {RandomPlane(6, 70), RandomPlane(6, 71)};
    for (std::uint8_t p = 0; p < 4; ++p) {
      const W w = BuildSplt1(p, &planes);
      ChunkCtx ctx;
      SpltChunk c;
      std::string err;
      EXPECT_TRUE(DecodeSplt(w.buf.data(), w.buf.size(), ctx, c, err));
      EXPECT_TRUE(c.planes.size() == 2 && c.planes[0] == planes[0] && c.planes[1] == planes[1]);
    }
    // limits: width 0, width 16385, unknown mode, unknown predictor, layers 33, materialIds count != layers
    DecodeStatus st;
    W a;
    a.u32(0), a.u32(2), a.u8(0);
    Dump("SPLT", a.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W b;
    b.u32(16385), b.u32(2), b.u8(0);
    Dump("SPLT", b.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W c2;
    c2.u32(3), c2.u32(2), c2.u8(2);
    Dump("SPLT", c2.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W bp = BuildSplt0();
    bp.buf[9] = 4; // first plane's predictor byte
    Dump("SPLT", bp.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W l33;
    l33.u32(1), l33.u32(1), l33.u8(1), l33.u8(33);
    Dump("SPLT", l33.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W mism;
    mism.u32(1), mism.u32(1), mism.u8(1), mism.u8(2), mism.count(1), mism.u16(1);
    Dump("SPLT", mism.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    // 16384 x 16384 with no data must not allocate: plain error
    W huge;
    huge.u32(16384), huge.u32(16384), huge.u8(0), huge.u8(0);
    Dump("SPLT", huge.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- NRML AOMP MACR
  {
    const W n0 = BuildNrml(0);
    const std::string d = Dump("NRML", n0.buf);
    EXPECT_TRUE(Has(d, "NRML.width = 5"));
    EXPECT_TRUE(Has(d, "NRML.format = 0"));
    EXPECT_TRUE(Has(d, "NRML.data = bytes[30] sha256:" + Sha256Hex(n0.buf.data() + 9, 30)));
    EXPECT_TRUE(Has(Dump("NRML", BuildNrml(1).buf), "NRML.data = bytes[32] sha256:" + Sha256Hex(BuildNrml(1).buf.data() + 9, 32)));
    const std::string a = Dump("AOMP", BuildAomp(1).buf);
    EXPECT_TRUE(Has(a, "AOMP.kind = 1"));
    EXPECT_TRUE(Has(a, "AOMP.format = 1"));
    EXPECT_TRUE(Has(a, "AOMP.data = bytes[8] sha256:" + Sha256Hex(BuildAomp(1).buf.data() + 10, 8)));
    const std::string m = Dump("MACR", BuildMacr(0).buf);
    EXPECT_TRUE(Has(m, "MACR.strength = " + F(0.5f)));
    EXPECT_TRUE(Has(m, "MACR.data = bytes[12] sha256:" + Sha256Hex(BuildMacr(0).buf.data() + 13, 12)));
    DecodeStatus st;
    W bad;
    bad.u32(5), bad.u32(3), bad.u8(2); // unknown format
    bad.raw(30, 0);
    Dump("NRML", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W zero;
    zero.u32(0), zero.u32(3), zero.u8(0);
    Dump("NRML", zero.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W kind;
    kind.u32(4), kind.u32(4), kind.u8(2), kind.u8(0), kind.raw(16, 0);
    Dump("AOMP", kind.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- HDET HOLE
  {
    const Bytes plain = RandomPlane(9 * 7 * 2, 99);
    for (std::uint8_t p = 0; p < 4; ++p) {
      const W w = BuildHdet(p, &plain);
      ChunkCtx ctx;
      ctx.cellsX = 4;
      ctx.cellsZ = 3;
      HdetChunk c;
      std::string err;
      EXPECT_TRUE(DecodeHdet(w.buf.data(), w.buf.size(), ctx, c, err));
      EXPECT_TRUE(c.samples == plain);
      EXPECT_EQ(c.width, 9u);
      EXPECT_EQ(c.height, 7u);
      const std::string d = Dump("HDET", w.buf, 4, 3);
      EXPECT_TRUE(Has(d, "HDET.log2Mult = 1"));
      EXPECT_TRUE(Has(d, "HDET.lsb = " + F(0.01f)));
      EXPECT_TRUE(Has(d, "HDET.predictor = " + std::to_string(p)));
      EXPECT_TRUE(Has(d, "HDET.samples = plane[9x7] sha256:" + Sha256Hex(plain.data(), plain.size())));
    }
    DecodeStatus st;
    std::string err;
    Dump("HDET", BuildHdet(0).buf, 0, 0, &st, &err); // grid unknown
    EXPECT_TRUE(st == DecodeStatus::Error);
    Dump("HDET", BuildHdet(0).buf, 5, 3, &st, &err); // wrong grid
    EXPECT_TRUE(st == DecodeStatus::Error);
    W m0 = BuildHdet(0);
    m0.buf[0] = 0;
    Dump("HDET", m0.buf, 4, 3, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    m0.buf[0] = 4;
    Dump("HDET", m0.buf, 4, 3, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    // log2Mult 3: (4*8+1) x (3*8+1)
    W m3;
    m3.u8(3), m3.f32(1.0f), m3.u8(0), m3.raw(33 * 25 * 2, 0);
    Dump("HDET", m3.buf, 4, 3, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok);
    // a huge grid with a short payload is an error, not an allocation
    Dump("HDET", m3.buf, 65536, 65536, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);

    const W h = BuildHole();
    const std::string d = Dump("HOLE", h.buf, 10, 3);
    EXPECT_TRUE(Has(d, "HOLE.mask = bytes[6] sha256:" + Sha256Hex(h.buf.data(), 6)));
    Dump("HOLE", h.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    Dump("HOLE", h.buf, 9, 3, &st); // 9 columns is still 2 bytes per row
    EXPECT_TRUE(st == DecodeStatus::Ok);
    Dump("HOLE", h.buf, 8, 3, &st); // 1 byte per row: payload too long
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- LITE LLGT PROB
  {
    const W w = BuildLite();
    ChunkCtx ctx;
    LiteChunk c;
    std::string err;
    EXPECT_TRUE(DecodeLite(w.buf.data(), w.buf.size(), ctx, c, err));
    EXPECT_EQ(c.hasMoon, 1);
    EXPECT_EQ(c.ambientMode, 2);
    EXPECT_EQ(c.cascades, 3);
    EXPECT_EQ(c.lut, std::string("/env/grade.dds"));
    const std::string d = Dump("LITE", w.buf);
    EXPECT_TRUE(Has(d, "LITE.sunDir = [" + F(0.0f) + ", " + F(1.0f) + ", " + F(0.0f) + "]"));
    EXPECT_TRUE(Has(d, "LITE.sunIntensity = " + F(1.0f)));
    EXPECT_TRUE(Has(d, "LITE.hasMoon = 1"));
    EXPECT_TRUE(Has(d, "LITE.moon.intensity = " + F(0.2f)));
    EXPECT_TRUE(Has(d, "LITE.ambientMode = 2"));
    EXPECT_TRUE(d.find("LITE.sh.count = 27") != std::string::npos);
    EXPECT_TRUE(Has(d, "LITE.cascades = 3"));
    EXPECT_TRUE(Has(d, "LITE.fogMode = 3"));
    EXPECT_TRUE(Has(d, "LITE.fogHeightFalloff = " + F(0.1f)));
    EXPECT_TRUE(Has(d, "LITE.toneMap = 1"));
    EXPECT_TRUE(Has(d, "LITE.lut = \"/env/grade.dds\""));
    // without moon and with flat ambient the optional blocks vanish
    W n;
    n.v3(0, 1, 0), n.v3(1, 1, 1), n.f32(1), n.f32(0.5f), n.u8(0);
    n.u8(0), n.v3(1, 1, 1), n.v3(0, 0, 0), n.f32(1);
    n.v3(0, 0, 0), n.f32(100), n.u8(1), n.f32(0), n.f32(1);
    n.u8(0), n.v3(0, 0, 0), n.fs(0, 0, 0, 0, 0);
    n.u8(0), n.fs(0, 0, 0), n.str("");
    const std::string dn = Dump("LITE", n.buf);
    EXPECT_TRUE(dn.find("LITE.moon") == std::string::npos && dn.find("LITE.sh =") == std::string::npos);
    EXPECT_TRUE(Has(dn, "LITE.hasMoon = 0"));
    // enum / range errors
    DecodeStatus st;
    W bad = BuildLite();
    bad.buf[12 + 12 + 4 + 4] = 2; // hasMoon
    Dump("LITE", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const std::string d = Dump("LLGT", BuildLlgt().buf);
    EXPECT_TRUE(Has(d, "LLGT.lights.count = 2"));
    EXPECT_TRUE(Has(d, "LLGT.lights[1].type = 1"));
    EXPECT_TRUE(Has(d, "LLGT.lights[1].pos = [" + F(1.0f) + ", " + F(2.0f) + ", " + F(3.0f) + "]"));
    EXPECT_TRUE(Has(d, "LLGT.lights[0].range = " + F(30.0f)));
    EXPECT_TRUE(Has(d, "LLGT.lights[0].flags = 11"));
    EXPECT_TRUE(Has(d, "LLGT.lights[1].layer = 1"));
    W bad = BuildLlgt();
    bad.buf[4] = 2; // type of light 0
    DecodeStatus st;
    Dump("LLGT", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const W w = BuildProb();
    const std::string d = Dump("PROB", w.buf);
    EXPECT_TRUE(Has(d, "PROB.reflProbes.count = 1"));
    EXPECT_TRUE(Has(d, "PROB.reflProbes[0].priority = -3"));
    EXPECT_TRUE(Has(d, "PROB.reflProbes[0].cubemap = \"/env/cube.dds\""));
    EXPECT_TRUE(Has(d, "PROB.nx = 2"));
    EXPECT_TRUE(d.find("PROB.shData = bytes[216] sha256:") != std::string::npos);
    // nx*ny*nz = 0 is allowed (no data); too many probes / wrong data size are not
    DecodeStatus st;
    W z;
    z.count(0), z.v3(0, 0, 0), z.v3(1, 1, 1), z.u32(0), z.u32(5), z.u32(7);
    Dump("PROB", z.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok);
    W many;
    many.count(0), many.v3(0, 0, 0), many.v3(1, 1, 1), many.u32(4096), many.u32(4096), many.u32(1);
    Dump("PROB", many.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W ovf;
    ovf.count(0), ovf.v3(0, 0, 0), ovf.v3(1, 1, 1), ovf.u32(0xFFFFFFFFu), ovf.u32(0xFFFFFFFFu), ovf.u32(0xFFFFFFFFu);
    Dump("PROB", ovf.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W ovf2;
    ovf2.count(0), ovf2.v3(0, 0, 0), ovf2.v3(1, 1, 1), ovf2.u32(4194304), ovf2.u32(4194304), ovf2.u32(4194304);
    Dump("PROB", ovf2.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- TODK ATMO WVIS
  {
    const std::string d = Dump("TODK", BuildTodk().buf);
    EXPECT_TRUE(Has(d, "TODK.cycleSeconds = " + F(600.0f)));
    EXPECT_TRUE(Has(d, "TODK.startPhase = " + F(0.25f)));
    EXPECT_TRUE(Has(d, "TODK.keys.count = 3"));
    EXPECT_TRUE(Has(d, "TODK.keys[2].sunIntensity = " + F(3.0f)));
    EXPECT_TRUE(Has(d, "TODK.keys[1].starIntensity = " + F(0.2f)));
    EXPECT_TRUE(Has(d, "TODK.keys[0].skyTint = [" + F(0.3f) + ", " + F(0.4f) + ", " + F(0.9f) + "]"));
    DecodeStatus st;
    auto with = [&](float t0, float t1, float cycle, float phase) {
      W w;
      w.f32(cycle), w.f32(phase), w.count(2);
      for (float t : {t0, t1}) {
        w.f32(t);
        w.raw(92, 0);
      }
      Dump("TODK", w.buf, 0, 0, &st);
      return st;
    };
    EXPECT_TRUE(with(0.0f, 0.5f, 10.0f, 0.0f) == DecodeStatus::Ok);
    EXPECT_TRUE(with(0.5f, 0.5f, 10.0f, 0.0f) == DecodeStatus::Error); // not strictly increasing
    EXPECT_TRUE(with(0.6f, 0.5f, 10.0f, 0.0f) == DecodeStatus::Error);
    EXPECT_TRUE(with(0.0f, 1.0f, 10.0f, 0.0f) == DecodeStatus::Error); // t must be < 1
    EXPECT_TRUE(with(-0.1f, 0.5f, 10.0f, 0.0f) == DecodeStatus::Error);
    EXPECT_TRUE(with(0.0f, 0.5f, -1.0f, 0.0f) == DecodeStatus::Error);
    EXPECT_TRUE(with(0.0f, 0.5f, 10.0f, 1.5f) == DecodeStatus::Error);
    W none;
    none.f32(0), none.f32(0), none.count(0);
    Dump("TODK", none.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const W w = BuildAtmo();
    const std::string d = Dump("ATMO", w.buf);
    EXPECT_TRUE(Has(d, "ATMO.skyModel = 1"));
    EXPECT_TRUE(Has(d, "ATMO.cubemap = \"\""));
    EXPECT_TRUE(Has(d, "ATMO.planetRadiusKm = " + F(6360.0f)));
    EXPECT_TRUE(Has(d, "ATMO.groundAlbedo = " + F(0.3f)));
    EXPECT_TRUE(Has(d, "ATMO.cloudMode = 2"));
    EXPECT_TRUE(Has(d, "ATMO.wind = [" + F(1.0f) + ", " + F(0.5f) + "]"));
    EXPECT_TRUE(Has(d, "ATMO.noiseDetail = \"/env/noise_d.dds\""));
    EXPECT_TRUE(Has(d, "ATMO.volumetricFog = 1"));
    EXPECT_TRUE(Has(d, "ATMO.maxDistance = " + F(5000.0f)));
    EXPECT_TRUE(Has(d, "ATMO.celestials[0].texture = \"/env/moon.dds\""));
    EXPECT_TRUE(Has(d, "ATMO.starIntensity = " + F(0.4f)));
    // cube map sky: the procedural block is absent from the payload and the dump
    W c;
    c.u8(0), c.str("/env/sky.dds"), c.f32(1.0f), c.f32(0.0f);
    c.u8(0), c.fs(0, 0, 0, 0), c.fs(0, 0), c.str(""), c.str(""), c.f32(0);
    c.u8(0), c.fs(0, 0, 0, 0), c.count(0), c.f32(0);
    DecodeStatus st;
    const std::string dc = Dump("ATMO", c.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok);
    EXPECT_TRUE(dc.find("ATMO.procedural") == std::string::npos);
    EXPECT_TRUE(Has(dc, "ATMO.cubemap = \"/env/sky.dds\""));
    W bad = BuildAtmo();
    bad.buf[0] = 3;
    Dump("ATMO", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W many;
    many.u8(0), many.str(""), many.f32(0), many.f32(0), many.u8(0), many.fs(0, 0, 0, 0), many.fs(0, 0), many.str(""), many.str(""),
        many.f32(0), many.u8(0), many.fs(0, 0, 0, 0), many.count(17);
    many.raw(17 * 34, 0);
    many.f32(0);
    Dump("ATMO", many.buf, 0, 0, &st); // 17 celestial bodies
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const std::string d = Dump("WVIS", BuildWvis().buf);
    EXPECT_TRUE(Has(d, "WVIS.bodies.count = 3"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[0].bodyId = 65535"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[0].waveModel = 0"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[0].normalMaps.count = 2"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[0].normalMaps[1].tiling = " + F(8.0f)));
    EXPECT_TRUE(Has(d, "WVIS.bodies[0].normalMaps[1].dir = [" + F(0.0f) + ", " + F(1.0f) + "]"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[1].waves.count = 3"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[1].waves[2].amplitude = " + F(1.0f)));
    EXPECT_TRUE(Has(d, "WVIS.bodies[2].windSpeed = " + F(12.0f)));
    EXPECT_TRUE(Has(d, "WVIS.bodies[2].patchSize = " + F(256.0f)));
    EXPECT_TRUE(Has(d, "WVIS.bodies[2].flowMap = 1"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[0].flowMap = 4294967295"));
    EXPECT_TRUE(Has(d, "WVIS.bodies[1].underwaterDensity = " + F(0.05f)));
    // 5 normal maps and 17 waves exceed the limits
    for (int model = 0; model < 2; ++model) {
      W w;
      w.count(1), w.u16(0), w.v3(0, 0, 0), w.v3(0, 0, 0), w.v3(0, 0, 0), w.fs(0, 0, 0), w.u8(static_cast<std::uint8_t>(model));
      w.count(model == 0 ? 5 : 17);
      w.raw(17 * 30, 0);
      DecodeStatus st;
      Dump("WVIS", w.buf, 0, 0, &st);
      EXPECT_TRUE(st == DecodeStatus::Error);
    }
    W bad = BuildWvis();
    bad.buf[4 + 2 + 36 + 12] = 3; // waveModel of body 0
    DecodeStatus st;
    Dump("WVIS", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- WFLW SCAT SCDM
  {
    const Bytes plain = RandomPlane(12, 41);
    for (std::uint8_t p = 0; p < 4; ++p) {
      const W w = BuildWflw(p, &plain);
      ChunkCtx ctx;
      WflwChunk c;
      std::string err;
      EXPECT_TRUE(DecodeWflw(w.buf.data(), w.buf.size(), ctx, c, err));
      EXPECT_TRUE(c.plane == plain);
      const std::string d = Dump("WFLW", w.buf);
      EXPECT_TRUE(Has(d, "WFLW.width = 3"));
      EXPECT_TRUE(Has(d, "WFLW.maxSpeed = " + F(4.5f)));
      EXPECT_TRUE(Has(d, "WFLW.flow = plane[3x2] sha256:" + Sha256Hex(plain.data(), 12)));
    }
    const Bytes plain2 = RandomPlane(12, 51);
    for (std::uint8_t p = 0; p < 4; ++p) {
      const W w = BuildScdm(p, &plain2);
      ChunkCtx ctx;
      ScdmChunk c;
      std::string err;
      EXPECT_TRUE(DecodeScdm(w.buf.data(), w.buf.size(), ctx, c, err));
      EXPECT_TRUE(c.plane == plain2);
      EXPECT_TRUE(Has(Dump("SCDM", w.buf), "SCDM.density = plane[4x3] sha256:" + Sha256Hex(plain2.data(), 12)));
    }
    DecodeStatus st;
    W bp = BuildScdm(0);
    bp.buf[8] = 9; // predictor
    Dump("SCDM", bp.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W big;
    big.u32(16384), big.u32(16384), big.u8(0);
    Dump("SCDM", big.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const W w = BuildScat();
    ChunkCtx ctx;
    ScatChunk c;
    std::string err;
    EXPECT_TRUE(DecodeScat(w.buf.data(), w.buf.size(), ctx, c, err));
    EXPECT_EQ(c.layer.size(), 1u);
    EXPECT_EQ(c.layer[0].seed, 0x1122334455667788ULL);
    EXPECT_EQ(c.layer[0].variant.size(), 2u);
    EXPECT_EQ(c.layer[0].variant[1].kind, 2);
    EXPECT_EQ(c.layer[0].allowedMaterials.size(), 2u);
    EXPECT_EQ(c.layer[0].forbiddenSurfaces[0], 4);
    EXPECT_EQ(c.layer[0].densityMap, -1);
    EXPECT_EQ(c.layer[0].flags, 0x0A);
    const std::string d = Dump("SCAT", w.buf);
    EXPECT_TRUE(Has(d, "SCAT.layers.count = 1"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].name = \"grass\""));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].seed = 1234605616436508552"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].variants.count = 2"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].variants[0].ref = \"/props/tree1.bp\""));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].variants[0].scaleMax = " + F(1.2f)));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].density = " + F(2.5f)));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].allowedMaterials.count = 2"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].allowedMaterials[1] = 2"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].forbiddenSurfaces[0] = 4"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].densityMap = -1"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].flags = 10"));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].tintVariation = " + F(0.1f)));
    EXPECT_TRUE(Has(d, "SCAT.layers[0].layer = 1"));
    // zero variants / 65 variants / 65 materials / densityMap -2 are errors
    DecodeStatus st;
    W nov;
    nov.count(1), nov.str("x"), nov.u64(0), nov.count(0);
    nov.raw(200, 0);
    Dump("SCAT", nov.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W v65;
    v65.count(1), v65.str("x"), v65.u64(0), v65.count(65);
    v65.raw(65 * 15 + 200, 0);
    Dump("SCAT", v65.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W dm = BuildScat();
    // densityMap sits 4+2+... from the end: layer(2) tint..cull(16) flags(2) jitter(4) => find by size
    const std::size_t dmOff = dm.buf.size() - 2 - 16 - 2 - 4 - 4;
    dm.buf[dmOff] = 0xFE, dm.buf[dmOff + 1] = 0xFF, dm.buf[dmOff + 2] = 0xFF, dm.buf[dmOff + 3] = 0xFF;
    Dump("SCAT", dm.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- SPLN DECL
  {
    const std::string d = Dump("SPLN", BuildSpln().buf);
    EXPECT_TRUE(Has(d, "SPLN.splines.count = 1"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].name = \"main road\""));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].flags = 6"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].points.count = 3"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].points[2].pos = [" + F(20.0f) + ", " + F(5.0f) + ", " + F(3.0f) + "]"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].points[1].tangentIn = [" + F(-1.0f) + ", " + F(0.0f) + ", " + F(0.0f) + "]"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].points[0].width = " + F(4.0f)));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].decalTexture = \"/env/road.dds\""));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].uvTile = " + F(0.25f)));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].paintMaterial = 3"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].writeSurface = 2"));
    EXPECT_TRUE(Has(d, "SPLN.splines[0].blendDistance = " + F(2.0f)));
    W one;
    one.count(1), one.u8(0), one.str("x"), one.u16(0), one.count(1);
    one.raw(44 + 100, 0);
    DecodeStatus st;
    Dump("SPLN", one.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error); // one point only
    W kind = BuildSpln();
    kind.buf[4] = 7;
    Dump("SPLN", kind.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const std::string d = Dump("DECL", BuildDecl().buf);
    EXPECT_TRUE(Has(d, "DECL.textures.count = 2"));
    EXPECT_TRUE(Has(d, "DECL.textures[1] = \"/env/d1.dds\""));
    EXPECT_TRUE(Has(d, "DECL.decals.count = 2"));
    EXPECT_TRUE(Has(d, "DECL.decals[0].tex1 = 4294967295"));
    EXPECT_TRUE(Has(d, "DECL.decals[1].tex0 = 1"));
    EXPECT_TRUE(Has(d, "DECL.decals[1].type = 1"));
    EXPECT_TRUE(Has(d, "DECL.decals[0].rot = [" + F(0.0f) + ", " + F(0.0f) + ", " + F(0.0f) + ", " + F(1.0f) + "]"));
    EXPECT_TRUE(Has(d, "DECL.decals[0].tint = [" + F(1.0f) + ", " + F(1.0f) + ", " + F(1.0f) + ", " + F(0.5f) + "]"));
    EXPECT_TRUE(Has(d, "DECL.decals[1].order = -1"));
    EXPECT_TRUE(Has(d, "DECL.decals[1].layer = 2"));
    EXPECT_TRUE(Has(d, "DECL.decals[1].blend = 1"));
    DecodeStatus st;
    W badTex = BuildDecl();
    badTex.buf[4 + 2 + 11 + 2 + 11 + 4 + 1] = 5; // tex0 of decal 0
    Dump("DECL", badTex.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- WTHR AUDI CAMR
  {
    const std::string d = Dump("WTHR", BuildWthr().buf);
    EXPECT_TRUE(Has(d, "WTHR.defaultState = 1"));
    EXPECT_TRUE(Has(d, "WTHR.states.count = 2"));
    EXPECT_TRUE(Has(d, "WTHR.states[1].name = \"rain\""));
    EXPECT_TRUE(Has(d, "WTHR.states[1].rain = " + F(0.5f)));
    EXPECT_TRUE(Has(d, "WTHR.zones.count = 2"));
    EXPECT_TRUE(Has(d, "WTHR.zones[0].shape.kind = 1"));
    EXPECT_TRUE(Has(d, "WTHR.zones[0].shape.points.count = 3"));
    EXPECT_TRUE(Has(d, "WTHR.zones[0].shape.points[2] = [" + F(0.0f) + ", " + F(10.0f) + "]"));
    EXPECT_TRUE(Has(d, "WTHR.zones[1].shape.kind = 2"));
    EXPECT_TRUE(Has(d, "WTHR.zones[1].shape.cx = " + F(5.0f)) && Has(d, "WTHR.zones[1].shape.cz = " + F(5.0f)) && Has(d, "WTHR.zones[1].shape.r = " + F(20.0f)));
    EXPECT_TRUE(Has(d, "WTHR.zones[0].state = 1"));
    EXPECT_TRUE(Has(d, "WTHR.zones[1].sound = \"/snd/w.xsb\""));
    DecodeStatus st;
    W bad = BuildWthr();
    bad.buf[0] = 2; // defaultState outside the table
    Dump("WTHR", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    // polygon with two points / rectangle shape / unknown shape kind
    W poly;
    poly.u16(0), poly.count(1), poly.str("s"), poly.fs(0, 0, 0, 0, 0, 0, 0, 0), poly.count(1);
    poly.str("z"), poly.u8(1), poly.count(2), poly.fs(0, 0, 1, 1), poly.u16(0), poly.fs(0, 1), poly.str(""), poly.str(""), poly.u16(0);
    Dump("WTHR", poly.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
    W rect;
    rect.u16(0), rect.count(1), rect.str("s"), rect.fs(0, 0, 0, 0, 0, 0, 0, 0), rect.count(1);
    rect.str("z"), rect.u8(0), rect.fs(1, 2, 3, 4), rect.u16(0), rect.fs(0, 1), rect.str(""), rect.str(""), rect.u16(0);
    const std::string dr = Dump("WTHR", rect.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok);
    EXPECT_TRUE(Has(dr, "WTHR.zones[0].shape.x0 = " + F(1.0f)) && Has(dr, "WTHR.zones[0].shape.z0 = " + F(2.0f)) && Has(dr, "WTHR.zones[0].shape.x1 = " + F(3.0f)) && Has(dr, "WTHR.zones[0].shape.z1 = " + F(4.0f)));
    rect.buf[rect.buf.size() - 2 - 2 - 2 - 8 - 2 - 16 - 1] = 3;
    Dump("WTHR", rect.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const std::string d = Dump("AUDI", BuildAudi().buf);
    EXPECT_TRUE(Has(d, "AUDI.ambientBed = \"bed\""));
    EXPECT_TRUE(Has(d, "AUDI.bedVolume = " + F(0.7f)));
    EXPECT_TRUE(Has(d, "AUDI.zones.count = 1"));
    EXPECT_TRUE(Has(d, "AUDI.zones[0].shape.kind = 0"));
    EXPECT_TRUE(Has(d, "AUDI.zones[0].shape.x1 = " + F(100.0f)) && Has(d, "AUDI.zones[0].shape.z1 = " + F(100.0f)));
    EXPECT_TRUE(Has(d, "AUDI.zones[0].priority = -4"));
    EXPECT_TRUE(Has(d, "AUDI.zones[0].reverbPreset = \"cave\""));
    EXPECT_TRUE(Has(d, "AUDI.cues.count = 2"));
    EXPECT_TRUE(Has(d, "AUDI.cues[1].state = \"idle\""));
    EXPECT_TRUE(Has(d, "AUDI.cues[1].cue = \"c2\""));
  }
  {
    const std::string d = Dump("CAMR", BuildCamr().buf);
    EXPECT_TRUE(Has(d, "CAMR.defaultPose.pos = [" + F(1.0f) + ", " + F(2.0f) + ", " + F(3.0f) + "]"));
    EXPECT_TRUE(Has(d, "CAMR.defaultPose.fovDeg = " + F(45.0f)));
    EXPECT_TRUE(Has(d, "CAMR.maxZoom = " + F(500.0f)));
    EXPECT_TRUE(Has(d, "CAMR.bounds = [" + F(0.0f) + ", " + F(0.0f) + ", " + F(512.0f) + ", " + F(512.0f) + "]"));
    EXPECT_TRUE(Has(d, "CAMR.bookmarks.count = 1"));
    EXPECT_TRUE(Has(d, "CAMR.bookmarks[0].name = \"home\""));
    EXPECT_TRUE(Has(d, "CAMR.bookmarks[0].pose.pos = [" + F(5.0f) + ", " + F(6.0f) + ", " + F(7.0f) + "]"));
    EXPECT_TRUE(Has(d, "CAMR.paths.count = 1"));
    EXPECT_TRUE(Has(d, "CAMR.paths[0].duration = " + F(8.0f)));
    EXPECT_TRUE(Has(d, "CAMR.paths[0].keys.count = 2"));
    EXPECT_TRUE(Has(d, "CAMR.paths[0].keys[1].t = " + F(0.5f)));
    EXPECT_TRUE(Has(d, "CAMR.paths[0].keys[1].ease = 1"));
    DecodeStatus st;
    W bad = BuildCamr();
    bad.buf.back() = 2; // ease
    Dump("CAMR", bad.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }

  // ------------------------------------------------------------------------------------- MINI POST DRVD
  {
    const W w = BuildMini();
    const std::string d = Dump("MINI", w.buf);
    EXPECT_TRUE(Has(d, "MINI.kind = 1"));
    EXPECT_TRUE(Has(d, "MINI.image.fmt = 0"));
    EXPECT_TRUE(Has(d, "MINI.image.w = 8"));
    EXPECT_TRUE(Has(d, "MINI.image.byteCount = 6"));
    EXPECT_TRUE(Has(d, "MINI.image.data = bytes[6] sha256:" + Sha256Hex(w.buf.data() + 1 + 1 + 4 + 4 + 4, 6)));
    EXPECT_TRUE(Has(d, "MINI.contourInterval = " + F(10.0f)));
    EXPECT_TRUE(Has(d, "MINI.ramp.count = 2"));
    EXPECT_TRUE(Has(d, "MINI.ramp[1].height = " + F(50.0f)));
    EXPECT_TRUE(Has(d, "MINI.ramp[1].color = [200, 210, 220]"));
    EXPECT_TRUE(Has(d, "MINI.borderColor = [1, 2, 3]"));
    EXPECT_TRUE(Has(d, "MINI.strategicStyle = \"classic\""));
    W k0;
    k0.u8(0), k0.f32(5.0f), k0.count(0), k0.u8(9), k0.u8(9), k0.u8(9), k0.str("");
    DecodeStatus st;
    const std::string d0 = Dump("MINI", k0.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Ok);
    EXPECT_TRUE(d0.find("MINI.image") == std::string::npos);
    W k3 = k0;
    k3.buf[0] = 3;
    Dump("MINI", k3.buf, 0, 0, &st);
    EXPECT_TRUE(st == DecodeStatus::Error);
  }
  {
    const std::string d = Dump("POST", BuildPost().buf);
    EXPECT_TRUE(Has(d, "POST.flags = 1"));
    EXPECT_TRUE(Has(d, "POST.bloom = " + F(0.1f)));
    EXPECT_TRUE(Has(d, "POST.dofAperture = " + F(0.8f)));
    const W w = BuildDrvd();
    const std::string dd = Dump("DRVD", w.buf);
    EXPECT_TRUE(Has(dd, "DRVD.kind = \"minmax_mips\""));
    EXPECT_TRUE(Has(dd, "DRVD.inputHash = bytes[32] sha256:" + Sha256Hex(w.buf.data() + 2 + 11, 32)));
    EXPECT_TRUE(Has(dd, "DRVD.byteCount = 8"));
    EXPECT_TRUE(Has(dd, "DRVD.data = bytes[8] sha256:" + Sha256Hex(w.buf.data() + 2 + 11 + 32 + 4, 8)));
  }

  // ------------------------------------------------------------------------------------- fuzz
  {
    Xs rng{0xA5A5A5A55A5A5A5AULL};
    const std::vector<Entry> entries = AllEntries();
    int decoded = 0;
    for (const Entry& e : entries) {
      const W base = e.build();
      DecodeStatus st;
      // every truncation (long payloads: a stride) must be handled
      const std::size_t stride = base.buf.size() > 600 ? base.buf.size() / 300 : 1;
      for (std::size_t len = 0; len < base.buf.size(); len += stride) {
        Bytes t(base.buf.begin(), base.buf.begin() + static_cast<std::ptrdiff_t>(len));
        Dump(e.id, t, e.cx, e.cz, &st);
        EXPECT_TRUE(st == DecodeStatus::Error || st == DecodeStatus::Ok);
      }
      // random byte mutations of the valid payload (these reach deep into the decoders)
      for (int it = 0; it < 300; ++it) {
        Bytes m = base.buf;
        const int flips = 1 + static_cast<int>(rng.next() % 4);
        for (int f = 0; f < flips; ++f) m[rng.next() % m.size()] = static_cast<std::uint8_t>(rng.next());
        if (rng.next() % 5 == 0) m.resize(rng.next() % (m.size() + 1));
        Dump(e.id, m, e.cx, e.cz, &st);
        if (st == DecodeStatus::Ok) ++decoded;
      }
      // pure random buffers
      for (int it = 0; it < 2000 / 34 + 60; ++it) {
        Bytes r(rng.next() % 200);
        for (auto& b : r) b = static_cast<std::uint8_t>(rng.next());
        Dump(e.id, r, e.cx ? e.cx : 16, e.cz ? e.cz : 16, &st);
        EXPECT_TRUE(st == DecodeStatus::Error || st == DecodeStatus::Ok);
      }
    }
    // 2000 random buffers for every id (in addition to the above), grid known and unknown
    const char* ids[] = {"META", "PREV", "GENR", "SIGN", "ASST", "LAYR", "MATL", "SPLT", "NRML", "AOMP",
                         "HDET", "HOLE", "MACR", "LITE", "LLGT", "PROB", "TODK", "ATMO", "WVIS", "WFLW",
                         "SCAT", "SCDM", "SPLN", "DECL", "WTHR", "AUDI", "CAMR", "MINI", "POST", "DRVD"};
    for (const char* id : ids)
      for (int it = 0; it < 2000; ++it) {
        Bytes r(rng.next() % 300);
        for (auto& b : r) b = static_cast<std::uint8_t>(rng.next() % (it % 3 == 0 ? 256 : 4)); // biased: zeros and small values
        DecodeStatus st;
        Dump(id, r, (it & 1) ? 8 : 0, (it & 1) ? 8 : 0, &st);
        EXPECT_TRUE(st != DecodeStatus::NotMine);
      }
    EXPECT_TRUE(decoded > 0); // some mutations stay valid (sanity of the fuzz setup)
  }
}
