// Full3D render chunk decoders and dumpers: CIDX MSHB MATB INST LODG OCCL LMAP PRBV ANIM VOLR.
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "moho/sim/mapformat/World3DChunks.h"

using namespace moho::mapformat;
typedef std::vector<std::uint8_t> Bytes;

namespace {

std::string F(float f) { return TextDump::F32Text(f); }
std::string V(std::initializer_list<float> v)
{
  std::string s = "[";
  bool first = true;
  for (float x : v) {
    s += (first ? "" : ", ") + F(x);
    first = false;
  }
  return s + "]";
}

bool Has(const std::string& text, const std::string& line) { return text.find("\n" + line + "\n") != std::string::npos || text.compare(0, line.size() + 1, line + "\n") == 0; }

void Vec3(ByteWriter& w, float a, float b, float c)
{
  w.f32(a);
  w.f32(b);
  w.f32(c);
}
void Quat(ByteWriter& w) // identity
{
  w.f32(0);
  w.f32(0);
  w.f32(0);
  w.f32(1);
}

struct Outcome
{
  DecodeStatus status;
  std::string text;
  std::string err;
};

Outcome Dump(const std::string& id, const Bytes& payload, std::uint16_t version = 1, int container = 4)
{
  ChunkCtx ctx;
  ctx.container = container;
  ctx.worldCells = 2; // CIDX needs the WRLD cell count; the test payload has two cells
  TextDump d;
  Outcome o;
  o.status = DumpChunkWorld3D(id, version, payload.data(), payload.size(), ctx, d, o.err);
  o.text = d.out;
  return o;
}

// What every chunk must satisfy: dumps Ok; any shorter payload and any longer payload is an Error that names the chunk;
// wrong version is an Error; container 3 does not own the chunk; arbitrary single-byte damage never crashes, and a count
// field raised to 0xFFFFFFFF is an Error.
void Robust(const char* id, const Bytes& payload, std::size_t countOffset)
{
  const Outcome ok = Dump(id, payload);
  EXPECT_TRUE(ok.status == DecodeStatus::Ok);
  if (ok.status != DecodeStatus::Ok) std::printf("  %s: %s\n", id, ok.err.c_str());
  EXPECT_TRUE(!ok.text.empty());

  for (std::size_t n = 0; n < payload.size(); ++n) {
    const Bytes cut(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(n));
    const Outcome o = Dump(id, cut);
    if (o.status != DecodeStatus::Error || o.err.compare(0, 4, id) != 0) {
      std::printf("  %s truncated to %zu: status %d\n", id, n, static_cast<int>(o.status));
      EXPECT_TRUE(false);
    }
  }
  Bytes longer = payload;
  longer.push_back(0);
  const Outcome extra = Dump(id, longer);
  EXPECT_TRUE(extra.status == DecodeStatus::Error);
  EXPECT_TRUE(extra.err.find("trailing") != std::string::npos);

  EXPECT_TRUE(Dump(id, payload, 0).status == DecodeStatus::Error);
  EXPECT_TRUE(Dump(id, payload, 2).status == DecodeStatus::Error);
  EXPECT_TRUE(Dump(id, payload, 1, 3).status == DecodeStatus::NotMine);
  EXPECT_TRUE(Dump(id, payload, 1, 2).status == DecodeStatus::NotMine);

  for (std::size_t i = 0; i < payload.size(); ++i) {
    for (unsigned mask : {0x01U, 0x80U, 0xFFU}) {
      Bytes b = payload;
      b[i] = static_cast<std::uint8_t>(b[i] ^ mask);
      (void)Dump(id, b); // either outcome is fine, surviving is the test
    }
  }
  if (countOffset + 4 <= payload.size()) {
    Bytes b = payload;
    for (int k = 0; k < 4; ++k) b[countOffset + static_cast<std::size_t>(k)] = 0xFF;
    const Outcome o = Dump(id, b);
    EXPECT_TRUE(o.status == DecodeStatus::Error);
    // A count just above the limit and one that merely does not fit the payload.
    b = payload;
    b[countOffset] = static_cast<std::uint8_t>(payload[countOffset] + 100);
    (void)Dump(id, b);
  }
}

// ---------------------------------------------------------------- payload builders
Bytes CidxPayload()
{
  ByteWriter w;
  w.u32(2);
  Vec3(w, 0, 0, 0);
  Vec3(w, 64, 32, 64);
  w.f32(300);
  w.f32(400);
  w.u8(5);
  w.u8(0x13);
  w.u16(2);
  Vec3(w, 64, 0, 0);
  Vec3(w, 128, 32, 64);
  w.f32(300);
  w.f32(300); // unload == load is fine
  w.u8(0);
  w.u8(1);
  w.u16(0);
  return w.buf;
}

Bytes NativeMesh()
{
  ByteWriter n;
  n.u32(3); // vertices
  n.u32(3); // indices
  n.u8(2);  // index width
  n.u32(3); // attributes
  n.u8(0); n.u8(0); n.u8(3); // position f32 x3 = 12
  n.u8(3); n.u8(1); n.u8(2); // uv0 f16 x2 = 4
  n.u8(5); n.u8(3); n.u8(3); // color unorm8 x3 = 3, rounded up to 4
  for (int i = 0; i < 3 * 20; ++i) n.u8(static_cast<std::uint8_t>(i));
  n.u16(0);
  n.u16(1);
  n.u16(2);
  n.u32(1); // submeshes
  n.u32(0); n.u32(3); n.u16(5);
  n.u32(1); // lods
  n.f32(0.5f); n.u32(0); n.u32(1);
  return n.buf;
}

Bytes MshbPayload(const Bytes& native)
{
  ByteWriter w;
  w.u32(2);
  w.str("tree");
  w.u8(0);
  for (float f : {-1.f, -2.f, -3.f, 1.f, 2.f, 3.f}) w.f32(f);
  w.u32(5);
  for (int i = 0; i < 5; ++i) w.u8(static_cast<std::uint8_t>(0x40 + i));
  w.str("rock");
  w.u8(1);
  for (int i = 0; i < 6; ++i) w.f32(static_cast<float>(i));
  w.u32(static_cast<std::uint32_t>(native.size()));
  w.bytes(native.data(), native.size());
  return w.buf;
}

void Path(ByteWriter& w, const char* p) { w.str(p); }

Bytes MatbPayload()
{
  ByteWriter w;
  w.u32(2);
  for (int m = 0; m < 2; ++m) {
    w.str(m ? "glass" : "wall");
    for (float f : {1.f, 0.5f, 0.25f, 1.f}) w.f32(f);       // baseColor
    Vec3(w, 0.1f, 0.2f, 0.3f);                               // emissive
    w.f32(2.f);                                              // emissiveStrength
    for (float f : {0.f, 0.75f, 1.f, 0.9f}) w.f32(f);        // metallic roughness normalScale occlusionStrength
    w.u8(m ? 2 : 0);                                         // alphaMode
    w.f32(0.5f);                                             // alphaCutoff
    w.u16(m ? 0x3 : 0x0);                                    // flags
    Path(w, m ? "" : "/env/tex/wall_albedo.dds");
    Path(w, m ? "" : "/env/tex/wall_normal.dds");
    Path(w, "");
    Path(w, m ? "" : "/env/tex/wall_emit.dds");
    w.f32(0.f); w.f32(0.f);                                  // uvOffset
    w.f32(2.f); w.f32(4.f);                                  // uvScale
    w.f32(0.25f);                                            // uvRotation
    w.f32(0.f); w.f32(0.f);                                  // clearcoat, clearcoatRoughness
    w.f32(0.f);                                              // windAmount
  }
  return w.buf;
}

Bytes InstPayload()
{
  ByteWriter w;
  Vec3(w, 10, 0, 20);
  Vec3(w, 64, 32, 64);
  w.u32(2);
  for (int i = 0; i < 2; ++i) {
    w.u16(1);                                // bundle
    w.u16(static_cast<std::uint16_t>(i + 7)); // index
    w.u16(100); w.u16(200); w.u16(65535);    // qpos
    w.u32(0xC0FFEE00U + static_cast<std::uint32_t>(i)); // qrot
    w.u16(0x3C00); w.u16(0x4000); w.u16(0x3800); // scale 1, 2, 0.5
    w.u32(0x7);                              // flags
    w.u16(1); w.u16(2); w.u16(3);            // lodBias, layer, cullDistance
    w.u16(i ? 4 : 0);                        // lightmap
    for (int k = 0; k < 4; ++k) w.u16(static_cast<std::uint16_t>(0x3C00 + k));
    w.u8(i ? 2 : 0);                         // overrideCount
    if (i) { w.u16(9); w.u16(11); }
  }
  return w.buf;
}

Bytes LodgPayload()
{
  ByteWriter w;
  w.u32(2);
  for (int i = 0; i < 2; ++i) {
    w.u16(3); w.u16(static_cast<std::uint16_t>(i));
    Vec3(w, 1, 2, 3);
    Quat(w);
    Vec3(w, 1, 1, 1);
    w.f32(500); w.f32(25);
    w.u32(i ? 0 : 3);
    if (!i) { w.u32(1); w.u32(2); w.u32(3); }
  }
  return w.buf;
}

Bytes OcclPayload()
{
  ByteWriter w;
  w.u32(2);
  w.u8(0); // box
  Vec3(w, 1, 2, 3); Vec3(w, 4, 5, 6); Quat(w);
  w.u8(1); // mesh
  w.u16(2); w.u16(3); Vec3(w, 7, 8, 9); Quat(w); Vec3(w, 1, 2, 1);
  w.u32(1);
  w.str("hall"); Vec3(w, 0, 0, 0); Vec3(w, 10, 5, 10);
  w.u32(1);
  for (int q = 0; q < 4; ++q) Vec3(w, static_cast<float>(q), static_cast<float>(q + 1), static_cast<float>(q + 2));
  w.u16(0); w.u16(0xFFFF); w.u8(1);
  return w.buf;
}

Bytes LmapPayload(int kind)
{
  ByteWriter w;
  w.u32(256); w.u32(128);
  w.u8(0); w.u8(static_cast<std::uint8_t>(kind));
  w.u32(6);
  for (int i = 0; i < 6; ++i) w.u8(static_cast<std::uint8_t>(i));
  if (kind == 1) {
    w.u32(4);
    for (int i = 0; i < 4; ++i) w.u8(static_cast<std::uint8_t>(0xA0 + i));
  }
  return w.buf;
}

Bytes PrbvPayload(std::uint32_t nx, std::uint32_t ny, std::uint32_t nz, std::size_t dataBytes)
{
  ByteWriter w;
  Vec3(w, 1, 2, 3);
  Vec3(w, 8, 8, 8);
  w.u32(nx); w.u32(ny); w.u32(nz);
  for (std::size_t i = 0; i < dataBytes; ++i) w.u8(static_cast<std::uint8_t>(i * 3));
  return w.buf;
}

Bytes AnimPayload()
{
  ByteWriter w;
  w.u32(1);
  w.str("spin");
  w.f32(4.f);
  w.u8(1);
  w.u32(2);
  for (int c = 0; c < 2; ++c) {
    w.u32(static_cast<std::uint32_t>(c)); w.u32(static_cast<std::uint32_t>(10 + c));
    w.u8(static_cast<std::uint8_t>(c));
    w.u32(2);
    for (int k = 0; k < 2; ++k) {
      w.f32(static_cast<float>(k) * 2.f);
      for (int j = 0; j < 4; ++j) w.f32(static_cast<float>(j + k));
    }
  }
  w.u32(2);
  w.str("spin"); w.f32(1.5f); w.f32(0.25f); w.u16(3); w.u8(0);
  w.str("spin"); w.f32(1.f); w.f32(0.f); w.u16(0); w.u8(1);
  return w.buf;
}

Bytes VolrPayload()
{
  ByteWriter w;
  w.u32(4);
  for (int kind = 0; kind < 4; ++kind) {
    w.u8(static_cast<std::uint8_t>(kind));
    w.u8(kind & 1);
    Vec3(w, 1, 2, 3); Vec3(w, 4, 5, 6); Quat(w);
    w.f32(2.f);
    w.i16(static_cast<std::int16_t>(-3 + kind));
    w.u16(static_cast<std::uint16_t>(kind));
    switch (kind) {
    case 0: Vec3(w, 0.5f, 0.6f, 0.7f); w.f32(0.01f); w.f32(0.1f); break;
    case 1: w.f32(1.f); w.f32(0.9f); w.f32(1.1f); Vec3(w, 1, 1, 0.5f); break;
    case 2: w.str("cave"); break;
    default: w.f32(0.5f); Vec3(w, 0.2f, 0.3f, 0.4f); break;
    }
  }
  return w.buf;
}

// ---------------------------------------------------------------- tests
void TestCidx()
{
  const Bytes p = CidxPayload();
  Robust("CIDX", p, 0);
  const Outcome o = Dump("CIDX", p);
  const std::string want = "CIDX.cells.count = 2\n"
                           "CIDX.cells[0].min = " + V({0, 0, 0}) + "\n"
                           "CIDX.cells[0].max = " + V({64, 32, 64}) + "\n"
                           "CIDX.cells[0].loadDistance = " + F(300) + "\n"
                           "CIDX.cells[0].unloadDistance = " + F(400) + "\n"
                           "CIDX.cells[0].priority = 5\n"
                           "CIDX.cells[0].flags = 19\n"
                           "CIDX.cells[0].layer = 2\n"
                           "CIDX.cells[1].min = " + V({64, 0, 0}) + "\n"
                           "CIDX.cells[1].max = " + V({128, 32, 64}) + "\n"
                           "CIDX.cells[1].loadDistance = " + F(300) + "\n"
                           "CIDX.cells[1].unloadDistance = " + F(300) + "\n"
                           "CIDX.cells[1].priority = 0\n"
                           "CIDX.cells[1].flags = 1\n"
                           "CIDX.cells[1].layer = 0\n";
  EXPECT_EQ(o.text, want);

  ChunkCtx ctx;
  Cidx c;
  std::string err;
  EXPECT_TRUE(!DecodeCidx(p.data(), p.size(), ctx, c, err)); // WRLD not decoded yet
  ctx.worldCells = 2;
  EXPECT_TRUE(DecodeCidx(p.data(), p.size(), ctx, c, err));
  EXPECT_EQ(c.cells.size(), 2U);
  EXPECT_EQ(c.cells[0].flags, 0x13);
  // unload < load violates the hysteresis rule
  Bytes bad = p;
  ByteWriter w;
  w.f32(500);
  std::memcpy(&bad[4 + 24 + 4], w.buf.data(), 4); // cell 0 unloadDistance := 500 (> load 300 is fine); now make it lower
  ByteWriter lo;
  lo.f32(100);
  std::memcpy(&bad[4 + 24 + 4], lo.buf.data(), 4);
  const Outcome ob = Dump("CIDX", bad);
  EXPECT_TRUE(ob.status == DecodeStatus::Error);
  EXPECT_TRUE(ob.err.find("unloadDistance") != std::string::npos);
  // NaN is not >= load either
  ByteWriter nan;
  nan.u32(0x7FC00000U);
  std::memcpy(&bad[4 + 24 + 4], nan.buf.data(), 4);
  EXPECT_TRUE(Dump("CIDX", bad).status == DecodeStatus::Error);
  // empty
  EXPECT_TRUE(Dump("CIDX", Bytes{0, 0, 0, 0}).status == DecodeStatus::Error); // WRLD says two cells
  // a count above the 2^22 cell limit
  ByteWriter big;
  big.u32((1U << 22) + 1);
  EXPECT_TRUE(Dump("CIDX", big.buf).status == DecodeStatus::Error);
}

void TestMshb()
{
  const Bytes native = NativeMesh();
  const Bytes p = MshbPayload(native);
  Robust("MSHB", p, 0);
  const Outcome o = Dump("MSHB", p);
  EXPECT_TRUE(Has(o.text, "MSHB.meshes.count = 2"));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[0].name = \"tree\""));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[0].format = 0"));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[0].aabb = " + V({-1, -2, -3, 1, 2, 3})));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[0].byteCount = 5"));
  const std::uint8_t glb[5] = {0x40, 0x41, 0x42, 0x43, 0x44};
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[0].data = bytes[5] sha256:" + Sha256Hex(glb, 5)));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[1].name = \"rock\""));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[1].format = 1"));
  EXPECT_TRUE(Has(o.text, "MSHB.meshes[1].data = bytes[" + std::to_string(native.size()) + "] sha256:" + Sha256Hex(native.data(), native.size())));
  EXPECT_TRUE(o.text.find(".native.") == std::string::npos); // the canonical dump hashes the whole body, native or not

  ChunkCtx ctx;
  Mshb m;
  std::string err;
  EXPECT_TRUE(DecodeMshb(p.data(), p.size(), ctx, m, err));
  // The canonical dump hashes the body; the decoded native parts are checked on the struct.
  EXPECT_EQ(m.meshes[1].native.vertexCount, 3U);
  EXPECT_EQ(m.meshes[1].native.indexWidth, 2);
  EXPECT_EQ(m.meshes[1].native.attributes.size(), 3U);
  EXPECT_EQ(m.meshes[1].native.attributes[2].semantic, 5);
  EXPECT_EQ(m.meshes[1].native.stride, 20U); // 12 + 4 + (3 rounded up to 4)
  EXPECT_EQ(m.meshes[1].native.submeshes[0].materialSlot, 5U);
  EXPECT_EQ(m.meshes[1].native.lods[0].screenSize, 0.5f);
  EXPECT_EQ(m.meshes[1].native.vertexData.size, 60U);
  EXPECT_EQ(m.meshes[1].native.indexData.size, 6U);
  EXPECT_EQ(m.meshes[0].bytes.size, 5U);

  // Corrupt the native mesh in one field at a time (patch the nested bytes, byteCount unchanged).
  const std::size_t nativeAt = p.size() - native.size();
  auto patch = [&](std::size_t off, std::uint8_t v) {
    Bytes b = p;
    b[nativeAt + off] = v;
    return Dump("MSHB", b);
  };
  EXPECT_TRUE(patch(8, 3).status == DecodeStatus::Error);  // indexWidth 3
  EXPECT_TRUE(patch(9, 9).status == DecodeStatus::Error);  // 9 attributes (count limit 8)
  EXPECT_TRUE(patch(13, 8).status == DecodeStatus::Error); // semantic 8
  EXPECT_TRUE(patch(14, 8).status == DecodeStatus::Error); // component 8
  EXPECT_TRUE(patch(15, 5).status == DecodeStatus::Error); // count 5
  EXPECT_TRUE(patch(15, 0).status == DecodeStatus::Error); // count 0
  EXPECT_TRUE(patch(0, 0xFF).status == DecodeStatus::Error); // vertex data would not fit
  {
    // vertices without attributes
    ByteWriter n;
    n.u32(3); n.u32(0); n.u8(2); n.u32(0); n.u32(0); n.u32(0);
    EXPECT_TRUE(Dump("MSHB", MshbPayload(n.buf)).status == DecodeStatus::Error);
    ByteWriter n0; // no vertices, no attributes: legal
    n0.u32(0); n0.u32(0); n0.u8(4); n0.u32(0); n0.u32(0); n0.u32(0);
    EXPECT_TRUE(Dump("MSHB", MshbPayload(n0.buf)).status == DecodeStatus::Ok);
    // submesh past the index data
    ByteWriter n1;
    n1.u32(0); n1.u32(3); n1.u8(2); n1.u32(0);
    for (int i = 0; i < 6; ++i) n1.u8(0);
    n1.u32(1); n1.u32(1); n1.u32(3); n1.u16(0);
    n1.u32(0);
    EXPECT_TRUE(Dump("MSHB", MshbPayload(n1.buf)).status == DecodeStatus::Error);
    // lod past the submesh table
    ByteWriter n2;
    n2.u32(0); n2.u32(3); n2.u8(2); n2.u32(0);
    for (int i = 0; i < 6; ++i) n2.u8(0);
    n2.u32(1); n2.u32(0); n2.u32(3); n2.u16(0);
    n2.u32(1); n2.f32(1.f); n2.u32(0); n2.u32(2);
    EXPECT_TRUE(Dump("MSHB", MshbPayload(n2.buf)).status == DecodeStatus::Error);
    // trailing bytes inside the native blob
    Bytes extra = native;
    extra.push_back(0);
    const Outcome oe = Dump("MSHB", MshbPayload(extra));
    EXPECT_TRUE(oe.status == DecodeStatus::Error);
    EXPECT_TRUE(oe.err.find("trailing") != std::string::npos);
    // unknown format
    ByteWriter w;
    w.u32(1); w.str("x"); w.u8(2);
    for (int i = 0; i < 6; ++i) w.f32(0);
    w.u32(0);
    EXPECT_TRUE(Dump("MSHB", w.buf).status == DecodeStatus::Error);
    // byteCount larger than the payload
    ByteWriter w2;
    w2.u32(1); w2.str("x"); w2.u8(0);
    for (int i = 0; i < 6; ++i) w2.f32(0);
    w2.u32(0xFFFFFFF0U);
    EXPECT_TRUE(Dump("MSHB", w2.buf).status == DecodeStatus::Error);
    // string longer than the limit
    ByteWriter w3;
    w3.u32(1);
    w3.u16(5000);
    EXPECT_TRUE(Dump("MSHB", w3.buf).status == DecodeStatus::Error);
  }
}

void TestMatb()
{
  const Bytes p = MatbPayload();
  Robust("MATB", p, 0);
  const Outcome o = Dump("MATB", p);
  EXPECT_TRUE(Has(o.text, "MATB.materials.count = 2"));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].name = \"wall\""));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].baseColor = " + V({1, 0.5f, 0.25f, 1})));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].emissive = " + V({0.1f, 0.2f, 0.3f})));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].emissiveStrength = " + F(2)));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].roughness = " + F(0.75f)));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].occlusionStrength = " + F(0.9f)));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].alphaMode = 0"));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].baseColorTex = \"/env/tex/wall_albedo.dds\""));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].ormTex = \"\""));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].uvScale = " + V({2, 4})));
  EXPECT_TRUE(Has(o.text, "MATB.materials[0].uvRotation = " + F(0.25f)));
  EXPECT_TRUE(Has(o.text, "MATB.materials[1].alphaMode = 2"));
  EXPECT_TRUE(Has(o.text, "MATB.materials[1].flags = 3"));
  // field order = spec order
  EXPECT_TRUE(o.text.find("MATB.materials[0].name") < o.text.find("MATB.materials[0].baseColor ="));
  EXPECT_TRUE(o.text.find("MATB.materials[0].emissiveTex") < o.text.find("MATB.materials[0].uvOffset"));
  EXPECT_TRUE(o.text.find("MATB.materials[0].windAmount") < o.text.find("MATB.materials[1].name"));

  // alphaMode 3 and a texture path without a leading slash
  ChunkCtx ctx;
  Matb m;
  std::string err;
  EXPECT_TRUE(DecodeMatb(p.data(), p.size(), ctx, m, err));
  EXPECT_EQ(m.materials[0].baseColorTex, std::string("/env/tex/wall_albedo.dds"));
  const std::size_t alphaAt = 4 + 2 + 4 + 2 * 0 + 16 + 12 + 4 + 16; // count + name("wall") + ...
  Bytes b = p;
  b[alphaAt] = 3;
  EXPECT_TRUE(Dump("MATB", b).status == DecodeStatus::Error);
  b = p;
  const std::string tex = "/env/tex/wall_albedo.dds";
  const std::size_t texAt = alphaAt + 1 + 4 + 2 + 2; // after alphaMode, alphaCutoff, flags, the str length
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(&b[texAt]), tex.size()), tex);
  b[texAt] = 'x';
  const Outcome ob = Dump("MATB", b);
  EXPECT_TRUE(ob.status == DecodeStatus::Error);
  EXPECT_TRUE(ob.err.find("path") != std::string::npos);
}

void TestInst()
{
  const Bytes p = InstPayload();
  Robust("INST", p, 24);
  const Outcome o = Dump("INST", p);
  EXPECT_TRUE(Has(o.text, "INST.cellOrigin = " + V({10, 0, 20})));
  EXPECT_TRUE(Has(o.text, "INST.cellExtent = " + V({64, 32, 64})));
  EXPECT_TRUE(Has(o.text, "INST.insts.count = 2"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].mesh.bundle = 1"));
  EXPECT_TRUE(Has(o.text, "INST.insts[1].mesh.index = 8"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].pos = [100, 200, 65535]"));
  EXPECT_TRUE(Has(o.text, "INST.insts[1].rot = " + std::to_string(0xC0FFEE01U)));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].scale = [15360, 16384, 14336]"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].flags = 7"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].cullDistance = 3"));
  EXPECT_TRUE(Has(o.text, "INST.insts[1].lightmap = 4"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].lightmapScaleOffset = [15360, 15361, 15362, 15363]"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].overrideCount = 0"));
  EXPECT_TRUE(Has(o.text, "INST.insts[1].overrideCount = 2"));
  EXPECT_TRUE(Has(o.text, "INST.insts[1].materialOverride[1] = 11"));
  EXPECT_TRUE(Has(o.text, "INST.insts[0].materialOverride.count = 0") && o.text.find("INST.insts[0].materialOverride[") == std::string::npos);

  // 9 overrides
  Bytes b = p;
  b[24 + 4 + 40] = 9; // overrideCount of instance 0 (41 bytes per instance without overrides: last byte)
  const Outcome ob = Dump("INST", b);
  EXPECT_TRUE(ob.status == DecodeStatus::Error);
  EXPECT_TRUE(ob.err.find("overrides") != std::string::npos);
  // the instance limit
  ByteWriter w;
  Vec3(w, 0, 0, 0); Vec3(w, 1, 1, 1);
  w.u32(1000001);
  EXPECT_TRUE(Dump("INST", w.buf).status == DecodeStatus::Error);
}

void TestLodg()
{
  const Bytes p = LodgPayload();
  Robust("LODG", p, 0);
  const Outcome o = Dump("LODG", p);
  EXPECT_TRUE(Has(o.text, "LODG.proxies.count = 2"));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[0].mesh.bundle = 3"));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[1].mesh.index = 1"));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[0].rot = " + V({0, 0, 0, 1})));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[0].showBeyond = " + F(500)));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[0].replacesInstances.count = 3"));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[0].replacesInstances[2] = 3"));
  EXPECT_TRUE(Has(o.text, "LODG.proxies[1].replacesInstances.count = 0"));
  // a nested count that does not fit
  Bytes b = p;
  const std::size_t repAt = 4 + 4 + 12 + 16 + 12 + 4 + 4;
  b[repAt] = 0xFF;
  b[repAt + 1] = 0xFF;
  b[repAt + 2] = 0xFF;
  b[repAt + 3] = 0xFF;
  EXPECT_TRUE(Dump("LODG", b).status == DecodeStatus::Error);
  b[repAt + 2] = 0; // 65535 + 0xFF..: still too big for the payload
  EXPECT_TRUE(Dump("LODG", b).status == DecodeStatus::Error);
}

void TestOccl()
{
  const Bytes p = OcclPayload();
  Robust("OCCL", p, 0);
  const Outcome o = Dump("OCCL", p);
  EXPECT_TRUE(Has(o.text, "OCCL.occluders.count = 2"));
  EXPECT_TRUE(Has(o.text, "OCCL.occluders[0].kind = 0"));
  EXPECT_TRUE(Has(o.text, "OCCL.occluders[0].center = " + V({1, 2, 3})));
  EXPECT_TRUE(Has(o.text, "OCCL.occluders[0].halfExtents = " + V({4, 5, 6})));
  EXPECT_TRUE(Has(o.text, "OCCL.occluders[1].mesh.bundle = 2"));
  EXPECT_TRUE(Has(o.text, "OCCL.occluders[1].pos = " + V({7, 8, 9})));
  EXPECT_TRUE(Has(o.text, "OCCL.occluders[1].scale = " + V({1, 2, 1})));
  EXPECT_TRUE(Has(o.text, "OCCL.rooms.count = 1"));
  EXPECT_TRUE(Has(o.text, "OCCL.rooms[0].name = \"hall\""));
  EXPECT_TRUE(Has(o.text, "OCCL.rooms[0].max = " + V({10, 5, 10})));
  EXPECT_TRUE(Has(o.text, "OCCL.portals.count = 1"));
  EXPECT_TRUE(Has(o.text, "OCCL.portals[0].quad = " + V({0, 1, 2, 1, 2, 3, 2, 3, 4, 3, 4, 5})));
  EXPECT_TRUE(Has(o.text, "OCCL.portals[0].roomB = 65535"));
  EXPECT_TRUE(Has(o.text, "OCCL.portals[0].flags = 1"));
  Bytes b = p;
  b[4] = 2; // unknown occluder kind
  EXPECT_TRUE(Dump("OCCL", b).status == DecodeStatus::Error);
  // empty chunk is three zero counts
  EXPECT_TRUE(Dump("OCCL", Bytes(12, 0)).text == "OCCL.occluders.count = 0\nOCCL.rooms.count = 0\nOCCL.portals.count = 0\n");
  ByteWriter w;
  w.u32(0); w.u32(1025);
  EXPECT_TRUE(Dump("OCCL", w.buf).status == DecodeStatus::Error);
}

void TestLmap()
{
  for (int kind = 0; kind < 2; ++kind) {
    const Bytes p = LmapPayload(kind);
    Robust("LMAP", p, 100000); // no count field: skip the count test
    const Outcome o = Dump("LMAP", p);
    EXPECT_TRUE(Has(o.text, "LMAP.width = 256"));
    EXPECT_TRUE(Has(o.text, "LMAP.height = 128"));
    EXPECT_TRUE(Has(o.text, "LMAP.format = 0"));
    EXPECT_TRUE(Has(o.text, "LMAP.kind = " + std::to_string(kind)));
    EXPECT_TRUE(Has(o.text, "LMAP.byteCount = 6"));
    const std::uint8_t d[6] = {0, 1, 2, 3, 4, 5};
    EXPECT_TRUE(Has(o.text, "LMAP.data = bytes[6] sha256:" + Sha256Hex(d, 6)));
    if (kind == 1) {
      const std::uint8_t dir[4] = {0xA0, 0xA1, 0xA2, 0xA3};
      EXPECT_TRUE(Has(o.text, "LMAP.dirByteCount = 4"));
      EXPECT_TRUE(Has(o.text, "LMAP.dirData = bytes[4] sha256:" + Sha256Hex(dir, 4)));
    } else {
      EXPECT_TRUE(o.text.find("direction") == std::string::npos);
    }
  }
  Bytes b = LmapPayload(0);
  b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 0; // width 0
  EXPECT_TRUE(Dump("LMAP", b).status == DecodeStatus::Error);
  b = LmapPayload(0);
  b[8] = 3; // format
  EXPECT_TRUE(Dump("LMAP", b).status == DecodeStatus::Error);
  b = LmapPayload(0);
  b[9] = 2; // kind
  EXPECT_TRUE(Dump("LMAP", b).status == DecodeStatus::Error);
  b = LmapPayload(0);
  b[10] = 0xFF; b[11] = 0xFF; b[12] = 0xFF; b[13] = 0xFF; // byteCount
  EXPECT_TRUE(Dump("LMAP", b).status == DecodeStatus::Error);
  b = LmapPayload(0);
  b[2] = 0x10; // width 0x100000
  EXPECT_TRUE(Dump("LMAP", b).status == DecodeStatus::Error);
}

void TestPrbv()
{
  const Bytes p = PrbvPayload(2, 1, 1, 2 * 27 * 2);
  Robust("PRBV", p, 100000);
  const Outcome o = Dump("PRBV", p);
  EXPECT_TRUE(Has(o.text, "PRBV.gridOrigin = " + V({1, 2, 3})));
  EXPECT_TRUE(Has(o.text, "PRBV.gridSpacing = " + V({8, 8, 8})));
  EXPECT_TRUE(Has(o.text, "PRBV.nx = 2"));
  Bytes data(108);
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 3);
  EXPECT_TRUE(Has(o.text, "PRBV.shData = bytes[108] sha256:" + Sha256Hex(data.data(), data.size())));
  // zero probes: no data
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(0, 5, 5, 0)).status == DecodeStatus::Ok);
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(0xFFFFFFFFU, 0xFFFFFFFFU, 0, 0)).status == DecodeStatus::Ok); // product 0 even for huge factors
  // product above 2^22, and products that overflow 32 and 64 bits
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(2048, 2048, 2, 0)).status == DecodeStatus::Error);
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0)).status == DecodeStatus::Error);
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(65536, 65536, 1, 0)).status == DecodeStatus::Error);
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(2048, 2048, 1, 0)).status == DecodeStatus::Error); // 2^22 probes but no data: payload too short
  // data size mismatch
  EXPECT_TRUE(Dump("PRBV", PrbvPayload(2, 1, 1, 107)).status == DecodeStatus::Error);
}

void TestAnim()
{
  const Bytes p = AnimPayload();
  Robust("ANIM", p, 0);
  const Outcome o = Dump("ANIM", p);
  EXPECT_TRUE(Has(o.text, "ANIM.clips.count = 1"));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].name = \"spin\""));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].duration = " + F(4)));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].loop = 1"));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].channels.count = 2"));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].channels[1].instanceIndex = 11"));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].channels[1].target = 1"));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].channels[0].keys.count = 2"));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].channels[0].keys[1].t = " + F(2)));
  EXPECT_TRUE(Has(o.text, "ANIM.clips[0].channels[0].keys[1].value = " + V({1, 2, 3, 4})));
  EXPECT_TRUE(Has(o.text, "ANIM.players.count = 2"));
  EXPECT_TRUE(Has(o.text, "ANIM.players[0].clip = \"spin\""));
  EXPECT_TRUE(Has(o.text, "ANIM.players[0].speed = " + F(1.5f)));
  EXPECT_TRUE(Has(o.text, "ANIM.players[0].layer = 3"));
  EXPECT_TRUE(Has(o.text, "ANIM.players[1].triggerKind = 1"));

  const std::size_t targetAt = 4 + 2 + 4 + 4 + 1 + 4 + 4 + 4; // clipCount, name, duration, loop, channelCount, instanceCell, instanceIndex
  Bytes b = p;
  EXPECT_EQ(b[targetAt], 0);
  b[targetAt] = 3;
  EXPECT_TRUE(Dump("ANIM", b).status == DecodeStatus::Error);
  b = p;
  b[targetAt + 1] = 0; b[targetAt + 2] = 0; b[targetAt + 3] = 0; b[targetAt + 4] = 0; // channel without keys
  const Outcome ok0 = Dump("ANIM", b);
  EXPECT_TRUE(ok0.status == DecodeStatus::Error);
  b = p;
  b[p.size() - 1] = 2; // triggerKind 2
  EXPECT_TRUE(Dump("ANIM", b).status == DecodeStatus::Error);
  ByteWriter w;
  w.u32(1025);
  EXPECT_TRUE(Dump("ANIM", w.buf).status == DecodeStatus::Error);
  // an empty animation chunk
  EXPECT_TRUE(Dump("ANIM", Bytes(8, 0)).text == "ANIM.clips.count = 0\nANIM.players.count = 0\n");
}

void TestVolr()
{
  const Bytes p = VolrPayload();
  Robust("VOLR", p, 0);
  const Outcome o = Dump("VOLR", p);
  EXPECT_TRUE(Has(o.text, "VOLR.volumes.count = 4"));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[0].kind = 0"));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[1].shapeKind = 1"));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[0].priority = -3"));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[2].priority = -1"));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[0].color = " + V({0.5f, 0.6f, 0.7f})));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[0].density = " + F(0.01f)));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[0].heightFalloff = " + F(0.1f)));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[1].exposureEV = " + F(1)));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[1].tint = " + V({1, 1, 0.5f})));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[2].preset = \"cave\""));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[3].ambientMul = " + F(0.5f)));
  EXPECT_TRUE(Has(o.text, "VOLR.volumes[3].tint = " + V({0.2f, 0.3f, 0.4f})));
  EXPECT_TRUE(o.text.find("VOLR.volumes[2].color") == std::string::npos); // only the fields of the volume's kind
  Bytes b = p;
  b[4] = 4; // kind
  EXPECT_TRUE(Dump("VOLR", b).status == DecodeStatus::Error);
  b = p;
  b[5] = 2; // shapeKind
  EXPECT_TRUE(Dump("VOLR", b).status == DecodeStatus::Error);
}

void TestFamilyEntry()
{
  ChunkCtx ctx;
  ctx.container = 4;
  TextDump d;
  std::string err = "keep";
  const Bytes nothing;
  for (const char* id : {"GRID", "WRLD", "COLL", "MATL", "XXXX", "cidx", "CIDX1", ""}) {
    EXPECT_TRUE(DumpChunkWorld3D(id, 1, nothing.data(), 0, ctx, d, err) == DecodeStatus::NotMine);
  }
  EXPECT_TRUE(d.out.empty());
  EXPECT_EQ(err, std::string("keep"));
  // all ten ids are mine at container 4
  for (const char* id : {"CIDX", "MSHB", "MATB", "INST", "LODG", "OCCL", "LMAP", "PRBV", "ANIM", "VOLR"}) {
    const DecodeStatus s = DumpChunkWorld3D(id, 1, nothing.data(), 0, ctx, d, err);
    EXPECT_TRUE(s == DecodeStatus::Error); // empty payload is malformed for every one of them
  }
  // The decoders are usable directly with typed results.
  const Bytes p = VolrPayload();
  Volr v;
  EXPECT_TRUE(DecodeVolr(p.data(), p.size(), ctx, v, err));
  EXPECT_EQ(v.volumes.size(), 4U);
  EXPECT_EQ(v.volumes[2].preset, std::string("cave"));
  EXPECT_EQ(v.volumes[0].priority, -3);
  const Bytes a = AnimPayload();
  Anim an;
  EXPECT_TRUE(DecodeAnim(a.data(), a.size(), ctx, an, err));
  EXPECT_EQ(an.clips[0].channels[1].keys.size(), 2U);
  const Bytes l = LmapPayload(1);
  Lmap lm;
  EXPECT_TRUE(DecodeLmap(l.data(), l.size(), ctx, lm, err));
  EXPECT_EQ(lm.directionBytes.size, 4U);
  EXPECT_EQ(lm.directionBytes.data[3], 0xA3);
}

} // namespace

TEST(MapFormatWorld3DChunks, Checks)
{
  TestCidx();
  TestMshb();
  TestMatb();
  TestInst();
  TestLodg();
  TestOccl();
  TestLmap();
  TestPrbv();
  TestAnim();
  TestVolr();
  TestFamilyEntry();
}
