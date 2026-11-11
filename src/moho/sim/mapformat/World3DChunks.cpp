#include "moho/sim/mapformat/World3DChunks.h"

#include <utility>

namespace moho::mapformat {

using namespace world3d;

namespace {

bool Fail(std::string& err, const char* id, const std::string& why)
{
  err = std::string(id) + ": " + why;
  return false;
}

/// End of every decoder: a failed reader (truncation, count or string length out of range) or unread bytes refuse the chunk.
bool Finish(ByteReader& r, std::string& err, const char* id)
{
  if (!r.ok()) return Fail(err, id, "truncated payload, or a count / string length out of range");
  if (!r.atEnd()) return Fail(err, id, std::to_string(r.remaining()) + " trailing bytes after the last field");
  return true;
}

void ReadFloats(ByteReader& r, float* v, int n)
{
  for (int i = 0; i < n; ++i) v[i] = r.f32();
}

/// `path` = str, empty or a lower case VFS path starting with '/'.
bool ReadPath(ByteReader& r, std::string& s)
{
  s = r.str();
  return !r.ok() || IsValidVfsPath(s);
}

std::string ElemName(const char* what, std::size_t i) { return std::string(what) + " " + std::to_string(i); }

std::string IntList(const std::uint16_t* v, int n)
{
  std::string s = "[";
  for (int i = 0; i < n; ++i) s += (i ? ", " : "") + std::to_string(v[i]);
  return s + "]";
}

void DumpMeshRef(TextDump& d, const std::string& p, const MeshRef& m)
{
  d.U(p + ".bundle", m.bundle);
  d.U(p + ".index", m.index);
}

// ---------------------------------------------------------------- CIDX
constexpr std::size_t kCidxCellMin = 36;
constexpr std::size_t kMshbMeshMin = 31;
constexpr std::size_t kMatbMin = 97;
constexpr std::size_t kInstMin = 41;
constexpr std::size_t kProxyMin = 56;

// ---------------------------------------------------------------- MSHB native payload
const std::uint32_t kComponentBytes[8] = {4, 2, 2, 1, 1, 1, 2, 2};

bool DecodeMshbNative(ByteSpan span, MshbNative& n, std::string& err, std::size_t meshIndex)
{
  const std::string at = "mesh " + std::to_string(meshIndex) + " (native)";
  ByteReader r(span.data, span.size);
  n.vertexCount = r.u32();
  n.indexCount = r.u32();
  n.indexWidth = r.u8();
  if (!r.ok()) return Fail(err, "MSHB", at + ": truncated header");
  if (n.indexWidth != 2 && n.indexWidth != 4) return Fail(err, "MSHB", at + ": indexWidth must be 2 or 4");
  const std::uint32_t na = r.count(3, kMaxAttributes);
  if (!r.ok()) return Fail(err, "MSHB", at + ": attribute count out of range");
  std::uint64_t stride = 0;
  for (std::uint32_t i = 0; i < na; ++i) {
    MshbAttribute a;
    a.semantic = r.u8();
    a.component = r.u8();
    a.count = r.u8();
    if (!r.ok()) break;
    if (a.semantic > 7 || a.component > 7 || a.count < 1 || a.count > 4)
      return Fail(err, "MSHB", at + ": attribute " + std::to_string(i) + " has an invalid semantic, component or count");
    stride += (static_cast<std::uint64_t>(kComponentBytes[a.component]) * a.count + 3) & ~3ULL;
    n.attributes.push_back(a);
  }
  if (!r.ok()) return Fail(err, "MSHB", at + ": truncated attribute table");
  n.stride = static_cast<std::uint32_t>(stride);
  if (n.vertexCount > 0 && stride == 0) return Fail(err, "MSHB", at + ": vertices without attributes");
  const std::uint8_t* vp = r.bytes(static_cast<std::uint64_t>(n.vertexCount) * stride);
  if (!vp) return Fail(err, "MSHB", at + ": vertex data larger than the payload");
  n.vertexData.data = vp;
  n.vertexData.size = static_cast<std::size_t>(static_cast<std::uint64_t>(n.vertexCount) * stride);
  const std::uint8_t* ip = r.bytes(static_cast<std::uint64_t>(n.indexCount) * n.indexWidth);
  if (!ip) return Fail(err, "MSHB", at + ": index data larger than the payload");
  n.indexData.data = ip;
  n.indexData.size = static_cast<std::size_t>(static_cast<std::uint64_t>(n.indexCount) * n.indexWidth);
  if (n.indexWidth == 2 && n.vertexCount > 65536)
    return Fail(err, "MSHB", at + ": 16 bit indices cannot address " + std::to_string(n.vertexCount) + " vertices");
  for (std::uint32_t i = 0; i < n.indexCount; ++i) {
    std::uint32_t idx = ip[i * n.indexWidth];
    for (unsigned b = 1; b < n.indexWidth; ++b) idx |= static_cast<std::uint32_t>(ip[i * n.indexWidth + b]) << (8 * b);
    if (idx >= n.vertexCount) return Fail(err, "MSHB", at + ": index " + std::to_string(i) + " refers past the vertices");
  }
  const std::uint32_t ns = r.count(10, kMaxSubmeshes);
  for (std::uint32_t i = 0; i < ns && r.ok(); ++i) {
    MshbSubmesh s;
    s.firstIndex = r.u32();
    s.indexCount = r.u32();
    s.materialSlot = r.u16();
    if (!r.ok()) break;
    if (static_cast<std::uint64_t>(s.firstIndex) + s.indexCount > n.indexCount)
      return Fail(err, "MSHB", at + ": submesh " + std::to_string(i) + " reaches past the index data");
    n.submeshes.push_back(s);
  }
  const std::uint32_t nl = r.ok() ? r.count(12, kMaxLods) : 0;
  for (std::uint32_t i = 0; i < nl && r.ok(); ++i) {
    MshbLod l;
    l.screenSize = r.f32();
    l.firstSubmesh = r.u32();
    l.submeshCount = r.u32();
    if (!r.ok()) break;
    if (static_cast<std::uint64_t>(l.firstSubmesh) + l.submeshCount > n.submeshes.size())
      return Fail(err, "MSHB", at + ": lod " + std::to_string(i) + " reaches past the submesh table");
    n.lods.push_back(l);
  }
  if (!r.ok()) return Fail(err, "MSHB", at + ": truncated or a count out of range");
  if (!r.atEnd()) return Fail(err, "MSHB", at + ": " + std::to_string(r.remaining()) + " trailing bytes inside the mesh");
  return true;
}

} // namespace

// ================================================================ CIDX
bool DecodeCidx(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Cidx& out, std::string& err)
{
  out = Cidx();
  if (ctx.worldCells == 0) return Fail(err, "CIDX", "needs the cell count from WRLD (decode WRLD first)");
  ByteReader r(data, size);
  const std::uint32_t n = r.count(kCidxCellMin, kMaxCells);
  if (!r.ok()) return Fail(err, "CIDX", "cell count out of range or larger than the payload");
  if (n != ctx.worldCells) return Fail(err, "CIDX", "cell count " + std::to_string(n) + " differs from the WRLD cell count " + std::to_string(ctx.worldCells));
  out.cells.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    CidxCell c;
    ReadFloats(r, c.min, 3);
    ReadFloats(r, c.max, 3);
    c.loadDistance = r.f32();
    c.unloadDistance = r.f32();
    c.priority = r.u8();
    c.flags = r.u8();
    c.layer = r.u16();
    if (!r.ok()) break;
    if (c.flags & ~0x1FU) return Fail(err, "CIDX", ElemName("cell", i) + ": flags use undefined bits");
    if (!(c.unloadDistance >= c.loadDistance)) return Fail(err, "CIDX", ElemName("cell", i) + ": unloadDistance is below loadDistance");
    out.cells.push_back(c);
  }
  return Finish(r, err, "CIDX");
}

void DumpCidx(const Cidx& v, TextDump& d)
{
  d.Count("CIDX.cells", v.cells.size());
  for (std::size_t i = 0; i < v.cells.size(); ++i) {
    const CidxCell& c = v.cells[i];
    const std::string p = TextDump::Idx("CIDX.cells", i);
    d.Vec(p + ".min", c.min, 3);
    d.Vec(p + ".max", c.max, 3);
    d.F32(p + ".loadDistance", c.loadDistance);
    d.F32(p + ".unloadDistance", c.unloadDistance);
    d.U(p + ".priority", c.priority);
    d.U(p + ".flags", c.flags);
    d.U(p + ".layer", c.layer);
  }
}

// ================================================================ MSHB
bool DecodeMshb(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Mshb& out, std::string& err)
{
  (void)ctx;
  out = Mshb();
  ByteReader r(data, size);
  const std::uint32_t n = r.count(kMshbMeshMin, kMaxMeshes);
  if (!r.ok()) return Fail(err, "MSHB", "mesh count out of range or larger than the payload");
  out.meshes.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    MshbMesh m;
    m.name = r.str();
    m.format = r.u8();
    ReadFloats(r, m.aabb, 6);
    m.byteCount = r.u32();
    const std::uint8_t* p = r.bytes(m.byteCount);
    if (!r.ok()) break;
    m.bytes.data = p;
    m.bytes.size = m.byteCount;
    if (m.format > 1) return Fail(err, "MSHB", ElemName("mesh", i) + ": unknown format " + std::to_string(m.format));
    if (m.format == 1 && !DecodeMshbNative(m.bytes, m.native, err, i)) return false;
    out.meshes.push_back(std::move(m));
  }
  return Finish(r, err, "MSHB");
}

void DumpMshb(const Mshb& v, TextDump& d)
{
  d.Count("MSHB.meshes", v.meshes.size());
  for (std::size_t i = 0; i < v.meshes.size(); ++i) {
    const MshbMesh& m = v.meshes[i];
    const std::string p = TextDump::Idx("MSHB.meshes", i);
    d.Str(p + ".name", m.name);
    d.U(p + ".format", m.format);
    d.Vec(p + ".aabb", m.aabb, 6);
    d.U(p + ".byteCount", m.byteCount);
    d.Bytes(p + ".data", m.bytes.data, m.bytes.size);
  }
}

// ================================================================ MATB
bool DecodeMatb(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Matb& out, std::string& err)
{
  (void)ctx;
  out = Matb();
  ByteReader r(data, size);
  const std::uint32_t n = r.count(kMatbMin, kMaxMaterials);
  if (!r.ok()) return Fail(err, "MATB", "material count out of range or larger than the payload");
  out.materials.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    MatbMaterial m;
    m.name = r.str();
    ReadFloats(r, m.baseColor, 4);
    ReadFloats(r, m.emissive, 3);
    m.emissiveStrength = r.f32();
    m.metallic = r.f32();
    m.roughness = r.f32();
    m.normalScale = r.f32();
    m.occlusionStrength = r.f32();
    m.alphaMode = r.u8();
    m.alphaCutoff = r.f32();
    m.flags = r.u16();
    const bool pathsOk = ReadPath(r, m.baseColorTex) && ReadPath(r, m.normalTex) && ReadPath(r, m.ormTex) && ReadPath(r, m.emissiveTex);
    ReadFloats(r, m.uvOffset, 2);
    ReadFloats(r, m.uvScale, 2);
    m.uvRotation = r.f32();
    m.clearcoat = r.f32();
    m.clearcoatRoughness = r.f32();
    m.windAmount = r.f32();
    if (!r.ok()) break;
    if (!pathsOk) return Fail(err, "MATB", ElemName("material", i) + ": a texture path is not a lower case VFS path starting with '/'");
    if (m.alphaMode > 2) return Fail(err, "MATB", ElemName("material", i) + ": unknown alphaMode " + std::to_string(m.alphaMode));
    if (m.flags & ~0x1FU) return Fail(err, "MATB", ElemName("material", i) + ": flags use undefined bits");
    out.materials.push_back(std::move(m));
  }
  return Finish(r, err, "MATB");
}

void DumpMatb(const Matb& v, TextDump& d)
{
  d.Count("MATB.materials", v.materials.size());
  for (std::size_t i = 0; i < v.materials.size(); ++i) {
    const MatbMaterial& m = v.materials[i];
    const std::string p = TextDump::Idx("MATB.materials", i);
    d.Str(p + ".name", m.name);
    d.Vec(p + ".baseColor", m.baseColor, 4);
    d.Vec(p + ".emissive", m.emissive, 3);
    d.F32(p + ".emissiveStrength", m.emissiveStrength);
    d.F32(p + ".metallic", m.metallic);
    d.F32(p + ".roughness", m.roughness);
    d.F32(p + ".normalScale", m.normalScale);
    d.F32(p + ".occlusionStrength", m.occlusionStrength);
    d.U(p + ".alphaMode", m.alphaMode);
    d.F32(p + ".alphaCutoff", m.alphaCutoff);
    d.U(p + ".flags", m.flags);
    d.Str(p + ".baseColorTex", m.baseColorTex);
    d.Str(p + ".normalTex", m.normalTex);
    d.Str(p + ".ormTex", m.ormTex);
    d.Str(p + ".emissiveTex", m.emissiveTex);
    d.Vec(p + ".uvOffset", m.uvOffset, 2);
    d.Vec(p + ".uvScale", m.uvScale, 2);
    d.F32(p + ".uvRotation", m.uvRotation);
    d.F32(p + ".clearcoat", m.clearcoat);
    d.F32(p + ".clearcoatRoughness", m.clearcoatRoughness);
    d.F32(p + ".windAmount", m.windAmount);
  }
}

// ================================================================ INST
bool DecodeInst(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Inst& out, std::string& err)
{
  (void)ctx;
  out = Inst();
  ByteReader r(data, size);
  ReadFloats(r, out.cellOrigin, 3);
  ReadFloats(r, out.cellExtent, 3);
  const std::uint32_t n = r.count(kInstMin, kMaxInstances);
  if (!r.ok()) return Fail(err, "INST", "truncated header, or instance count out of range / larger than the payload");
  out.instances.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    InstInstance in;
    in.mesh.bundle = r.u16();
    in.mesh.index = r.u16();
    for (int k = 0; k < 3; ++k) in.pos[k] = r.u16();
    in.rot = r.u32();
    for (int k = 0; k < 3; ++k) in.scale[k] = r.u16();
    in.flags = r.u32();
    in.lodBias = r.u16();
    in.layer = r.u16();
    in.cullDistance = r.u16();
    in.lightmap = r.u16();
    for (int k = 0; k < 4; ++k) in.lightmapScaleOffset[k] = r.u16();
    in.overrideCount = r.u8();
    if (!r.ok()) break;
    if (in.flags & ~0x3FU) return Fail(err, "INST", ElemName("instance", i) + ": flags use undefined bits");
    if (in.overrideCount > kMaxMaterialOverrides) return Fail(err, "INST", ElemName("instance", i) + ": more than 8 material overrides");
    for (unsigned k = 0; k < in.overrideCount; ++k) in.materialOverride[k] = r.u16();
    if (!r.ok()) break;
    out.instances.push_back(in);
  }
  return Finish(r, err, "INST");
}

void DumpInst(const Inst& v, TextDump& d)
{
  d.Vec("INST.cellOrigin", v.cellOrigin, 3);
  d.Vec("INST.cellExtent", v.cellExtent, 3);
  d.Count("INST.insts", v.instances.size());
  for (std::size_t i = 0; i < v.instances.size(); ++i) {
    const InstInstance& in = v.instances[i];
    const std::string p = TextDump::Idx("INST.insts", i);
    DumpMeshRef(d, p + ".mesh", in.mesh);
    d.Raw(p + ".pos", IntList(in.pos, 3));
    d.U(p + ".rot", in.rot);
    d.Raw(p + ".scale", IntList(in.scale, 3));
    d.U(p + ".flags", in.flags);
    d.U(p + ".lodBias", in.lodBias);
    d.U(p + ".layer", in.layer);
    d.U(p + ".cullDistance", in.cullDistance);
    d.U(p + ".lightmap", in.lightmap);
    d.Raw(p + ".lightmapScaleOffset", IntList(in.lightmapScaleOffset, 4));
    d.U(p + ".overrideCount", in.overrideCount);
    d.Count(p + ".materialOverride", in.overrideCount);
    for (unsigned k = 0; k < in.overrideCount; ++k) d.U(TextDump::Idx(p + ".materialOverride", k), in.materialOverride[k]);
  }
}

// ================================================================ LODG
bool DecodeLodg(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Lodg& out, std::string& err)
{
  (void)ctx;
  out = Lodg();
  ByteReader r(data, size);
  const std::uint32_t n = r.count(kProxyMin, kMaxProxies);
  if (!r.ok()) return Fail(err, "LODG", "proxy count out of range or larger than the payload");
  out.proxies.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    LodgProxy p;
    p.mesh.bundle = r.u16();
    p.mesh.index = r.u16();
    ReadFloats(r, p.pos, 3);
    ReadFloats(r, p.rot, 4);
    ReadFloats(r, p.scale, 3);
    p.showBeyond = r.f32();
    p.fadeWidth = r.f32();
    const std::uint32_t nr = r.count(4, kMaxReplaced);
    if (!r.ok()) break;
    p.replacesInstances.reserve(nr);
    for (std::uint32_t k = 0; k < nr; ++k) p.replacesInstances.push_back(r.u32());
    if (!r.ok()) break;
    out.proxies.push_back(std::move(p));
  }
  return Finish(r, err, "LODG");
}

void DumpLodg(const Lodg& v, TextDump& d)
{
  d.Count("LODG.proxies", v.proxies.size());
  for (std::size_t i = 0; i < v.proxies.size(); ++i) {
    const LodgProxy& x = v.proxies[i];
    const std::string p = TextDump::Idx("LODG.proxies", i);
    DumpMeshRef(d, p + ".mesh", x.mesh);
    d.Vec(p + ".pos", x.pos, 3);
    d.Vec(p + ".rot", x.rot, 4);
    d.Vec(p + ".scale", x.scale, 3);
    d.F32(p + ".showBeyond", x.showBeyond);
    d.F32(p + ".fadeWidth", x.fadeWidth);
    d.Count(p + ".replacesInstances", x.replacesInstances.size());
    for (std::size_t k = 0; k < x.replacesInstances.size(); ++k) d.U(TextDump::Idx(p + ".replacesInstances", k), x.replacesInstances[k]);
  }
}

// ================================================================ OCCL
bool DecodeOccl(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Occl& out, std::string& err)
{
  (void)ctx;
  out = Occl();
  ByteReader r(data, size);
  std::uint32_t n = r.count(41, kMaxOccluders);
  if (!r.ok()) return Fail(err, "OCCL", "occluder count out of range or larger than the payload");
  out.occluders.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    OcclOccluder o;
    o.kind = r.u8();
    if (!r.ok()) break;
    if (o.kind == 0) {
      ReadFloats(r, o.center, 3);
      ReadFloats(r, o.halfExtents, 3);
      ReadFloats(r, o.rot, 4);
    } else if (o.kind == 1) {
      o.mesh.bundle = r.u16();
      o.mesh.index = r.u16();
      ReadFloats(r, o.pos, 3);
      ReadFloats(r, o.rot, 4);
      ReadFloats(r, o.scale, 3);
    } else {
      return Fail(err, "OCCL", ElemName("occluder", i) + ": unknown kind " + std::to_string(o.kind));
    }
    if (!r.ok()) break;
    out.occluders.push_back(o);
  }
  if (!r.ok()) return Finish(r, err, "OCCL");
  n = r.count(26, kMaxRooms);
  for (std::uint32_t i = 0; i < n && r.ok(); ++i) {
    OcclRoom room;
    room.name = r.str();
    ReadFloats(r, room.min, 3);
    ReadFloats(r, room.max, 3);
    if (!r.ok()) break;
    out.rooms.push_back(std::move(room));
  }
  if (!r.ok()) return Finish(r, err, "OCCL");
  n = r.count(53, kMaxPortals);
  for (std::uint32_t i = 0; i < n && r.ok(); ++i) {
    OcclPortal po;
    for (int q = 0; q < 4; ++q) ReadFloats(r, po.quad[q], 3);
    po.roomA = r.u16();
    po.roomB = r.u16();
    po.flags = r.u8();
    if (!r.ok()) break;
    if (po.flags & ~1U) return Fail(err, "OCCL", ElemName("portal", i) + ": flags use undefined bits");
    out.portals.push_back(po);
  }
  return Finish(r, err, "OCCL");
}

void DumpOccl(const Occl& v, TextDump& d)
{
  d.Count("OCCL.occluders", v.occluders.size());
  for (std::size_t i = 0; i < v.occluders.size(); ++i) {
    const OcclOccluder& o = v.occluders[i];
    const std::string p = TextDump::Idx("OCCL.occluders", i);
    d.U(p + ".kind", o.kind);
    if (o.kind == 0) {
      d.Vec(p + ".center", o.center, 3);
      d.Vec(p + ".halfExtents", o.halfExtents, 3);
      d.Vec(p + ".rot", o.rot, 4);
    } else {
      DumpMeshRef(d, p + ".mesh", o.mesh);
      d.Vec(p + ".pos", o.pos, 3);
      d.Vec(p + ".rot", o.rot, 4);
      d.Vec(p + ".scale", o.scale, 3);
    }
  }
  d.Count("OCCL.rooms", v.rooms.size());
  for (std::size_t i = 0; i < v.rooms.size(); ++i) {
    const std::string p = TextDump::Idx("OCCL.rooms", i);
    d.Str(p + ".name", v.rooms[i].name);
    d.Vec(p + ".min", v.rooms[i].min, 3);
    d.Vec(p + ".max", v.rooms[i].max, 3);
  }
  d.Count("OCCL.portals", v.portals.size());
  for (std::size_t i = 0; i < v.portals.size(); ++i) {
    const OcclPortal& po = v.portals[i];
    const std::string p = TextDump::Idx("OCCL.portals", i);
    {
      float flat[12];
      for (int q = 0; q < 4; ++q)
        for (int k = 0; k < 3; ++k) flat[q * 3 + k] = po.quad[q][k];
      d.Vec(p + ".quad", flat, 12);
    }
    d.U(p + ".roomA", po.roomA);
    d.U(p + ".roomB", po.roomB);
    d.U(p + ".flags", po.flags);
  }
}

// ================================================================ LMAP
bool DecodeLmap(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Lmap& out, std::string& err)
{
  (void)ctx;
  out = Lmap();
  ByteReader r(data, size);
  out.width = r.u32();
  out.height = r.u32();
  out.format = r.u8();
  out.kind = r.u8();
  out.byteCount = r.u32();
  if (!r.ok()) return Fail(err, "LMAP", "truncated header");
  if (out.width == 0 || out.height == 0 || out.width > kMaxLightmapDim || out.height > kMaxLightmapDim)
    return Fail(err, "LMAP", "width / height must be 1.." + std::to_string(kMaxLightmapDim));
  if (out.format > 2) return Fail(err, "LMAP", "unknown format " + std::to_string(out.format));
  if (out.kind > 1) return Fail(err, "LMAP", "unknown kind " + std::to_string(out.kind));
  const std::uint8_t* p = r.bytes(out.byteCount);
  if (!p) return Fail(err, "LMAP", "byteCount is larger than the payload");
  out.bytes.data = p;
  out.bytes.size = out.byteCount;
  if (out.kind == 1) {
    out.directionByteCount = r.u32();
    const std::uint8_t* q = r.bytes(out.directionByteCount);
    if (!q) return Fail(err, "LMAP", "direction byteCount is larger than the payload");
    out.directionBytes.data = q;
    out.directionBytes.size = out.directionByteCount;
  }
  return Finish(r, err, "LMAP");
}

void DumpLmap(const Lmap& v, TextDump& d)
{
  d.U("LMAP.width", v.width);
  d.U("LMAP.height", v.height);
  d.U("LMAP.format", v.format);
  d.U("LMAP.kind", v.kind);
  d.U("LMAP.byteCount", v.byteCount);
  d.Bytes("LMAP.data", v.bytes.data, v.bytes.size);
  if (v.kind == 1) {
    d.U("LMAP.dirByteCount", v.directionByteCount);
    d.Bytes("LMAP.dirData", v.directionBytes.data, v.directionBytes.size);
  }
}

// ================================================================ PRBV
bool DecodePrbv(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Prbv& out, std::string& err)
{
  (void)ctx;
  out = Prbv();
  ByteReader r(data, size);
  ReadFloats(r, out.gridOrigin, 3);
  ReadFloats(r, out.gridSpacing, 3);
  out.nx = r.u32();
  out.ny = r.u32();
  out.nz = r.u32();
  if (!r.ok()) return Fail(err, "PRBV", "truncated header");
  // nx*ny fits in 64 bits (two u32 factors); times nz it is bounded by 2^22 * 2^32 once the first product is checked.
  std::uint64_t probes = 0;
  if (out.nx != 0 && out.ny != 0 && out.nz != 0) {
    probes = static_cast<std::uint64_t>(out.nx) * out.ny;
    if (probes <= kMaxProbeCells) probes *= out.nz;
  }
  if (probes > kMaxProbeCells) return Fail(err, "PRBV", "nx*ny*nz exceeds 2^22");
  const std::uint8_t* p = r.bytes(probes * 27 * 2);
  if (!p) return Fail(err, "PRBV", "coefficient data is larger than the payload");
  out.coefficients.data = p;
  out.coefficients.size = static_cast<std::size_t>(probes * 27 * 2);
  return Finish(r, err, "PRBV");
}

void DumpPrbv(const Prbv& v, TextDump& d)
{
  d.Vec("PRBV.gridOrigin", v.gridOrigin, 3);
  d.Vec("PRBV.gridSpacing", v.gridSpacing, 3);
  d.U("PRBV.nx", v.nx);
  d.U("PRBV.ny", v.ny);
  d.U("PRBV.nz", v.nz);
  d.Bytes("PRBV.shData", v.coefficients.data, v.coefficients.size);
}

// ================================================================ ANIM
bool DecodeAnim(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Anim& out, std::string& err)
{
  (void)ctx;
  out = Anim();
  ByteReader r(data, size);
  const std::uint32_t nc = r.count(11, kMaxClips);
  if (!r.ok()) return Fail(err, "ANIM", "clip count out of range or larger than the payload");
  out.clips.reserve(nc);
  for (std::uint32_t i = 0; i < nc; ++i) {
    AnimClip c;
    c.name = r.str();
    c.duration = r.f32();
    c.loop = r.u8();
    if (r.ok() && c.loop > 1) return Fail(err, "ANIM", ElemName("clip", i) + ": loop must be 0 or 1");
    for (const AnimClip& prev : out.clips)
      if (prev.name == c.name) return Fail(err, "ANIM", ElemName("clip", i) + ": duplicate clip name");
    const std::uint32_t nch = r.count(13, kMaxChannels);
    if (!r.ok()) break;
    c.channels.reserve(nch);
    for (std::uint32_t j = 0; j < nch; ++j) {
      AnimChannel ch;
      ch.instanceCell = r.u32();
      ch.instanceIndex = r.u32();
      ch.target = r.u8();
      const std::uint32_t nk = r.count(20, kMaxKeys);
      if (!r.ok()) break;
      if (ch.target > 2) return Fail(err, "ANIM", ElemName("clip", i) + ", " + ElemName("channel", j) + ": unknown target " + std::to_string(ch.target));
      if (nk < 1) return Fail(err, "ANIM", ElemName("clip", i) + ", " + ElemName("channel", j) + ": a channel needs at least one key");
      ch.keys.reserve(nk);
      for (std::uint32_t k = 0; k < nk; ++k) {
        AnimKey key;
        key.t = r.f32();
        ReadFloats(r, key.value, 4);
        ch.keys.push_back(key);
      }
      if (!r.ok()) break;
      c.channels.push_back(std::move(ch));
    }
    if (!r.ok()) break;
    out.clips.push_back(std::move(c));
  }
  if (!r.ok()) return Finish(r, err, "ANIM");
  const std::uint32_t np = r.count(13, kMaxPlayers);
  for (std::uint32_t i = 0; i < np && r.ok(); ++i) {
    AnimPlayer p;
    p.clip = r.str();
    p.speed = r.f32();
    p.phase = r.f32();
    p.layer = r.u16();
    p.triggerKind = r.u8();
    if (!r.ok()) break;
    if (p.triggerKind > 1) return Fail(err, "ANIM", ElemName("player", i) + ": unknown triggerKind " + std::to_string(p.triggerKind));
    out.players.push_back(std::move(p));
  }
  return Finish(r, err, "ANIM");
}

void DumpAnim(const Anim& v, TextDump& d)
{
  d.Count("ANIM.clips", v.clips.size());
  for (std::size_t i = 0; i < v.clips.size(); ++i) {
    const AnimClip& c = v.clips[i];
    const std::string p = TextDump::Idx("ANIM.clips", i);
    d.Str(p + ".name", c.name);
    d.F32(p + ".duration", c.duration);
    d.U(p + ".loop", c.loop);
    d.Count(p + ".channels", c.channels.size());
    for (std::size_t j = 0; j < c.channels.size(); ++j) {
      const AnimChannel& ch = c.channels[j];
      const std::string q = TextDump::Idx(p + ".channels", j);
      d.U(q + ".instanceCell", ch.instanceCell);
      d.U(q + ".instanceIndex", ch.instanceIndex);
      d.U(q + ".target", ch.target);
      d.Count(q + ".keys", ch.keys.size());
      for (std::size_t k = 0; k < ch.keys.size(); ++k) {
        const std::string e = TextDump::Idx(q + ".keys", k);
        d.F32(e + ".t", ch.keys[k].t);
        d.Vec(e + ".value", ch.keys[k].value, 4);
      }
    }
  }
  d.Count("ANIM.players", v.players.size());
  for (std::size_t i = 0; i < v.players.size(); ++i) {
    const AnimPlayer& pl = v.players[i];
    const std::string p = TextDump::Idx("ANIM.players", i);
    d.Str(p + ".clip", pl.clip);
    d.F32(p + ".speed", pl.speed);
    d.F32(p + ".phase", pl.phase);
    d.U(p + ".layer", pl.layer);
    d.U(p + ".triggerKind", pl.triggerKind);
  }
}

// ================================================================ VOLR
bool DecodeVolr(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, Volr& out, std::string& err)
{
  (void)ctx;
  out = Volr();
  ByteReader r(data, size);
  const std::uint32_t n = r.count(52, kMaxVolumes);
  if (!r.ok()) return Fail(err, "VOLR", "volume count out of range or larger than the payload");
  out.volumes.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    VolrVolume v;
    v.kind = r.u8();
    v.shapeKind = r.u8();
    ReadFloats(r, v.center, 3);
    ReadFloats(r, v.halfExtents, 3);
    ReadFloats(r, v.rot, 4);
    v.blendDistance = r.f32();
    v.priority = r.i16();
    v.layer = r.u16();
    if (!r.ok()) break;
    if (v.shapeKind > 1) return Fail(err, "VOLR", ElemName("volume", i) + ": unknown shapeKind " + std::to_string(v.shapeKind));
    switch (v.kind) {
    case 0:
      ReadFloats(r, v.color, 3);
      v.density = r.f32();
      v.heightFalloff = r.f32();
      break;
    case 1:
      v.exposureEV = r.f32();
      v.saturation = r.f32();
      v.contrast = r.f32();
      ReadFloats(r, v.tint, 3);
      break;
    case 2: v.preset = r.str(); break;
    case 3:
      v.ambientMul = r.f32();
      ReadFloats(r, v.tint, 3);
      break;
    default: return Fail(err, "VOLR", ElemName("volume", i) + ": unknown kind " + std::to_string(v.kind));
    }
    if (!r.ok()) break;
    out.volumes.push_back(std::move(v));
  }
  return Finish(r, err, "VOLR");
}

void DumpVolr(const Volr& v, TextDump& d)
{
  d.Count("VOLR.volumes", v.volumes.size());
  for (std::size_t i = 0; i < v.volumes.size(); ++i) {
    const VolrVolume& x = v.volumes[i];
    const std::string p = TextDump::Idx("VOLR.volumes", i);
    d.U(p + ".kind", x.kind);
    d.U(p + ".shapeKind", x.shapeKind);
    d.Vec(p + ".center", x.center, 3);
    d.Vec(p + ".halfExtents", x.halfExtents, 3);
    d.Vec(p + ".rot", x.rot, 4);
    d.F32(p + ".blendDistance", x.blendDistance);
    d.I(p + ".priority", x.priority);
    d.U(p + ".layer", x.layer);
    switch (x.kind) {
    case 0:
      d.Vec(p + ".color", x.color, 3);
      d.F32(p + ".density", x.density);
      d.F32(p + ".heightFalloff", x.heightFalloff);
      break;
    case 1:
      d.F32(p + ".exposureEV", x.exposureEV);
      d.F32(p + ".saturation", x.saturation);
      d.F32(p + ".contrast", x.contrast);
      d.Vec(p + ".tint", x.tint, 3);
      break;
    case 2: d.Str(p + ".preset", x.preset); break;
    default:
      d.F32(p + ".ambientMul", x.ambientMul);
      d.Vec(p + ".tint", x.tint, 3);
      break;
    }
  }
}

// ================================================================ family entry point
namespace {

template <class T, bool (*Decode)(const std::uint8_t*, std::size_t, ChunkCtx&, T&, std::string&), void (*Dump)(const T&, TextDump&)>
DecodeStatus Run(const std::uint8_t* data, std::size_t size, ChunkCtx& ctx, TextDump& dump, std::string& err)
{
  T value;
  if (!Decode(data, size, ctx, value, err)) return DecodeStatus::Error;
  Dump(value, dump);
  return DecodeStatus::Ok;
}

} // namespace

DecodeStatus DumpChunkWorld3D(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx,
                              TextDump& dump, std::string& err)
{
  if (ctx.container < 4) return DecodeStatus::NotMine;
  typedef DecodeStatus (*Runner)(const std::uint8_t*, std::size_t, ChunkCtx&, TextDump&, std::string&);
  Runner run = nullptr;
  if (id == "CIDX") run = &Run<Cidx, DecodeCidx, DumpCidx>;
  else if (id == "MSHB") run = &Run<Mshb, DecodeMshb, DumpMshb>;
  else if (id == "MATB") run = &Run<Matb, DecodeMatb, DumpMatb>;
  else if (id == "INST") run = &Run<Inst, DecodeInst, DumpInst>;
  else if (id == "LODG") run = &Run<Lodg, DecodeLodg, DumpLodg>;
  else if (id == "OCCL") run = &Run<Occl, DecodeOccl, DumpOccl>;
  else if (id == "LMAP") run = &Run<Lmap, DecodeLmap, DumpLmap>;
  else if (id == "PRBV") run = &Run<Prbv, DecodePrbv, DumpPrbv>;
  else if (id == "ANIM") run = &Run<Anim, DecodeAnim, DumpAnim>;
  else if (id == "VOLR") run = &Run<Volr, DecodeVolr, DumpVolr>;
  if (!run) return DecodeStatus::NotMine;
  if (version != 1) {
    err = id + ": unsupported chunk version " + std::to_string(version) + " (this reader knows 1)";
    return DecodeStatus::Error;
  }
  return run(data, size, ctx, dump, err);
}

} // namespace moho::mapformat
