#include "moho/sim/mapformat/ClassicExport.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>

#include "moho/sim/mapformat/MapFormatCommon.h"

namespace moho::mapformat {

namespace {

constexpr std::uint32_t kClassicMagic = 0x1A70614DU;
constexpr std::int32_t kClassicMinor = 56;
constexpr std::uint32_t kPreviewMagic = 0xBEEFFEEDU;

void CStr(ByteWriter& w, const std::string& s)
{
  w.bytes(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  w.u8(0);
}

void WriteBlob(ByteWriter& w, const std::vector<std::uint8_t>& b)
{
  w.i32(static_cast<std::int32_t>(b.size()));
  w.bytes(b.data(), b.size());
}

void Dds(ByteWriter& h, std::uint32_t width, std::uint32_t height, bool dxt5)
{
  const std::uint32_t blocks = ((width + 3) / 4) * ((height + 3) / 4);
  h.bytes(reinterpret_cast<const std::uint8_t*>("DDS "), 4);
  h.u32(124);
  h.u32(0x1 | 0x2 | 0x4 | 0x1000 | (dxt5 ? 0x80000 : 0x8));
  h.u32(height);
  h.u32(width);
  h.u32(dxt5 ? blocks * 16 : width * 4);
  h.u32(0);
  h.u32(0);
  for (int i = 0; i < 11; ++i) h.u32(0);
  h.u32(32);
  if (dxt5) {
    h.u32(0x4);
    h.bytes(reinterpret_cast<const std::uint8_t*>("DXT5"), 4);
    for (int i = 0; i < 5; ++i) h.u32(0);
  } else {
    h.u32(0x41);
    h.u32(0);
    h.u32(32);
    h.u32(0x00FF0000);
    h.u32(0x0000FF00);
    h.u32(0x000000FF);
    h.u32(0xFF000000);
  }
  h.u32(0x1000);
  for (int i = 0; i < 4; ++i) h.u32(0);
}

} // namespace

std::vector<std::uint8_t> MakeArgbDds(std::uint32_t width, std::uint32_t height, const std::uint8_t* bgra)
{
  ByteWriter w;
  Dds(w, width, height, false);
  const std::size_t n = static_cast<std::size_t>(width) * height * 4;
  if (bgra) w.bytes(bgra, n);
  else w.buf.resize(w.buf.size() + n, 0);
  return std::move(w.buf);
}

std::vector<std::uint8_t> MakeDxt5FlatDds(std::uint32_t width, std::uint32_t height, std::uint8_t r, std::uint8_t g,
                                           std::uint8_t b, std::uint8_t a)
{
  ByteWriter w;
  Dds(w, width, height, true);
  const std::uint16_t c565 = static_cast<std::uint16_t>(((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3));
  const std::uint32_t blocks = ((width + 3) / 4) * ((height + 3) / 4);
  for (std::uint32_t i = 0; i < blocks; ++i) {
    w.u8(a);
    w.u8(a);
    for (int k = 0; k < 6; ++k) w.u8(0);
    w.u16(c565);
    w.u16(c565);
    for (int k = 0; k < 4; ++k) w.u8(0);
  }
  return std::move(w.buf);
}

void QuatToAxes(const float q[4], float a[9])
{
  const float x = q[0], y = q[1], z = q[2], w = q[3];
  a[0] = 1.0f - 2.0f * (y * y + z * z);
  a[1] = 2.0f * (x * y + w * z);
  a[2] = 2.0f * (x * z - w * y);
  a[3] = 2.0f * (x * y - w * z);
  a[4] = 1.0f - 2.0f * (x * x + z * z);
  a[5] = 2.0f * (y * z + w * x);
  a[6] = 2.0f * (x * z + w * y);
  a[7] = 2.0f * (y * z - w * x);
  a[8] = 1.0f - 2.0f * (x * x + y * y);
}

namespace {

struct Slots
{
  // Per classic slot (0 = base .. 8): the MATL material index, -1 when unused.
  int material[9];
  Slots() { for (int& m : material) m = -1; }
};

const MatlMaterial* FindMaterial(const MatlChunk& matl, int id)
{
  for (const MatlMaterial& m : matl.material) {
    if (m.id == id) return &m;
  }
  return nullptr;
}

float Clamp01(float v) { return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v); }

} // namespace

bool ExportClassic(const ExtendedMap& map, const ClassicExportOptions& options, ClassicExportResult& out, std::string& err)
{
  const MapSimData& s = map.sim;
  if (!s.grid || !s.hght || !s.gply || !s.wbod) {
    err = "the map has no GRID / HGHT / GPLY / WBOD";
    return false;
  }
  const GridChunk& grid = *s.grid;
  const HghtChunk& hght = *s.hght;
  const std::uint32_t cx = grid.cellsX, cz = grid.cellsZ;
  const std::uint32_t sw = cx + 1, sh = cz + 1;
  if (hght.samples.size() != static_cast<std::size_t>(sw) * sh) {
    err = "HGHT sample count does not match GRID";
    return false;
  }
  std::vector<std::string>& notes = out.notes;

  // ---- heights: Classic is u16 / 128 --------------------------------------------------------------------------------
  std::vector<std::uint16_t> heights(hght.samples.size());
  {
    const double step = std::ldexp(1.0, hght.stepLog2);
    std::uint64_t rounded = 0;
    double maxErr = 0.0;
    for (std::size_t i = 0; i < heights.size(); ++i) {
      const double h = static_cast<double>(hght.minHeight) + static_cast<double>(hght.samples[i]) * step;
      const double u = h * 128.0;
      double r = std::floor(u + 0.5);
      if (r < 0.0) r = 0.0;
      if (r > 65535.0) r = 65535.0;
      const double e = std::fabs(r - u) / 128.0;
      if (e > 1e-9) {
        ++rounded;
        maxErr = std::max(maxErr, e);
      }
      heights[i] = static_cast<std::uint16_t>(r);
    }
    out.maxHeightError = static_cast<float>(maxErr);
    if (rounded) {
      if (!options.quantizeHeights) {
        err = "heights are not multiples of 1/128 and quantisation is off";
        return false;
      }
      notes.push_back("heights rounded to 1/128 units: " + std::to_string(rounded) + " samples, largest error " +
                      std::to_string(maxErr));
    }
  }

  // ---- terrain types ---------------------------------------------------------------------------------------------------
  std::vector<std::uint8_t> terrainType(static_cast<std::size_t>(cx) * cz, 0);
  {
    const GplyChunk& g = *s.gply;
    bool big = false;
    for (std::size_t i = 0; i < terrainType.size() && i < g.ids.size(); ++i) {
      if (g.ids[i] > 255) big = true;
      terrainType[i] = static_cast<std::uint8_t>(g.ids[i] & 0xFF);
    }
    if (big) {
      err = "GPLY surface ids above 255 cannot become Classic terrain types";
      return false;
    }
    if (!g.legacyTerrainIds) notes.push_back("GPLY ids are used as Classic terrain type codes (legacyTerrainIds was 0)");
  }

  // ---- lighting, sky -----------------------------------------------------------------------------------------------------
  float light[23] = {1.5f, 0.4f, 0.8f, 0.4f, 0.25f, 0.25f, 0.3f, 1.0f, 0.95f, 0.85f, 0.3f, 0.3f, 0.35f, 0.0f, 0.0f, 0.0f,
                     0.0f, 0.08f, 0.7f, 0.75f, 0.85f, 1000.0f, 1500.0f};
  std::string skycube = "/textures/environment/defaultskycube.dds";
  if (map.lite) {
    const LiteChunk& l = *map.lite;
    light[0] = l.sunIntensity;
    light[1] = l.sunDir[0]; light[2] = l.sunDir[1]; light[3] = l.sunDir[2];
    const float ai = l.ambientIntensity;
    Vec3 amb = l.ambient;
    if (l.ambientMode == 1) {
      amb = {(l.ambient[0] + l.ground[0]) * 0.5f, (l.ambient[1] + l.ground[1]) * 0.5f, (l.ambient[2] + l.ground[2]) * 0.5f};
    } else if (l.ambientMode == 2) {
      // SH2 L0 term carries the average colour (Y00 = 0.282095); the directional part cannot be expressed in Classic.
      amb = {l.sh[0] * 0.282095f, l.sh[1] * 0.282095f, l.sh[2] * 0.282095f};
      notes.push_back("ambient SH2 reduced to its average colour");
    }
    light[4] = amb[0] * ai; light[5] = amb[1] * ai; light[6] = amb[2] * ai;
    light[7] = l.sunColor[0]; light[8] = l.sunColor[1]; light[9] = l.sunColor[2];
    light[10] = l.shadowFill[0]; light[11] = l.shadowFill[1]; light[12] = l.shadowFill[2];
    light[17] = l.bloomIntensity;
    light[18] = l.fogColor[0]; light[19] = l.fogColor[1]; light[20] = l.fogColor[2];
    switch (l.fogMode) {
    case 0: light[21] = 100000.0f; light[22] = 100001.0f; break;
    case 1: light[21] = l.fogStart; light[22] = l.fogEnd; break;
    default: {
      const float d = l.fogDensity > 1e-6f ? l.fogDensity : 1e-6f;
      light[21] = 0.0f;
      light[22] = 4.6f / d; // distance at which exponential fog reaches 99%
      notes.push_back("exponential fog approximated by linear fog");
    }
    }
    if (l.hasMoon) notes.push_back("moon light ignored");
    if (l.toneMap != 0 || l.exposureEV != 0.0f || !l.lut.empty()) notes.push_back("tone map, exposure and LUT ignored");
  }
  if (map.atmo) {
    if (map.atmo->skyModel == 0 && !map.atmo->cubemap.empty()) skycube = map.atmo->cubemap;
    else if (map.atmo->skyModel != 0) notes.push_back("procedural / HDRI sky replaced by the default sky cube");
    if (map.atmo->cloudMode != 0) notes.push_back("clouds ignored");
  }
  for (float& f : light) {
    if (!std::isfinite(f)) f = 0.0f;
  }

  // ---- water ----------------------------------------------------------------------------------------------------------
  bool waterOn = false;
  float waterLevel = 0.0f;
  for (const WbodBody& b : s.wbod->bodies) {
    if (b.extentKind == 0 && b.level > -1.0e5f) {
      if (waterOn) {
        notes.push_back("more than one global water body: only the first is used");
        break;
      }
      waterOn = true;
      waterLevel = b.level;
    } else if (b.extentKind != 0) {
      notes.push_back("water body '" + b.name + "' has a mask / polygon extent: not representable in Classic, ignored");
    }
  }

  // ---- strata from MATL + SPLT ------------------------------------------------------------------------------------------
  const std::uint32_t mw = std::max<std::uint32_t>(1, cx / 2), mh = std::max<std::uint32_t>(1, cz / 2);
  std::vector<std::uint8_t> maskLow(static_cast<std::size_t>(mw) * mh * 4, 0), maskHigh(maskLow.size(), 0);
  Slots slots;
  std::string albedoPath[10], normalPath[9];
  float albedoScale[10], normalScale[9];
  for (float& f : albedoScale) f = 4.0f;
  for (float& f : normalScale) f = 4.0f;
  if (map.matl && !map.matl->material.empty()) {
    const MatlChunk& matl = *map.matl;
    // Per-material weight planes sampled at the mask resolution: weight[slot][texel].
    std::vector<std::vector<float>> weight;
    std::vector<int> slotMaterialId;
    auto sampleIndex = [&](std::uint32_t tx, std::uint32_t ty, std::uint32_t w, std::uint32_t h) {
      const std::uint32_t x = std::min<std::uint32_t>(w - 1, static_cast<std::uint32_t>((tx + 0.5) * w / mw));
      const std::uint32_t y = std::min<std::uint32_t>(h - 1, static_cast<std::uint32_t>((ty + 0.5) * h / mh));
      return static_cast<std::size_t>(y) * w + x;
    };
    if (map.splt && map.splt->mode == 1) {
      const SpltChunk& sp = *map.splt;
      const std::size_t layers = std::min<std::size_t>(sp.planes.size(), 9);
      if (sp.planes.size() > 9) notes.push_back("more than 9 splat layers: the extra layers were dropped");
      weight.assign(layers, std::vector<float>(static_cast<std::size_t>(mw) * mh, 0.0f));
      for (std::size_t l = 0; l < layers; ++l) {
        slotMaterialId.push_back(sp.materialIds[l]);
        for (std::uint32_t ty = 0; ty < mh; ++ty) {
          for (std::uint32_t tx = 0; tx < mw; ++tx) {
            weight[l][static_cast<std::size_t>(ty) * mw + tx] =
              sp.planes[l][sampleIndex(tx, ty, sp.width, sp.height)] / 255.0f;
          }
        }
      }
    } else if (map.splt && map.splt->mode == 0) {
      const SpltChunk& sp = *map.splt;
      // Pick the 9 heaviest materials; the rest folds into the base layer.
      std::map<int, double> total;
      const std::size_t texels = static_cast<std::size_t>(sp.width) * sp.height;
      for (std::size_t t = 0; t < texels; ++t) {
        for (int k = 0; k < 4; ++k) total[sp.indices[t * 4 + k]] += sp.weights[t * 4 + k];
      }
      std::vector<std::pair<double, int>> order;
      for (const auto& kv : total) order.push_back({-kv.second, kv.first});
      std::sort(order.begin(), order.end());
      if (order.size() > 9) notes.push_back("more than 9 materials in the splat map: the lightest were folded into the base layer");
      std::map<int, int> slotOf;
      for (std::size_t i = 0; i < order.size() && i < 9; ++i) {
        slotOf[order[i].second] = static_cast<int>(i);
        slotMaterialId.push_back(order[i].second);
      }
      weight.assign(slotMaterialId.size(), std::vector<float>(static_cast<std::size_t>(mw) * mh, 0.0f));
      for (std::uint32_t ty = 0; ty < mh; ++ty) {
        for (std::uint32_t tx = 0; tx < mw; ++tx) {
          const std::size_t t = sampleIndex(tx, ty, sp.width, sp.height);
          for (int k = 0; k < 4; ++k) {
            auto it = slotOf.find(sp.indices[t * 4 + k]);
            const int slot = it == slotOf.end() ? 0 : it->second;
            weight[static_cast<std::size_t>(slot)][static_cast<std::size_t>(ty) * mw + tx] += sp.weights[t * 4 + k] / 255.0f;
          }
        }
      }
    } else {
      slotMaterialId.push_back(matl.material[0].id);
    }
    for (std::size_t i = 0; i < slotMaterialId.size() && i < 9; ++i) {
      const MatlMaterial* m = FindMaterial(matl, slotMaterialId[i]);
      if (!m) {
        notes.push_back("splat refers to material id " + std::to_string(slotMaterialId[i]) + " that MATL does not define");
        continue;
      }
      albedoPath[i] = m->albedo;
      normalPath[i] = m->normal;
      albedoScale[i] = normalScale[i] = m->tileSize > 0.0f ? m->tileSize : 4.0f;
      slots.material[i] = static_cast<int>(i);
      if (m->flags & 0x1) notes.push_back("material '" + m->name + "': triplanar ignored");
      if (m->flags & (0x4 | 0x8)) notes.push_back("material '" + m->name + "': parallax / height blending ignored");
    }
    // Unused mask layers (mask 0 = invisible) get the base layer's textures: the engine warns about every empty path.
    for (int i = 1; i < 9; ++i) {
      if (albedoPath[i].empty()) { albedoPath[i] = albedoPath[0]; albedoScale[i] = albedoScale[0]; }
      if (normalPath[i].empty()) { normalPath[i] = normalPath[0]; normalScale[i] = normalScale[0]; }
    }
    notes.push_back("materials reduced to the stock layer model (ORM / height textures unused)");
    // Sequential alpha so that Classic's successive lerps reproduce the weights: a_k = w_k / (w_0 + .. + w_k).
    const std::size_t layers = weight.size();
    for (std::size_t t = 0; t < static_cast<std::size_t>(mw) * mh; ++t) {
      float sum = layers ? weight[0][t] : 0.0f;
      for (std::size_t k = 1; k < layers && k < 9; ++k) {
        sum += weight[k][t];
        const float a = sum > 1e-6f ? Clamp01(weight[k][t] / sum) : 0.0f;
        const std::uint8_t v = static_cast<std::uint8_t>(a * 255.0f + 0.5f);
        // Layer k (1..8): masks are BGRA bytes, R = layer 1, G = 2, B = 3, A = 4 (then the same in the high mask).
        std::vector<std::uint8_t>& mk = k <= 4 ? maskLow : maskHigh;
        const std::size_t kk = (k - 1) % 4;
        static const int channelByte[4] = {2, 1, 0, 3};
        mk[t * 4 + channelByte[kk]] = v;
      }
    }
  } else {
    notes.push_back("no MATL: the map is drawn with the engine's empty strata");
  }

  // ---- write ---------------------------------------------------------------------------------------------------------
  ByteWriter w;
  w.u32(kClassicMagic);
  w.u32(2);
  w.u32(kPreviewMagic);
  w.u32(2);
  w.f32(static_cast<float>(cx));
  w.f32(static_cast<float>(cz));
  w.u16(0); // preview name terminator
  w.u32(0); // metadata entries
  {
    std::vector<std::uint8_t> preview;
    if (map.prev && map.prev->kind == 1 && map.prev->data.size >= 128 && map.prev->data.data &&
        std::memcmp(map.prev->data.data, "DDS ", 4) == 0) {
      preview.assign(map.prev->data.data, map.prev->data.data + map.prev->data.size);
    } else {
      if (map.prev) notes.push_back("PNG preview replaced by a flat image (the engine reads DDS)");
      std::vector<std::uint8_t> px(256 * 256 * 4);
      for (std::size_t i = 0; i < px.size(); i += 4) {
        px[i] = 0x40; px[i + 1] = 0x40; px[i + 2] = 0x40; px[i + 3] = 0xFF;
      }
      preview = MakeArgbDds(256, 256, px.data());
    }
    WriteBlob(w, preview);
  }
  w.i32(kClassicMinor);
  w.i32(static_cast<std::int32_t>(cx));
  w.i32(static_cast<std::int32_t>(cz));
  w.f32(1.0f / 128.0f);
  for (std::uint16_t v : heights) w.u16(v);
  w.u8(0);
  CStr(w, "TTerrain");
  CStr(w, "/textures/environment/defaultbackground.dds");
  CStr(w, skycube);
  w.i32(1);
  CStr(w, "<default>");
  CStr(w, "/textures/environment/defaultenvcube.dds");
  for (float f : light) w.f32(f);
  // water: present byte, elevation / deep / abyss, then CWaterShaderProperties::Load's 20 floats
  w.u8(waterOn ? 1 : 0);
  w.f32(waterOn ? waterLevel : 0.0f);
  w.f32(waterOn ? waterLevel - 5.0f : 0.0f);
  w.f32(waterOn ? waterLevel - 15.0f : 0.0f);
  {
    float sunDir[3] = {0.1f, -0.967f, 0.253f};
    float sunCol[3] = {1.2f, 0.7f, 0.5f};
    for (int pass = 0; pass < 2; ++pass) {
      float* v = pass == 0 ? sunDir : sunCol;
      const float len = std::sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
      for (int i = 0; i < 3; ++i) v[i] /= len;
    }
    const float head[12] = {0.0f, 0.7f, 1.5f, 0.064f, 0.119f, 0.375f, 0.15f, 1.5f, 0.5f, 1.5f, 50.0f, 10.0f};
    for (float f : head) w.f32(f);
    for (float f : sunDir) w.f32(f);
    for (float f : sunCol) w.f32(f);
    w.f32(5.0f);
    w.f32(0.1f);
    CStr(w, "/textures/engine/waterCubemap.dds");
    CStr(w, "/textures/engine/waterramp.dds");
    const float repeat[4] = {0.0009f, 0.009f, 0.05f, 0.5f};
    for (float f : repeat) w.f32(f);
    const float mv[4][2] = {{0.5f, -0.95f}, {0.05f, -0.095f}, {0.01f, 0.03f}, {0.0005f, 0.0009f}};
    for (int i = 0; i < 4; ++i) {
      w.f32(mv[i][0]);
      w.f32(mv[i][1]);
      CStr(w, "/textures/engine/waves.dds");
    }
  }
  w.i32(0); // wave generators
  // topographic samples + hypsometric colours (version >= 0x38)
  w.i32(20);
  w.u32(0xFF0E3EFFU); w.u32(0xFF215CFFU); w.u32(0xFF4785FFU); w.u32(0xFF4C9D32U); w.u32(0xFFFFFFFFU);
  // strata: 10 albedo, then 9 normal (path + scale)
  for (int i = 0; i < 10; ++i) {
    CStr(w, albedoPath[i]);
    w.f32(albedoScale[i]);
  }
  for (int i = 0; i < 9; ++i) {
    CStr(w, normalPath[i]);
    w.f32(normalScale[i]);
  }
  // decal manager: two counters, decals, groups
  w.i32(0);
  w.i32(0);
  {
    std::vector<ByteWriter> recs;
    if (options.exportDecals && map.decl) {
      for (const DeclDecal& d : map.decl->decal) {
        int type = 0;
        switch (d.type) {
        case 0: type = 1; break; // albedo
        case 1: type = 2; break; // normals
        case 2: type = 6; break; // glow
        default: break;
        }
        if (type == 0) continue;
        ByteWriter r;
        r.i32(static_cast<std::int32_t>(recs.size()));
        r.i32(type);
        const std::string& t0 = d.tex0 < map.decl->textures.size() ? map.decl->textures[d.tex0] : std::string();
        const std::string* t1 = d.tex1 < map.decl->textures.size() ? &map.decl->textures[d.tex1] : nullptr;
        r.i32(t1 ? 2 : 1);
        r.i32(static_cast<std::int32_t>(t0.size()));
        r.bytes(reinterpret_cast<const std::uint8_t*>(t0.data()), t0.size());
        if (t1) {
          r.i32(static_cast<std::int32_t>(t1->size()));
          r.bytes(reinterpret_cast<const std::uint8_t*>(t1->data()), t1->size());
        }
        r.f32(d.size[0]); r.f32(d.size[1]); r.f32(d.size[2]);
        r.f32(d.pos[0]); r.f32(d.pos[1]); r.f32(d.pos[2]);
        const float qx = d.rot[0], qy = d.rot[1], qz = d.rot[2], qw = d.rot[3];
        const float yaw = std::atan2(2.0f * (qw * qy + qx * qz), 1.0f - 2.0f * (qy * qy + qx * qx));
        r.f32(0.0f); r.f32(yaw); r.f32(0.0f);
        r.f32(d.lodMax); r.f32(d.lodMin);
        r.i32(-1);
        recs.push_back(std::move(r));
      }
      notes.push_back("decals exported with yaw only (rotation convention unverified in game)");
    } else if (map.decl && !map.decl->decal.empty()) {
      notes.push_back("decals not exported (exportDecals is off)");
    }
    w.i32(static_cast<std::int32_t>(recs.size()));
    for (const ByteWriter& r : recs) w.bytes(r.buf.data(), r.buf.size());
    w.i32(0);
  }
  // legacy skip list: width, height, one record (the normal map, recomputed by the engine)
  w.i32(static_cast<std::int32_t>(cx));
  w.i32(static_cast<std::int32_t>(cz));
  w.i32(1);
  WriteBlob(w, MakeDxt5FlatDds(4, 4, 0, 128, 0, 128));
  WriteBlob(w, MakeArgbDds(mw, mh, maskLow.data()));
  WriteBlob(w, MakeArgbDds(mw, mh, maskHigh.data()));
  w.i32(1);
  WriteBlob(w, MakeDxt5FlatDds(mw, mh, 0, 0, 0, 0));
  {
    const std::size_t half = static_cast<std::size_t>(mw) * mh;
    w.buf.resize(w.buf.size() + half, 0x00);   // foam
    w.buf.resize(w.buf.size() + half, 0xFF);   // flatness
    w.buf.resize(w.buf.size() + half, 0x7F);   // depth bias
  }
  w.bytes(terrainType.data(), terrainType.size());
  // props
  if (s.prop) {
    w.i32(static_cast<std::int32_t>(s.prop->props.size()));
    for (const PropItem& p : s.prop->props) {
      CStr(w, p.blueprintIndex < s.prop->blueprints.size() ? s.prop->blueprints[p.blueprintIndex] : std::string());
      w.f32(p.pos[0]); w.f32(p.pos[1]); w.f32(p.pos[2]);
      float axes[9];
      QuatToAxes(p.rot, axes);
      for (float f : axes) w.f32(f);
      w.f32(p.scale[0]); w.f32(p.scale[1]); w.f32(p.scale[2]);
    }
  } else {
    w.i32(0);
  }

  if (s.levl) notes.push_back("LEVL decks are not part of Classic: dropped");
  if (s.play && (s.play->x0 != 0 || s.play->z0 != 0 || s.play->x1 != static_cast<std::int32_t>(cx) ||
                 s.play->z1 != static_cast<std::int32_t>(cz))) {
    notes.push_back("playable area is set by the scenario in Classic: PLAY is not written into the .scmap");
  }
  out.bytes = std::move(w.buf);
  return true;
}

} // namespace moho::mapformat
