#include "moho/sim/mapformat/ExtendedMap.h"

#include <cstring>

#include "moho/sim/mapformat/FeatureBits.h"

namespace moho::mapformat {

namespace {

struct Loader
{
  ExtendedMap& m;
  const LoadOptions& opt;
  ChunkCtx ctx;
  std::uint64_t budget = 0;

  Loader(ExtendedMap& map, const LoadOptions& o) : m(map), opt(o) {} // budget counts decoded bytes up from 0

  /// Reads the chunk payload into `raw`. Returns 0 = absent, 1 = ok, -1 = error (err set).
  int Fetch(const char* id, std::uint32_t instance, std::vector<std::uint8_t>& raw, std::uint16_t& version,
            std::string& err)
  {
    const ChunkEntry* e = nullptr;
    if (!m.container.FindChunk(id, instance, &e)) return 0;
    const Result r = m.container.ReadChunk(*e, raw, &budget);
    if (!r.ok()) {
      err = std::string(id) + ": " + r.message;
      return -1;
    }
    version = e->version;
    return 1;
  }

  /// Decodes a required or optional SIM chunk with `fn`.
  template <typename T, typename Fn>
  bool Sim(const char* id, bool required, std::optional<T>& dst, Fn fn, std::string& err)
  {
    std::vector<std::uint8_t> raw;
    std::uint16_t version = 0;
    const int f = Fetch(id, 0, raw, version, err);
    if (f < 0) return false;
    if (f == 0) {
      if (required) {
        err = std::string(id) + ": required chunk is missing";
        return false;
      }
      return true;
    }
    if (version != 1) {
      err = std::string(id) + ": unsupported chunk version " + std::to_string(version);
      return false;
    }
    T value;
    std::string e;
    if (!fn(raw.data(), raw.size(), ctx, value, e)) {
      err = e.empty() ? std::string(id) + ": malformed" : e;
      return false;
    }
    dst = std::move(value);
    return true;
  }

  /// Optional render / metadata chunk: failure is a warning in lenient mode.
  template <typename T, typename Fn>
  bool Render(const char* id, std::optional<T>& dst, Fn fn, bool keepRaw, std::string& err)
  {
    std::vector<std::uint8_t> raw;
    std::uint16_t version = 0;
    std::string e;
    const int f = Fetch(id, 0, raw, version, e);
    if (f == 0) return true;
    T value;
    bool ok = f > 0 && version == 1 && fn(raw.data(), raw.size(), ctx, value, e);
    if (f > 0 && version != 1 && e.empty()) e = std::string(id) + ": unsupported chunk version " + std::to_string(version);
    if (!ok) {
      if (!opt.lenientRender) {
        err = e.empty() ? std::string(id) + ": malformed" : e;
        return false;
      }
      m.warnings.push_back("dropped " + (e.empty() ? std::string(id) + ": malformed" : e));
      return true;
    }
    if (keepRaw) {
      m.keep.push_back(std::move(raw));
      // Re-decode against the kept buffer so Blob views point at memory that stays alive.
      T again;
      std::string e2;
      if (!fn(m.keep.back().data(), m.keep.back().size(), ctx, again, e2)) {
        err = e2;
        return false;
      }
      dst = std::move(again);
    } else {
      dst = std::move(value);
    }
    return true;
  }
};

} // namespace

bool LoadExtendedMap(std::vector<std::uint8_t>&& file, const LoadOptions& options, ExtendedMap& out, std::string& err)
{
  out.file = std::move(file);
  OpenOptions oo;
  oo.limits = options.limits;
  oo.supportedFeatures = options.supportedFeatures;
  const Result r = MapContainer::Open(out.file.data(), out.file.size(), oo, out.container);
  if (!r.ok()) {
    err = r.message;
    return false;
  }
  out.info = out.container.FormatInfo();
  if (!out.info.IsChunked()) {
    err = "not a container 3 or 4 map";
    return false;
  }
  const Result h = out.container.VerifySimHash();
  if (!h.ok()) {
    err = h.message;
    return false;
  }

  Loader L(out, options);
  L.ctx.container = static_cast<int>(out.info.container);
  out.sim.container = static_cast<int>(out.info.container);
  MapSimData& s = out.sim;

  // GRID first: every plane-sized chunk needs the dimensions.
  if (!L.Sim<GridChunk>("GRID", true, s.grid, DecodeGrid, err)) return false;
  L.ctx.cellsX = s.grid->cellsX;
  L.ctx.cellsZ = s.grid->cellsZ;
  if (!L.Sim<HghtChunk>("HGHT", true, s.hght, DecodeHght, err)) return false;
  if (!L.Sim<PlayChunk>("PLAY", true, s.play, DecodePlay, err)) return false;
  if (!L.Sim<GplyChunk>("GPLY", true, s.gply, DecodeGply, err)) return false;
  if (!L.Sim<WbodChunk>("WBOD", true, s.wbod, DecodeWbod, err)) return false;
  if (!L.Sim<LevlChunk>("LEVL", false, s.levl, DecodeLevl, err)) return false;
  if (!L.Sim<MrkrChunk>("MRKR", false, s.mrkr, DecodeMrkr, err)) return false;
  if (!L.Sim<AreaChunk>("AREA", false, s.area, DecodeArea, err)) return false;
  if (!L.Sim<PropChunk>("PROP", false, s.prop, DecodeProp, err)) return false;
  if (!L.Sim<HintChunk>("HINT", false, s.hint, DecodeHint, err)) return false;
  if (out.info.container == 4) {
    if (!L.Sim<WrldChunk>("WRLD", true, s.wrld, DecodeWrld, err)) return false;
    if (!L.Sim<SlyrChunk>("SLYR", false, s.slyr, DecodeSlyr, err)) return false;
    if (!L.Sim<NavsChunk>("NAVS", false, s.navs, DecodeNavs, err)) return false;
    if (!L.Sim<VolsChunk>("VOLS", false, s.vols, DecodeVols, err)) return false;
    for (const ChunkEntry& e : out.container.entries()) {
      if (std::memcmp(e.id, "COLL", 4) != 0) continue;
      std::vector<std::uint8_t> raw;
      const Result rr = out.container.ReadChunk(e, raw, &L.budget);
      if (!rr.ok()) {
        err = "COLL: " + rr.message;
        return false;
      }
      MapSimData::CollEntry entry;
      entry.instance = e.instance;
      std::string e2;
      if (e.version != 1 || !DecodeColl(raw.data(), raw.size(), L.ctx, entry.chunk, e2)) {
        err = e2.empty() ? "COLL: unsupported or malformed" : e2;
        return false;
      }
      s.coll.push_back(std::move(entry));
    }
  }

  std::string verr;
  if (!ValidateSimData(s, verr)) {
    err = verr;
    return false;
  }
  // The writer must declare every sim feature the data uses, or an older exe would misplay the map silently.
  std::uint64_t derived = RequiredFeatureMaskFor(s);
  {
    const ChunkEntry* cidx = nullptr;
    if (out.container.FindChunk("CIDX", 0, &cidx)) derived |= kFeat_WorldCells; // a cell index means streamed cells
  }
  if ((derived & ~out.info.requiredFeatures) != 0) {
    err = "the map uses sim features it does not declare as required (derived 0x" + TextDump::Hex(derived, 16) +
          ", declared 0x" + TextDump::Hex(out.info.requiredFeatures, 16) + ")";
    return false;
  }

  // Metadata and the render chunks the engine uses now. Lenient: a bad one is dropped with a warning.
  if (!L.Render<MetaChunk>("META", out.meta, DecodeMeta, false, err)) return false;
  if (!L.Render<PrevChunk>("PREV", out.prev, DecodePrev, true, err)) return false;
  if (!L.Render<LiteChunk>("LITE", out.lite, DecodeLite, false, err)) return false;
  if (!L.Render<MatlChunk>("MATL", out.matl, DecodeMatl, false, err)) return false;
  if (!L.Render<SpltChunk>("SPLT", out.splt, DecodeSplt, false, err)) return false;
  if (!L.Render<DeclChunk>("DECL", out.decl, DecodeDecl, false, err)) return false;
  if (!L.Render<AtmoChunk>("ATMO", out.atmo, DecodeAtmo, false, err)) return false;
  return true;
}

} // namespace moho::mapformat
