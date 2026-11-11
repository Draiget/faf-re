#include "moho/sim/mapformat/MapDump.h"

#include "moho/sim/mapformat/ChunkFamilies.h"
#include "moho/sim/mapformat/Hash.h"

namespace moho::mapformat {
namespace {

/// Runs the families in order. NotMine from all of them = nobody knows the chunk.
DecodeStatus RunFamilies(const ChunkEntry& e, const std::vector<std::uint8_t>& raw, ChunkCtx& ctx, TextDump& out, std::string& err)
{
  const std::string id = e.Id();
  const std::uint8_t* data = raw.data();
  const std::size_t size = raw.size();
  // A chunk version this reader does not know (0 or newer than 1) is treated like an unknown chunk: skipped, or refused
  // when it is REQUIRED (the reference dump prints `chunk ID inst=N skipped` for it).
  if (e.version != 1) return DecodeStatus::NotMine;
  DecodeStatus s = DumpChunkSim(id, e.version, data, size, ctx, out, err);
  if (s != DecodeStatus::NotMine) return s;
  s = DumpChunkRender(id, e.version, data, size, ctx, out, err);
  if (s != DecodeStatus::NotMine) return s;
  return DumpChunkWorld3D(id, e.version, data, size, ctx, out, err);
}

std::string ChunkRef(const ChunkEntry& e) { return "chunk " + e.Id() + " inst=" + std::to_string(e.instance); }

} // namespace

std::string DumpText(const MapContainer& c, std::string* err)
{
  if (err) err->clear();
  const Header& h = c.header();
  ChunkCtx ctx;
  ctx.container = static_cast<int>(h.container);
  ctx.strict = true;

  // Pass 1: GRID (and WRLD) give chunks that sort before them ("AREA", "CIDX", "DECL", ...) the sizes they validate against.
  for (const char* first : {"GRID", "WRLD"}) {
    const ChunkEntry* e = nullptr;
    std::vector<std::uint8_t> raw;
    if (c.FindChunk(first, 0, &e) && c.ReadChunk(*e, raw)) {
      TextDump scratch;
      std::string ignored;
      (void)DumpChunkSim(first, e->version, raw.data(), raw.size(), ctx, scratch, ignored); // errors reported in pass 2
    }
  }

  TextDump d;
  d.U("file.container", h.container);
  d.U("file.revision", h.revision);
  d.Raw("file.flags", "0x" + TextDump::Hex(h.flags, 8));
  d.Raw("file.required", "0x" + TextDump::Hex(h.requiredFeatures, 16));
  d.Raw("file.optional", "0x" + TextDump::Hex(h.optionalFeatures, 16));
  d.Raw("file.mapGuid", HexString(h.mapGuid.data(), h.mapGuid.size()));
  d.Raw("file.simHash", HexString(h.simHash.data(), h.simHash.size()));

  std::uint64_t budget = 0;
  std::vector<std::uint8_t> raw;
  for (const ChunkEntry& e : c.entries()) {
    enum { kOk, kSkipped, kFailed } state = kOk;
    std::string why;
    TextDump lines; // a failing family may have appended partial lines: keep them only on Ok

    const Result rr = c.ReadChunk(e, raw, &budget);
    if (!rr) {
      state = kFailed;
      why = rr.message;
    } else {
      switch (RunFamilies(e, raw, ctx, lines, why)) {
      case DecodeStatus::Ok: break;
      case DecodeStatus::Error: state = kFailed; break;
      case DecodeStatus::NotMine:
        if (e.required()) {
          state = kFailed;
          why = ChunkRef(e) + ": required chunk is not understood by this reader";
        } else {
          state = kSkipped;
        }
        break;
      }
    }

    if (state == kOk) {
      d.out += ChunkRef(e) + " ver=" + std::to_string(e.version) + " flags=0x" + TextDump::Hex(e.flags, 4) +
               " raw=" + std::to_string(e.rawSize) + '\n' + lines.out;
    } else if (state == kSkipped) {
      d.out += ChunkRef(e) + " skipped\n";
    } else if (e.required() || e.sim()) {
      if (err) *err = why.empty() ? ChunkRef(e) + ": failed" : why;
      return std::string();
    } else {
      d.out += ChunkRef(e) + " error " + TextDump::Quote(why) + '\n';
    }
  }
  return d.out;
}

} // namespace moho::mapformat
