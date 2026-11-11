// A whole container-3/4 map decoded into typed chunks: what the engine keeps after a load, and what ClassicExport reads.
// Engine-independent (standard library only).
#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <vector>

#include "moho/sim/mapformat/MapContainer.h"
#include "moho/sim/mapformat/RenderChunks.h"
#include "moho/sim/mapformat/SimChunks.h"

namespace moho::mapformat {

struct LoadOptions
{
  /// Feature bits the caller can honour (the file is refused when it requires more). Default: what the engine honours today.
  std::uint64_t supportedFeatures = EngineSupportedFeaturesMask();
  Limits limits;
  /// Lenient mode drops a malformed render / metadata chunk with a warning; sim chunks are always strict.
  bool lenientRender = true;
};

/// Owns the file bytes and everything that points into them. Not copyable; movable (the byte vector's heap block does not
/// move with the object).
class ExtendedMap
{
public:
  ExtendedMap() = default;
  ExtendedMap(const ExtendedMap&) = delete;
  ExtendedMap& operator=(const ExtendedMap&) = delete;
  ExtendedMap(ExtendedMap&&) = default;
  ExtendedMap& operator=(ExtendedMap&&) = default;

  std::vector<std::uint8_t> file;
  MapContainer container;
  SMapFormatInfo info;

  MapSimData sim; ///< GRID HGHT PLAY GPLY WBOD + optional sim chunks (container 4: WRLD ...)

  // Metadata and the render chunks the engine consumes today. The rest stays in the container, decoded on demand.
  std::optional<MetaChunk> meta;
  std::optional<PrevChunk> prev;
  std::optional<LiteChunk> lite;
  std::optional<MatlChunk> matl;
  std::optional<SpltChunk> splt;
  std::optional<DeclChunk> decl;
  std::optional<AtmoChunk> atmo;

  std::vector<std::string> warnings; ///< dropped chunks, approximations: shown in the log

  /// Raw payloads that Blob views in the chunks above point into.
  std::deque<std::vector<std::uint8_t>> keep;
};

/// Opens `file` (takes the bytes), verifies the sim hash, decodes and cross-checks the sim chunks, decodes the render chunks
/// listed above. Returns false with a one-line `err` that names the chunk or rule.
bool LoadExtendedMap(std::vector<std::uint8_t>&& file, const LoadOptions& options, ExtendedMap& out, std::string& err);

} // namespace moho::mapformat
