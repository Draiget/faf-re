// Canonical text dump of an open container (docs/mapformat/CONTAINER.md section 8).
#pragma once

#include <string>

#include "moho/sim/mapformat/MapContainer.h"

namespace moho::mapformat {

/// Produces the conformance dump. Layout, `\n` line endings:
///
///   file.container = 3
///   file.revision = 1
///   file.flags = 0x00000000                 (8 hex digits, the header flags)
///   file.required = 0x0000000000000003      (16 hex digits)
///   file.optional = 0x00000000000001fa
///   file.mapGuid = <32 hex>
///   file.simHash = <64 hex>                 (as stored in the header; use VerifySimHash to check it)
///   chunk GRID inst=0 ver=1 flags=0x0003 raw=36     one per directory entry, directory order, followed by the
///   GRID.cellsX = 1024                              lines of the chunk family dumpers (ChunkFamilies.h)
///   ...
///   chunk XXXX inst=0 skipped                       no family knows the chunk and it is not REQUIRED
///   chunk ZZZZ inst=0 error "message"               decode error in a chunk that is neither REQUIRED nor SIM
///
/// A chunk that fails (CRC, inflate, decode, not understood) and is REQUIRED or SIM is fatal: the result is empty and
/// `*err` (optional) says which chunk and why. GRID and WRLD are decoded in a first pass so that `ChunkCtx::cellsX/cellsZ` are known
/// by chunks that sort before it ('AREA', 'DECL', ...). The decoded sizes of one dump are budgeted with
/// Limits::maxTotalRaw.
std::string DumpText(const MapContainer& container, std::string* err);

} // namespace moho::mapformat
