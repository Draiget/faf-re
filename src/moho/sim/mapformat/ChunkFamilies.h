// The three chunk families the text dump walks, in this order, until one does not answer NotMine:
//   DumpChunkSim     (SimChunks.h)      sim chunks of Extended and Full3D
//   DumpChunkRender  (RenderChunks.h)   render / metadata / derived chunks of Extended
//   DumpChunkWorld3D (World3DChunks.h)  Full3D render chunks (only container 4)
// Declared here (same signatures as in the family headers) so MapDump.cpp needs none of the family headers.
// Contract of every entry point: NotMine = id belongs to another family (nothing appended, `err` untouched);
// Ok = decoded, lines appended; Error = malformed / unsupported version, `err` says why (lines appended so far may be
// partial: callers dump into a scratch TextDump and keep it only on Ok).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "moho/sim/mapformat/MapFormatCommon.h"

namespace moho::mapformat {

DecodeStatus DumpChunkSim(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx,
                          TextDump& dump, std::string& err);
DecodeStatus DumpChunkRender(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx,
                             TextDump& dump, std::string& err);
DecodeStatus DumpChunkWorld3D(const std::string& id, std::uint16_t version, const std::uint8_t* data, std::size_t size, ChunkCtx& ctx,
                              TextDump& dump, std::string& err);

} // namespace moho::mapformat
