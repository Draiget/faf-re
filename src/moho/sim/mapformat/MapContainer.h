// Reader for the chunked map containers 3 (Extended) and 4 (Full3D): docs/mapformat/CONTAINER.md.
// Works on a file that is already in memory. Every offset and size is validated before use; nothing is allocated from a
// file-supplied size without a limit. Standard library only. No exceptions are thrown on bad input.
//
// Usage:
//   MapContainer c;
//   Result r = MapContainer::Open(bytes, size, OpenOptions(), c);     // header + directory + ranges
//   if (!r) -> r.code / r.message
//   const ChunkEntry* e; if (c.FindChunk("GRID", 0, &e)) { std::vector<uint8_t> raw; c.ReadChunk(*e, raw); }
//   c.VerifySimHash();                                                // optional, decodes every SIM chunk
// The container keeps a pointer into `bytes`: the buffer must outlive it.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "moho/sim/mapformat/MapFormat.h"

namespace moho::mapformat {

constexpr std::uint32_t kMapMagic = 0x1A70614DU;
constexpr std::uint16_t kContainerRevision = 1; ///< highest revision this reader knows
constexpr std::uint16_t kHeaderSize = 128;
constexpr std::size_t kDirEntrySize = 48;
constexpr std::uint32_t kFileHasSignature = 1; ///< header flags bit0

/// Directory entry flags (CONTAINER.md 1.2).
enum ChunkFlags : std::uint16_t
{
  kChunkRequired = 1,
  kChunkSim = 2,
  kChunkDerived = 4,
  kChunkDeflate = 8,
  kChunkKnownFlags = 15,
};

/// Reader hard caps (CONTAINER.md section 6). The engine may tighten or loosen them.
struct Limits
{
  std::uint64_t maxFileSize = 4ULL << 30;
  std::uint32_t maxDirEntries = 4096;
  std::uint64_t maxChunkRaw = 1ULL << 30;     ///< raw (decompressed) size of one chunk
  std::uint64_t maxTotalRaw = 3ULL << 30;     ///< sum of raw sizes decoded through one `budget` (see ReadChunk)
  std::uint64_t maxInflateRatio = 1032;       ///< rawSize <= storedSize * ratio for compressed chunks
  std::uint32_t maxCellsPerAxis = 65536;      ///< not used by the container: for the GRID decoder / engine
  std::uint64_t maxSampleCount = 1ULL << 30;  ///< not used by the container: for the GRID decoder / engine
  std::uint32_t maxStringLength = 4096;       ///< not used by the container: chunk decoders use ByteReader::str's default
};

enum class ContainerError
{
  Ok = 0,
  TooSmall,             ///< shorter than the 128 byte header
  BadMagic,
  UnsupportedContainer, ///< container is not 3 or 4
  BadRevision,
  BadHeader,            ///< headerSize, reserved fields, flags
  FileSizeMismatch,     ///< header.fileSize != buffer size (truncation or padding)
  HeaderCrc,
  UnsupportedFeature,   ///< requiredFeatures has bits outside OpenOptions::supportedFeatures
  LimitExceeded,
  BadDirectory,         ///< dirOffset / dirCount out of range
  DirectoryCrc,
  BadChunkEntry,        ///< id, flags, alignment, ordering, duplicate (id, instance)
  ChunkOutOfRange,      ///< outside [headerSize, dirOffset)
  ChunkOverlap,
  UnknownRequiredChunk, ///< REQUIRED chunk the caller's isKnownChunk rejected
  ChunkCrc,
  InflateFailed,
  RatioExceeded,        ///< rawSize beyond maxInflateRatio * storedSize
  OutOfMemory,
  SimHashMismatch,
};

const char* ContainerErrorName(ContainerError e);

struct Result
{
  ContainerError code = ContainerError::Ok;
  std::string message; ///< human readable, names the chunk / field when there is one
  bool ok() const { return code == ContainerError::Ok; }
  explicit operator bool() const { return ok(); }
};

struct Header
{
  std::uint32_t container = 0;
  std::uint16_t revision = 0;
  std::uint16_t headerSize = 0;
  std::uint32_t flags = 0;
  std::uint64_t fileSize = 0;
  std::uint64_t dirOffset = 0;
  std::uint32_t dirCount = 0;
  std::uint32_t dirCrc32 = 0;
  std::uint64_t requiredFeatures = 0;
  std::uint64_t optionalFeatures = 0;
  std::array<std::uint8_t, 16> mapGuid{};
  std::array<std::uint8_t, 32> simHash{};
};

struct ChunkEntry
{
  char id[4] = {0, 0, 0, 0};
  std::uint16_t version = 0;
  std::uint16_t flags = 0;
  std::uint32_t instance = 0;
  std::uint32_t crc32 = 0;
  std::uint64_t offset = 0;
  std::uint64_t storedSize = 0;
  std::uint64_t rawSize = 0;

  std::string Id() const { return std::string(id, 4); }
  bool required() const { return (flags & kChunkRequired) != 0; }
  bool sim() const { return (flags & kChunkSim) != 0; }
  bool derived() const { return (flags & kChunkDerived) != 0; }
  bool deflated() const { return (flags & kChunkDeflate) != 0; }
};

struct OpenOptions
{
  Limits limits;
  /// Feature bits the caller implements; a `requiredFeatures` bit outside it refuses the file (UnsupportedFeature, the
  /// message lists the names). Default: what the engine supports today. Tools pass ~0ULL to open anything.
  std::uint64_t supportedFeatures = SupportedFeaturesMask();
  /// Optional: does the caller understand this chunk id at this version? A chunk flagged REQUIRED for which it returns
  /// false refuses the file (UnknownRequiredChunk). Optional chunks are never refused here. nullptr = accept all.
  bool (*isKnownChunk)(const char id[4], std::uint16_t version) = nullptr;
};

class MapContainer
{
public:
  /// Parses and validates header, directory and chunk ranges, in the CONTAINER.md section 6 order: magic / container /
  /// size / header CRC, required features, directory bounds + CRC, then per entry: id, flags, order and uniqueness of
  /// (id, instance), 16-byte alignment, range inside [headerSize, dirOffset), non-overlap, size limits and the
  /// inflate ratio. Chunk payloads (CRC, inflate) are checked when read. On failure `out` is left untouched.
  static Result Open(const std::uint8_t* data, std::size_t size, const OpenOptions& options, MapContainer& out);

  bool valid() const { return data_ != nullptr; }
  const Header& header() const { return header_; }
  /// Directory order = ascending (id bytes, instance).
  const std::vector<ChunkEntry>& entries() const { return entries_; }
  const Limits& limits() const { return limits_; }
  const std::uint8_t* data() const { return data_; }
  std::size_t size() const { return size_; }

  /// Binary search on (id, instance); `id` points at 4 characters.
  bool FindChunk(const char* id, std::uint32_t instance, const ChunkEntry** out) const;

  /// Verifies the CRC of the stored bytes, inflates (declared rawSize, ratio cap, limits) and returns the raw bytes.
  /// `budget` (optional) accumulates the raw sizes decoded by one load: the call fails with LimitExceeded when
  /// *budget + rawSize would pass limits().maxTotalRaw (the engine passes one counter per load; nullptr = unchecked).
  Result ReadChunk(const ChunkEntry& entry, std::vector<std::uint8_t>& raw, std::uint64_t* budget = nullptr) const;

  /// simHash per CONTAINER.md section 5: SHA-256 over every SIM chunk in directory order of
  /// id(4) | version u16 | instance u32 | rawSize u64 | raw bytes. Decodes (and CRC-checks) each SIM chunk.
  Result ComputeSimHash(std::array<std::uint8_t, 32>& out) const;
  /// ComputeSimHash and compare to the header: SimHashMismatch (message shows both) when different.
  Result VerifySimHash() const;

  /// Format id, revision, feature masks and simHash from the header (Extended for container 3, Full3D for 4).
  SMapFormatInfo FormatInfo() const;

private:
  const std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  Header header_;
  std::vector<ChunkEntry> entries_;
  Limits limits_;
};

} // namespace moho::mapformat
