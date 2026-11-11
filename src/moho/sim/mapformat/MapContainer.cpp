#include "moho/sim/mapformat/MapContainer.h"

#include <algorithm>
#include <cstring>
#include <new>

#include "moho/sim/mapformat/Hash.h"
#include "moho/sim/mapformat/Inflate.h"
#include "moho/sim/mapformat/MapFormatCommon.h"

namespace moho::mapformat {
namespace {

Result Fail(ContainerError code, std::string message)
{
  Result r;
  r.code = code;
  r.message = std::move(message);
  return r;
}

std::string IdText(const char id[4])
{
  std::string s;
  for (int i = 0; i < 4; ++i) {
    const unsigned char c = static_cast<unsigned char>(id[i]);
    s.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '?');
  }
  return s;
}

std::string ChunkName(const ChunkEntry& e) { return "chunk '" + IdText(e.id) + "' instance " + std::to_string(e.instance); }

std::string Hex32(std::uint32_t v) { return "0x" + TextDump::Hex(v, 8); }

// (id bytes, instance) ordering of the directory.
int CompareKey(const ChunkEntry& a, const ChunkEntry& b)
{
  const int c = std::memcmp(a.id, b.id, 4);
  if (c != 0) return c < 0 ? -1 : 1;
  if (a.instance != b.instance) return a.instance < b.instance ? -1 : 1;
  return 0;
}

// rawSize > storedSize * ratio, without overflow. ratio 0 = unchecked.
bool RatioExceeded(std::uint64_t rawSize, std::uint64_t storedSize, std::uint64_t ratio)
{
  if (ratio == 0) return false;
  if (storedSize > ~0ULL / ratio) return false; // the product would not fit: no 64-bit rawSize can exceed it
  return rawSize > storedSize * ratio;
}

bool IsRange(std::uint64_t offset, std::uint64_t length, std::uint64_t begin, std::uint64_t end)
{
  return offset >= begin && offset <= end && length <= end - offset;
}

} // namespace

const char* ContainerErrorName(ContainerError e)
{
  switch (e) {
  case ContainerError::Ok: return "Ok";
  case ContainerError::TooSmall: return "TooSmall";
  case ContainerError::BadMagic: return "BadMagic";
  case ContainerError::UnsupportedContainer: return "UnsupportedContainer";
  case ContainerError::BadRevision: return "BadRevision";
  case ContainerError::BadHeader: return "BadHeader";
  case ContainerError::FileSizeMismatch: return "FileSizeMismatch";
  case ContainerError::HeaderCrc: return "HeaderCrc";
  case ContainerError::UnsupportedFeature: return "UnsupportedFeature";
  case ContainerError::LimitExceeded: return "LimitExceeded";
  case ContainerError::BadDirectory: return "BadDirectory";
  case ContainerError::DirectoryCrc: return "DirectoryCrc";
  case ContainerError::BadChunkEntry: return "BadChunkEntry";
  case ContainerError::ChunkOutOfRange: return "ChunkOutOfRange";
  case ContainerError::ChunkOverlap: return "ChunkOverlap";
  case ContainerError::UnknownRequiredChunk: return "UnknownRequiredChunk";
  case ContainerError::ChunkCrc: return "ChunkCrc";
  case ContainerError::InflateFailed: return "InflateFailed";
  case ContainerError::RatioExceeded: return "RatioExceeded";
  case ContainerError::OutOfMemory: return "OutOfMemory";
  case ContainerError::SimHashMismatch: return "SimHashMismatch";
  }
  return "?";
}

Result MapContainer::Open(const std::uint8_t* data, std::size_t size, const OpenOptions& options, MapContainer& out)
{
  const Limits& lim = options.limits;
  if (!data || size < kHeaderSize)
    return Fail(ContainerError::TooSmall, "file is " + std::to_string(size) + " bytes, shorter than the 128 byte header");

  // --- header (bytes 0..127) ---
  ByteReader r(data, kHeaderSize);
  Header h;
  const std::uint32_t magic = r.u32();
  if (magic != kMapMagic) return Fail(ContainerError::BadMagic, "bad magic " + Hex32(magic) + " (expected 0x1a70614d)");
  h.container = r.u32();
  if (h.container != 3 && h.container != 4)
    return Fail(ContainerError::UnsupportedContainer,
                h.container == 2 ? "container 2 is a Classic .scmap, not a chunked map container (3 or 4)"
                                 : "unsupported container version " + std::to_string(h.container) + " (3 and 4 are chunked)");
  h.revision = r.u16();
  h.headerSize = r.u16();
  h.flags = r.u32();
  h.fileSize = r.u64();
  h.dirOffset = r.u64();
  h.dirCount = r.u32();
  h.dirCrc32 = r.u32();
  h.requiredFeatures = r.u64();
  h.optionalFeatures = r.u64();
  const std::uint8_t* guid = r.bytes(16);
  const std::uint8_t* hash = r.bytes(32);
  const std::uint8_t* reserved = r.bytes(16);
  const std::uint32_t reserved2 = r.u32();
  const std::uint32_t headerCrc = r.u32();
  if (!r.ok() || !guid || !hash || !reserved) return Fail(ContainerError::TooSmall, "header could not be read");
  std::copy(guid, guid + 16, h.mapGuid.begin());
  std::copy(hash, hash + 32, h.simHash.begin());

  if (h.revision == 0) return Fail(ContainerError::BadRevision, "revision 0 is invalid");
  if (h.headerSize < kHeaderSize || (h.headerSize % 16) != 0 || (h.revision == 1 && h.headerSize != kHeaderSize))
    return Fail(ContainerError::BadHeader, "invalid headerSize " + std::to_string(h.headerSize) + " (128 expected)");
  if (h.fileSize != size)
    return Fail(ContainerError::FileSizeMismatch, "header fileSize " + std::to_string(h.fileSize) + " but the file is " +
                                                      std::to_string(size) + " bytes (truncated or padded)");
  if (h.fileSize > lim.maxFileSize)
    return Fail(ContainerError::LimitExceeded, "file size " + std::to_string(h.fileSize) + " exceeds the limit " +
                                                   std::to_string(lim.maxFileSize));
  const std::uint32_t crc = Crc32(data, 124);
  if (crc != headerCrc)
    return Fail(ContainerError::HeaderCrc, "header CRC mismatch (stored " + Hex32(headerCrc) + ", computed " + Hex32(crc) + ")");
  if (h.revision == 1) {
    bool zero = reserved2 == 0;
    for (int i = 0; i < 16; ++i) zero = zero && reserved[i] == 0;
    if ((h.flags & ~kFileHasSignature) != 0 || !zero)
      return Fail(ContainerError::BadHeader, "reserved header bits or bytes are not zero");
  }

  const std::uint64_t missing = h.requiredFeatures & ~options.supportedFeatures;
  if (missing != 0)
    return Fail(ContainerError::UnsupportedFeature, "map requires unsupported feature(s): " + FeatureNamesText(missing));

  // --- directory ---
  if (h.dirCount > lim.maxDirEntries)
    return Fail(ContainerError::LimitExceeded, "directory has " + std::to_string(h.dirCount) + " entries (limit " +
                                                   std::to_string(lim.maxDirEntries) + ")");
  const std::uint64_t dirBytes = static_cast<std::uint64_t>(h.dirCount) * kDirEntrySize;
  if (!IsRange(h.dirOffset, dirBytes, h.headerSize, h.fileSize))
    return Fail(ContainerError::BadDirectory, "directory range [" + std::to_string(h.dirOffset) + ", +" +
                                                  std::to_string(dirBytes) + ") is outside the file");
  const std::uint8_t* dir = data + static_cast<std::size_t>(h.dirOffset);
  const std::uint32_t dcrc = Crc32(dir, static_cast<std::size_t>(dirBytes));
  if (dcrc != h.dirCrc32)
    return Fail(ContainerError::DirectoryCrc, "directory CRC mismatch (header " + Hex32(h.dirCrc32) + ", computed " + Hex32(dcrc) + ")");

  std::vector<ChunkEntry> entries;
  entries.reserve(h.dirCount); // dirCount <= maxDirEntries and the bytes exist
  ByteReader dr(dir, static_cast<std::size_t>(dirBytes));
  for (std::uint32_t i = 0; i < h.dirCount; ++i) {
    ChunkEntry e;
    const std::uint8_t* id = dr.bytes(4);
    if (!id) return Fail(ContainerError::BadDirectory, "directory entry could not be read");
    std::memcpy(e.id, id, 4);
    e.version = dr.u16();
    e.flags = dr.u16();
    e.instance = dr.u32();
    e.crc32 = dr.u32();
    e.offset = dr.u64();
    e.storedSize = dr.u64();
    e.rawSize = dr.u64();
    const std::uint64_t reservedEntry = dr.u64();
    const std::string name = ChunkName(e);
    for (int k = 0; k < 4; ++k) {
      const unsigned char c = static_cast<unsigned char>(e.id[k]);
      if (c <= 0x20 || c >= 0x7F) return Fail(ContainerError::BadChunkEntry, "directory entry " + std::to_string(i) + ": id is not four printable ASCII characters");
    }
    if (h.revision == 1 && reservedEntry != 0) return Fail(ContainerError::BadChunkEntry, name + ": reserved field is not zero");
    if ((e.flags & ~kChunkKnownFlags) != 0)
      return Fail(ContainerError::BadChunkEntry, name + ": unknown flag bits 0x" + TextDump::Hex(e.flags & ~kChunkKnownFlags, 4));
    if ((e.flags & kChunkSim) && (e.flags & kChunkDerived))
      return Fail(ContainerError::BadChunkEntry, name + ": SIM and DERIVED are exclusive");
    if (i > 0) {
      const int c = CompareKey(entries.back(), e);
      if (c == 0) return Fail(ContainerError::BadChunkEntry, name + ": duplicate (id, instance)");
      if (c > 0) return Fail(ContainerError::BadChunkEntry, name + ": directory is not sorted by (id, instance)");
    }
    if ((e.offset % 16) != 0) return Fail(ContainerError::BadChunkEntry, name + ": offset " + std::to_string(e.offset) + " is not 16-byte aligned");
    if (!IsRange(e.offset, e.storedSize, h.headerSize, h.dirOffset))
      return Fail(ContainerError::ChunkOutOfRange, name + ": range [" + std::to_string(e.offset) + ", +" + std::to_string(e.storedSize) +
                                                       ") is outside [headerSize, dirOffset)");
    if (!(e.flags & kChunkDeflate) && e.rawSize != e.storedSize)
      return Fail(ContainerError::BadChunkEntry, name + ": rawSize differs from storedSize but the chunk is not compressed");
    if (e.rawSize > lim.maxChunkRaw)
      return Fail(ContainerError::LimitExceeded, name + ": rawSize " + std::to_string(e.rawSize) + " exceeds the limit " + std::to_string(lim.maxChunkRaw));
    if ((e.flags & kChunkDeflate) && RatioExceeded(e.rawSize, e.storedSize, lim.maxInflateRatio))
      return Fail(ContainerError::RatioExceeded, name + ": rawSize " + std::to_string(e.rawSize) + " from " + std::to_string(e.storedSize) +
                                                     " stored bytes exceeds the expansion ratio 1:" + std::to_string(lim.maxInflateRatio));
    if (e.required() && options.isKnownChunk && !options.isKnownChunk(e.id, e.version))
      return Fail(ContainerError::UnknownRequiredChunk, name + " version " + std::to_string(e.version) + " is required but not supported");
    entries.push_back(e);
  }

  // Non-overlap: order by offset, compare neighbours (empty chunks occupy nothing).
  std::vector<std::uint32_t> order;
  order.reserve(entries.size());
  for (std::uint32_t i = 0; i < entries.size(); ++i)
    if (entries[i].storedSize != 0) order.push_back(i);
  std::sort(order.begin(), order.end(), [&](std::uint32_t a, std::uint32_t b) {
    return entries[a].offset != entries[b].offset ? entries[a].offset < entries[b].offset : a < b;
  });
  for (std::size_t i = 1; i < order.size(); ++i) {
    const ChunkEntry& prev = entries[order[i - 1]];
    const ChunkEntry& cur = entries[order[i]];
    if (prev.offset + prev.storedSize > cur.offset) // both ranges were checked to lie in the file: no overflow
      return Fail(ContainerError::ChunkOverlap, ChunkName(prev) + " overlaps " + ChunkName(cur));
  }

  out.data_ = data;
  out.size_ = size;
  out.header_ = h;
  out.entries_ = std::move(entries);
  out.limits_ = lim;
  return Result();
}

bool MapContainer::FindChunk(const char* id, std::uint32_t instance, const ChunkEntry** out) const
{
  ChunkEntry key;
  std::memcpy(key.id, id, 4);
  key.instance = instance;
  auto it = std::lower_bound(entries_.begin(), entries_.end(), key,
                             [](const ChunkEntry& a, const ChunkEntry& b) { return CompareKey(a, b) < 0; });
  if (it == entries_.end() || CompareKey(*it, key) != 0) return false;
  if (out) *out = &*it;
  return true;
}

Result MapContainer::ReadChunk(const ChunkEntry& e, std::vector<std::uint8_t>& raw, std::uint64_t* budget) const
{
  raw.clear();
  if (!data_) return Fail(ContainerError::BadDirectory, "container is not open");
  const std::string name = ChunkName(e);
  // The entry is a copy the caller could have changed: re-check it against this buffer.
  if (!IsRange(e.offset, e.storedSize, header_.headerSize, header_.dirOffset) || e.storedSize > size_)
    return Fail(ContainerError::ChunkOutOfRange, name + ": range is outside the file");
  if ((e.flags & ~kChunkKnownFlags) != 0) return Fail(ContainerError::BadChunkEntry, name + ": unknown flag bits");
  const std::uint8_t* stored = data_ + static_cast<std::size_t>(e.offset);
  const std::size_t storedSize = static_cast<std::size_t>(e.storedSize);

  const std::uint32_t crc = Crc32(stored, storedSize);
  if (crc != e.crc32) return Fail(ContainerError::ChunkCrc, name + ": CRC mismatch (stored " + Hex32(e.crc32) + ", computed " + Hex32(crc) + ")");

  if (e.rawSize > limits_.maxChunkRaw)
    return Fail(ContainerError::LimitExceeded, name + ": rawSize " + std::to_string(e.rawSize) + " exceeds the limit " + std::to_string(limits_.maxChunkRaw));
  if (budget && (*budget > limits_.maxTotalRaw || e.rawSize > limits_.maxTotalRaw - *budget))
    return Fail(ContainerError::LimitExceeded, name + ": total decoded size exceeds the limit " + std::to_string(limits_.maxTotalRaw));

  if (!(e.flags & kChunkDeflate)) {
    if (e.rawSize != e.storedSize) return Fail(ContainerError::BadChunkEntry, name + ": rawSize differs from storedSize but the chunk is not compressed");
    try {
      raw.assign(stored, stored + storedSize);
    } catch (const std::bad_alloc&) {
      raw.clear();
      return Fail(ContainerError::OutOfMemory, name + ": cannot allocate " + std::to_string(e.rawSize) + " bytes");
    }
  } else {
    // Ratio first: rawSize is what we are about to allocate.
    if (RatioExceeded(e.rawSize, e.storedSize, limits_.maxInflateRatio))
      return Fail(ContainerError::RatioExceeded, name + ": rawSize " + std::to_string(e.rawSize) + " from " + std::to_string(e.storedSize) +
                                                     " stored bytes exceeds the expansion ratio 1:" + std::to_string(limits_.maxInflateRatio));
    if (e.rawSize > static_cast<std::uint64_t>(~static_cast<std::size_t>(0)))
      return Fail(ContainerError::OutOfMemory, name + ": rawSize does not fit the address space");
    try {
      raw.resize(static_cast<std::size_t>(e.rawSize));
    } catch (const std::bad_alloc&) {
      raw.clear();
      return Fail(ContainerError::OutOfMemory, name + ": cannot allocate " + std::to_string(e.rawSize) + " bytes");
    }
    std::size_t used = 0;
    const char* why = nullptr;
    if (!Inflate(stored, storedSize, raw.data(), raw.size(), &used, &why)) {
      raw.clear();
      return Fail(ContainerError::InflateFailed, name + ": " + (why ? why : "inflate failed"));
    }
    if (used != storedSize) {
      raw.clear();
      return Fail(ContainerError::InflateFailed, name + ": " + std::to_string(storedSize - used) + " bytes follow the end of the deflate stream");
    }
  }
  if (budget) *budget += e.rawSize;
  return Result();
}

Result MapContainer::ComputeSimHash(std::array<std::uint8_t, 32>& out) const
{
  Sha256 sha;
  std::vector<std::uint8_t> raw;
  for (const ChunkEntry& e : entries_) {
    if (!e.sim()) continue;
    const Result r = ReadChunk(e, raw);
    if (!r) return r;
    ByteWriter w;
    w.bytes(reinterpret_cast<const std::uint8_t*>(e.id), 4);
    w.u16(e.version);
    w.u32(e.instance);
    w.u64(e.rawSize);
    sha.Update(w.buf.data(), w.buf.size());
    sha.Update(raw.data(), raw.size());
  }
  sha.Final(out.data());
  return Result();
}

Result MapContainer::VerifySimHash() const
{
  std::array<std::uint8_t, 32> h{};
  const Result r = ComputeSimHash(h);
  if (!r) return r;
  if (h != header_.simHash)
    return Fail(ContainerError::SimHashMismatch, "simHash mismatch (header " + HexString(header_.simHash.data(), 32) + ", computed " +
                                                     HexString(h.data(), 32) + ")");
  return Result();
}

SMapFormatInfo MapContainer::FormatInfo() const
{
  SMapFormatInfo i;
  i.id = header_.container == 4 ? EMapFormat::Full3D : (header_.container == 3 ? EMapFormat::Extended : EMapFormat::Unknown);
  i.container = header_.container;
  i.revision = header_.revision;
  i.requiredFeatures = header_.requiredFeatures;
  i.optionalFeatures = header_.optionalFeatures;
  i.simHash = header_.simHash;
  return i;
}

} // namespace moho::mapformat
