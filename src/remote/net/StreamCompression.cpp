#include "remote/net/StreamCompression.h"

#include <algorithm>

// For `ZSTD_getCParams`: the library is linked in, at the version cmake/FafDependencies.cmake pins.
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition, net channel: see StreamCompression.h.

namespace faf::remote::net
{
  namespace
  {
    // Plan WP10.13: the hash and chain tables at most 2^16 entries each (zstd's level 3 takes 2^17 and 2^16), so a
    // player's compressor holds about 1.5 MB at level 3 with the 256 KB window (`ZSTD_sizeof_CCtx`: 1529 KB; 1081 KB
    // at level 1). Measured on an 8v8's saved stream (12,596 messages, 29.3 MB): 54.2 % of the bytes left against
    // 54.1 % with level 3's own tables and 53.5 % with its 2 MB window.
    constexpr int kTableLogMax = 16;
  } // namespace

  std::vector<std::uint8_t> WriteCompressOffer(
    const int maxWindowLog
  )
  {
    std::vector<std::uint8_t> out;
    ByteWriter writer(out);
    writer.Byte(static_cast<std::uint8_t>(ESeatMessage::CompressOffer));
    writer.Varint(kCompressionFormat);
    writer.Byte(static_cast<std::uint8_t>(maxWindowLog));
    return out;
  }

  std::optional<int> ReadCompressOffer(
    const std::uint8_t* const data,
    const std::size_t size
  ) noexcept
  {
    if (size < 1u || data[0] != static_cast<std::uint8_t>(ESeatMessage::CompressOffer)) {
      return std::nullopt;
    }
    ByteReader reader(data + 1, size - 1u);
    const std::uint64_t format = reader.Varint();
    const int windowLog = reader.Byte();
    // A later format may add fields after these; this end reads its own and leaves the rest.
    if (!reader.Ok() || format != kCompressionFormat || windowLog < kCompressionWindowLogMin) {
      return std::nullopt;
    }
    return windowLog;
  }

  CStreamCompressor::CStreamCompressor(
    const int level,
    const int windowLog
  )
    : mContext(ZSTD_createCCtx())
  {
    if (mContext == nullptr) {
      return;
    }
    const int window = std::clamp(windowLog, kCompressionWindowLogMin, kDecompressionWindowLogMax);
    // The level's own parameters, then the window and the tables bounded: what one player's channel holds.
    const ZSTD_compressionParameters params = ZSTD_getCParams(level, 0, 0);
    const bool set = ZSTD_isError(ZSTD_CCtx_setParameter(mContext, ZSTD_c_compressionLevel, level)) == 0u &&
      ZSTD_isError(ZSTD_CCtx_setParameter(mContext, ZSTD_c_windowLog, window)) == 0u &&
      ZSTD_isError(
        ZSTD_CCtx_setParameter(mContext, ZSTD_c_hashLog, std::min(static_cast<int>(params.hashLog), kTableLogMax))
      ) == 0u &&
      ZSTD_isError(
        ZSTD_CCtx_setParameter(mContext, ZSTD_c_chainLog, std::min(static_cast<int>(params.chainLog), kTableLogMax))
      ) == 0u &&
      // Nothing a message's size or the stream's end could tell: the frame never ends, and the channel checks.
      ZSTD_isError(ZSTD_CCtx_setParameter(mContext, ZSTD_c_contentSizeFlag, 0)) == 0u &&
      ZSTD_isError(ZSTD_CCtx_setParameter(mContext, ZSTD_c_checksumFlag, 0)) == 0u;
    if (!set) {
      ZSTD_freeCCtx(mContext);
      mContext = nullptr;
    }
  }

  CStreamCompressor::~CStreamCompressor()
  {
    ZSTD_freeCCtx(mContext);
  }

  bool CStreamCompressor::Compress(
    const void* const data,
    const std::size_t size,
    std::vector<std::uint8_t>& out
  )
  {
    out.clear();
    if (mContext == nullptr) {
      return false;
    }
    ByteWriter writer(out);
    writer.Byte(static_cast<std::uint8_t>(ESeatMessage::Compressed));
    writer.Varint(size);
    const std::size_t head = out.size();
    // A flush ends the block: the bound for this input, plus a frame header (the first time) and a block header.
    out.resize(head + ZSTD_compressBound(size) + 32u);
    ZSTD_inBuffer in{data, size, 0};
    ZSTD_outBuffer output{out.data() + head, out.size() - head, 0};
    for (;;) {
      const std::size_t left = ZSTD_compressStream2(mContext, &output, &in, ZSTD_e_flush);
      if (ZSTD_isError(left) != 0u) {
        out.clear();
        return false;
      }
      if (left == 0u) {
        break;
      }
      // Rare: more came out than the bound gave room for. Grow and go on with the same stream.
      const std::size_t written = output.pos;
      out.resize(out.size() + std::max<std::size_t>(left, 1024u));
      output.dst = out.data() + head;
      output.size = out.size() - head;
      output.pos = written;
    }
    out.resize(head + output.pos);
    return true;
  }

  std::size_t CStreamCompressor::MemoryBytes() const noexcept
  {
    return mContext == nullptr ? 0u : ZSTD_sizeof_CCtx(mContext);
  }

  CStreamDecompressor::CStreamDecompressor(
    const int maxWindowLog
  )
    : mContext(ZSTD_createDCtx())
  {
    if (
      mContext != nullptr && ZSTD_isError(ZSTD_DCtx_setParameter(mContext, ZSTD_d_windowLogMax, maxWindowLog)) != 0u
    ) {
      ZSTD_freeDCtx(mContext);
      mContext = nullptr;
    }
  }

  CStreamDecompressor::~CStreamDecompressor()
  {
    ZSTD_freeDCtx(mContext);
  }

  bool CStreamDecompressor::Decompress(
    const std::uint8_t* const data,
    const std::size_t size,
    const std::size_t maxSize,
    std::vector<std::uint8_t>& out
  )
  {
    out.clear();
    if (mContext == nullptr || size < 1u || data[0] != static_cast<std::uint8_t>(ESeatMessage::Compressed)) {
      return false;
    }
    ByteReader reader(data + 1, size - 1u);
    const std::uint64_t rawSize = reader.Varint();
    if (!reader.Ok() || rawSize > maxSize) {
      return false;
    }
    const std::size_t at = size - reader.Remaining();
    out.resize(static_cast<std::size_t>(rawSize));
    ZSTD_inBuffer in{data + at, size - at, 0};
    ZSTD_outBuffer output{out.data(), out.size(), 0};
    // The sender flushed after the message: every byte of it decodes now, and decodes to exactly its stated size.
    while (in.pos < in.size) {
      const std::size_t inBefore = in.pos;
      const std::size_t outBefore = output.pos;
      const std::size_t result = ZSTD_decompressStream(mContext, &output, &in);
      if (ZSTD_isError(result) != 0u || (in.pos == inBefore && output.pos == outBefore)) {
        out.clear();
        return false;
      }
    }
    // Nothing held back: a decoder still holding output has more than the stated size.
    if (output.pos != output.size) {
      out.clear();
      return false;
    }
    std::uint8_t extra = 0;
    ZSTD_outBuffer probe{&extra, 1u, 0};
    ZSTD_inBuffer none{nullptr, 0u, 0};
    if (ZSTD_isError(ZSTD_decompressStream(mContext, &probe, &none)) != 0u || probe.pos != 0u) {
      out.clear();
      return false;
    }
    return true;
  }

  std::size_t CStreamDecompressor::MemoryBytes() const noexcept
  {
    return mContext == nullptr ? 0u : ZSTD_sizeof_DCtx(mContext);
  }
} // namespace faf::remote::net
