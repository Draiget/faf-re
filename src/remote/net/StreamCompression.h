#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Engine addition, net channel (plan WP10.13): what a game server sends a player on the reliable stream, compressed as
// one zstd stream per player channel, flushed after each message (ZSTD_e_flush), so every message is whole on its own
// when it arrives and the player's client decodes the messages in the order the stream hands them out. The bytes go
// into the reliable stream compressed: a resend sends the same bytes again, nothing is compressed twice.
//
// Who takes it (GameLinks.h, `ESeatMessage`):
//   player -> server  CompressOffer  first reliable message on each new channel: varint format (1), then a byte, the
//                                    largest zstd window (log 2) the player's decoder takes
//   server -> player  Compressed     varint the message's size, then its zstd bytes: the next piece of that channel's
//                                    stream, which decodes to exactly that many bytes, the message as it was
// A server that doesn't know the offer counts it as a bad message and sends everything as it is; a client that never
// offered gets nothing compressed. A new channel (a reconnect) starts new streams at both ends.

struct ZSTD_CCtx_s;
struct ZSTD_DCtx_s;

namespace faf::remote::net
{
  inline constexpr std::uint64_t kCompressionFormat = 1;
  /** The window a server's compressor keeps (256 KB), unless the client's decoder takes less. */
  inline constexpr int kCompressionWindowLog = 18;
  /** The largest window a client's decoder takes (1 MB): a server can't make a client hold more. */
  inline constexpr int kDecompressionWindowLogMax = 20;
  /** zstd's smallest window. */
  inline constexpr int kCompressionWindowLogMin = 10;
  /**
   * Messages shorter than this go as they are: they gain nothing (a 2-byte `Beat`-sized message would grow by the tag,
   * the size and a block header), and they stay out of the stream.
   */
  inline constexpr std::size_t kCompressMinBytes = 32;

  /** The offer: `ESeatMessage::CompressOffer`, the format, the decoder's largest window. */
  [[nodiscard]] std::vector<std::uint8_t> WriteCompressOffer(int maxWindowLog = kDecompressionWindowLogMax);
  /** The decoder's largest window from an offer; empty when it isn't one of a format this end knows. */
  [[nodiscard]] std::optional<int> ReadCompressOffer(const std::uint8_t* data, std::size_t size) noexcept;

  /** One player channel's compressor: the server's end. */
  class CStreamCompressor
  {
  public:
    /** `level`: zstd's (1 fastest; 3 the server's default). `windowLog`: at most the client's offer. */
    CStreamCompressor(int level, int windowLog);
    ~CStreamCompressor();
    CStreamCompressor(const CStreamCompressor&) = delete;
    CStreamCompressor& operator=(const CStreamCompressor&) = delete;

    /** False when zstd couldn't be set up; then nothing is compressed. */
    [[nodiscard]] bool Ok() const noexcept
    {
      return mContext != nullptr;
    }

    /**
     * `out` becomes the `Compressed` message for `data`. False on a zstd failure: the stream is then broken, and the
     * channel must not take another compressed message.
     */
    [[nodiscard]] bool Compress(const void* data, std::size_t size, std::vector<std::uint8_t>& out);

    /** What zstd holds for this channel (`ZSTD_sizeof_CCtx`). */
    [[nodiscard]] std::size_t MemoryBytes() const noexcept;

  private:
    ZSTD_CCtx_s* mContext = nullptr;
  };

  /** One player channel's decompressor: the client's end. */
  class CStreamDecompressor
  {
  public:
    explicit CStreamDecompressor(int maxWindowLog = kDecompressionWindowLogMax);
    ~CStreamDecompressor();
    CStreamDecompressor(const CStreamDecompressor&) = delete;
    CStreamDecompressor& operator=(const CStreamDecompressor&) = delete;

    [[nodiscard]] bool Ok() const noexcept
    {
      return mContext != nullptr;
    }

    /**
     * `out` becomes the message a `Compressed` message holds. False when it isn't one, says it is larger than
     * `maxSize`, or doesn't decode to its stated size with every byte used: the stream is broken from then on.
     */
    [[nodiscard]] bool
    Decompress(const std::uint8_t* data, std::size_t size, std::size_t maxSize, std::vector<std::uint8_t>& out);

    [[nodiscard]] std::size_t MemoryBytes() const noexcept;

  private:
    ZSTD_DCtx_s* mContext = nullptr;
  };
} // namespace faf::remote::net
