// Engine addition: tests for the compression of what a game server sends each player (src/remote/net/
// StreamCompression.h, plan WP10.13): one stream per channel, flushed after each message, decoded in order; the offer;
// what a broken or hostile piece does. The links themselves, over real sockets: GameLinkTests.cpp.
//
// Build: cmake --build --preset clang-x64-release --target faf_netchannel_tests
// Run:   build\clang-x64-release\tests\remote\faf_netchannel_tests.exe --gtest_filter=*StreamCompression*

#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include <gtest/gtest.h>

#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/net/StreamCompression.h"

using namespace faf::remote::net;

namespace
{
  constexpr std::size_t kMaxMessage = 16u * 1024u * 1024u;

  /**
   * Messages shaped like a view stream: a kind byte, a beat, then records that mostly repeat the last beat's with a
   * few fields changed, and now and then a stretch of noise (incompressible) or a tiny message.
   */
  [[nodiscard]] std::vector<std::vector<std::uint8_t>> ViewLikeMessages(
    const int count,
    const std::uint32_t seed
  )
  {
    std::mt19937 random(seed);
    std::vector<std::uint8_t> records(1800u);
    for (std::uint8_t& byte : records) {
      byte = static_cast<std::uint8_t>(random() % 40u);
    }
    std::vector<std::vector<std::uint8_t>> out;
    for (int beat = 0; beat < count; ++beat) {
      std::vector<std::uint8_t> message;
      ByteWriter writer(message);
      writer.Byte(static_cast<std::uint8_t>(beat % 7 == 3 ? ESeatMessage::LuaSync : ESeatMessage::View));
      writer.Varint(static_cast<std::uint64_t>(beat));
      if (beat % 11 == 5) {
        writer.Byte(0u); // tiny: under kCompressMinBytes
        out.push_back(std::move(message));
        continue;
      }
      for (int change = 0; change < 40; ++change) {
        records[random() % records.size()] = static_cast<std::uint8_t>(random());
      }
      writer.Bytes(records.data(), records.size() - static_cast<std::size_t>(random() % 600u));
      if (beat % 13 == 0) {
        for (int i = 0; i < 700; ++i) {
          writer.Byte(static_cast<std::uint8_t>(random()));
        }
      }
      out.push_back(std::move(message));
    }
    return out;
  }
} // namespace

TEST(
  Existing_StreamCompression,
  OfferRoundTripAndRefusals
)
{
  const std::vector<std::uint8_t> offer = WriteCompressOffer(17);
  ASSERT_FALSE(offer.empty());
  EXPECT_EQ(offer[0], static_cast<std::uint8_t>(ESeatMessage::CompressOffer));
  EXPECT_EQ(ReadCompressOffer(offer.data(), offer.size()), std::optional<int>(17));
  EXPECT_EQ(ReadCompressOffer(WriteCompressOffer().data(), 3u), std::optional<int>(kDecompressionWindowLogMax));

  // A later format's offer, a cut one, one for a window zstd doesn't have, and another message kind: none counts.
  std::vector<std::uint8_t> later = offer;
  later[1] = 2u;
  EXPECT_FALSE(ReadCompressOffer(later.data(), later.size()).has_value());
  EXPECT_FALSE(ReadCompressOffer(offer.data(), 2u).has_value());
  const std::vector<std::uint8_t> tiny = WriteCompressOffer(9);
  EXPECT_FALSE(ReadCompressOffer(tiny.data(), tiny.size()).has_value());
  std::vector<std::uint8_t> other = offer;
  other[0] = static_cast<std::uint8_t>(ESeatMessage::Chat);
  EXPECT_FALSE(ReadCompressOffer(other.data(), other.size()).has_value());

  // Fields after the ones this end knows are left alone.
  std::vector<std::uint8_t> longer = offer;
  longer.push_back(7u);
  EXPECT_EQ(ReadCompressOffer(longer.data(), longer.size()), std::optional<int>(17));
}

TEST(
  Existing_StreamCompression,
  ManyMessagesDecodeInOrder
)
{
  for (const int level : {1, 3, 6}) {
    CStreamCompressor compressor(level, kCompressionWindowLog);
    CStreamDecompressor decompressor;
    ASSERT_TRUE(compressor.Ok() && decompressor.Ok());
    const std::vector<std::vector<std::uint8_t>> messages = ViewLikeMessages(3000, 42u);
    std::uint64_t raw = 0;
    std::uint64_t packed = 0;
    std::vector<std::uint8_t> piece;
    std::vector<std::uint8_t> back;
    for (const std::vector<std::uint8_t>& message : messages) {
      if (message.size() < kCompressMinBytes) {
        continue; // as the links send them: as they are, outside the stream
      }
      ASSERT_TRUE(compressor.Compress(message.data(), message.size(), piece));
      ASSERT_FALSE(piece.empty());
      EXPECT_EQ(piece[0], static_cast<std::uint8_t>(ESeatMessage::Compressed));
      ASSERT_TRUE(decompressor.Decompress(piece.data(), piece.size(), kMaxMessage, back)) << "level " << level;
      ASSERT_EQ(back, message);
      raw += message.size();
      packed += piece.size();
    }
    EXPECT_LT(packed, raw * 7u / 10u) << "level " << level << " leaves " << packed << " of " << raw;
    std::printf(
      "level %d: %llu of %llu bytes (%.1f %%), compressor %zu KB, decompressor %zu KB\n",
      level,
      static_cast<unsigned long long>(packed),
      static_cast<unsigned long long>(raw),
      100.0 * static_cast<double>(packed) / static_cast<double>(raw),
      compressor.MemoryBytes() / 1024u,
      decompressor.MemoryBytes() / 1024u
    );
    // Plan WP10.13: what one player's channel holds, bounded by the window and the tables (StreamCompression.cpp):
    // 1081 KB at level 1, 1529 KB at level 3, the decoder 733 KB (Linux, zstd 1.5.7).
    if (level <= 3) {
      EXPECT_LT(compressor.MemoryBytes(), 2048u * 1024u);
    }
    EXPECT_LT(decompressor.MemoryBytes(), 1024u * 1024u);
  }
}

TEST(
  Existing_StreamCompression,
  LargeAndIncompressibleMessages
)
{
  CStreamCompressor compressor(3, kCompressionWindowLog);
  CStreamDecompressor decompressor;
  std::mt19937 random(7u);
  std::vector<std::uint8_t> piece;
  std::vector<std::uint8_t> back;
  // Past the window (a whole view after a reconnect), noise that grows under zstd, and a message after each.
  for (const std::size_t size : {std::size_t{3u << 20}, std::size_t{1u << 20}, std::size_t{70000u}, std::size_t{40u}}) {
    std::vector<std::uint8_t> message(size);
    for (std::size_t i = 0; i < size; ++i) {
      message[i] = static_cast<std::uint8_t>(size == (1u << 20) ? random() : (i % 251u) ^ (i >> 12));
    }
    message[0] = static_cast<std::uint8_t>(ESeatMessage::View);
    ASSERT_TRUE(compressor.Compress(message.data(), message.size(), piece));
    ASSERT_TRUE(decompressor.Decompress(piece.data(), piece.size(), kMaxMessage, back)) << size;
    ASSERT_EQ(back, message) << size;
  }
}

TEST(
  Existing_StreamCompression,
  BrokenPiecesAreRefused
)
{
  const std::vector<std::vector<std::uint8_t>> messages = ViewLikeMessages(40, 9u);
  std::vector<std::vector<std::uint8_t>> pieces;
  {
    CStreamCompressor compressor(3, kCompressionWindowLog);
    for (const std::vector<std::uint8_t>& message : messages) {
      std::vector<std::uint8_t> piece;
      if (message.size() >= kCompressMinBytes) {
        ASSERT_TRUE(compressor.Compress(message.data(), message.size(), piece));
        pieces.push_back(std::move(piece));
      }
    }
  }
  ASSERT_GE(pieces.size(), 4u);
  std::vector<std::uint8_t> back;

  // Not a `Compressed` message.
  {
    CStreamDecompressor decompressor;
    std::vector<std::uint8_t> wrong = pieces[0];
    wrong[0] = static_cast<std::uint8_t>(ESeatMessage::View);
    EXPECT_FALSE(decompressor.Decompress(wrong.data(), wrong.size(), kMaxMessage, back));
  }
  // Says it is larger than the channel takes: refused before anything is made.
  {
    CStreamDecompressor decompressor;
    EXPECT_FALSE(decompressor.Decompress(pieces[0].data(), pieces[0].size(), 100u, back));
    EXPECT_TRUE(back.empty());
  }
  // A stated size off by one either way.
  for (const int delta : {-1, 1}) {
    CStreamDecompressor decompressor;
    ByteReader reader(pieces[0].data() + 1, pieces[0].size() - 1u);
    const std::uint64_t size = reader.Varint();
    std::vector<std::uint8_t> lying;
    ByteWriter writer(lying);
    writer.Byte(static_cast<std::uint8_t>(ESeatMessage::Compressed));
    writer.Varint(static_cast<std::uint64_t>(static_cast<std::int64_t>(size) + delta));
    const std::size_t at = pieces[0].size() - reader.Remaining();
    writer.Bytes(pieces[0].data() + at, pieces[0].size() - at);
    EXPECT_FALSE(decompressor.Decompress(lying.data(), lying.size(), kMaxMessage, back)) << delta;
  }
  // Cut short.
  {
    CStreamDecompressor decompressor;
    EXPECT_FALSE(decompressor.Decompress(pieces[0].data(), pieces[0].size() - 3u, kMaxMessage, back));
  }
  // A later piece first, on a new decoder (as a client whose stream started over and the server's didn't): its frame
  // header is missing, so it never decodes as the message.
  {
    CStreamDecompressor decompressor;
    const bool decoded = decompressor.Decompress(pieces[2].data(), pieces[2].size(), kMaxMessage, back);
    EXPECT_FALSE(decoded && back == messages[2]);
  }
}

TEST(
  Existing_StreamCompression,
  NewStreamAfterReconnect
)
{
  // A reconnect: both ends make new contexts, and the first piece of the new stream decodes on the new decoder,
  // whatever the old pair had seen.
  const std::vector<std::vector<std::uint8_t>> messages = ViewLikeMessages(200, 3u);
  std::vector<std::uint8_t> piece;
  std::vector<std::uint8_t> back;
  for (int channel = 0; channel < 3; ++channel) {
    CStreamCompressor compressor(3, kCompressionWindowLog);
    CStreamDecompressor decompressor;
    for (std::size_t i = static_cast<std::size_t>(channel) * 50u; i < messages.size(); ++i) {
      if (messages[i].size() < kCompressMinBytes) {
        continue;
      }
      ASSERT_TRUE(compressor.Compress(messages[i].data(), messages[i].size(), piece));
      ASSERT_TRUE(decompressor.Decompress(piece.data(), piece.size(), kMaxMessage, back));
      ASSERT_EQ(back, messages[i]);
    }
  }
}

TEST(
  Existing_StreamCompression,
  WindowFollowsTheOffer
)
{
  // A decoder that takes only 64 KB refuses a stream with a larger window; a compressor made for its offer suits it.
  const std::vector<std::vector<std::uint8_t>> messages = ViewLikeMessages(10, 5u);
  std::vector<std::uint8_t> piece;
  std::vector<std::uint8_t> back;
  {
    CStreamCompressor compressor(3, 22);
    CStreamDecompressor decompressor(16);
    ASSERT_TRUE(compressor.Compress(messages[0].data(), messages[0].size(), piece));
    EXPECT_FALSE(decompressor.Decompress(piece.data(), piece.size(), kMaxMessage, back));
  }
  {
    CStreamCompressor compressor(3, 16);
    CStreamDecompressor decompressor(16);
    for (const std::vector<std::uint8_t>& message : messages) {
      if (message.size() < kCompressMinBytes) {
        continue;
      }
      ASSERT_TRUE(compressor.Compress(message.data(), message.size(), piece));
      ASSERT_TRUE(decompressor.Decompress(piece.data(), piece.size(), kMaxMessage, back));
      ASSERT_EQ(back, message);
    }
  }
}
