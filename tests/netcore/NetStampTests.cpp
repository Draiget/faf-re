// The network layer's bookkeeping that needs no socket, from moho/net/Common.h: the names of packet types and
// connection states, the 4096-slot ring of send and receive stamps the bandwidth graph reads, the bandwidth series
// built from it, and the decoder of one GPGNet command argument.

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/net/Common.h"
#include "moho/net/NetTransportEnums.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{
  std::string PacketName(
    const int type
  )
  {
    fa::string out;
    moho::NetPacketTypeToStr(static_cast<moho::EPacketType>(type), out);
    return out.c_str();
  }

  /** The stamp ring is 98 KB, so tests keep it on the heap. */
  std::unique_ptr<moho::SSendStampBuffer> NewRing()
  {
    return std::make_unique<moho::SSendStampBuffer>();
  }

  moho::SSendStamp Stamp(
    const std::uint32_t direction,
    const std::uint64_t timeUs,
    const std::uint32_t bytes
  )
  {
    moho::SSendStamp stamp{};
    stamp.direction = direction;
    stamp.timestampUs = timeUs;
    stamp.payloadSizeBytes = bytes;
    return stamp;
  }

  /** Little-endian bytes of `value`, as the GPGNet socket sends numbers. */
  std::string Le32(
    const std::uint32_t value
  )
  {
    std::string bytes(4, '\0');
    for (int i = 0; i < 4; ++i) {
      bytes[static_cast<std::size_t>(i)] = static_cast<char>((value >> (8 * i)) & 0xFFu);
    }
    return bytes;
  }

  moho::SNetCommandArg Decode(
    const std::string& bytes
  )
  {
    gpg::MemBufferStream stream(gpg::CopyMemBuffer(bytes.data(), bytes.size()));
    gpg::BinaryReader reader(&stream);
    return moho::NET_DecodeSocketArg(reader);
  }
} // namespace

TEST(
  NetStamps,
  PacketTypeNamesAndHexForUnknownTypes
)
{
  EXPECT_EQ(PacketName(moho::PT_Connect), "CONNECT");
  EXPECT_EQ(PacketName(moho::PT_Answer), "ANSWER");
  EXPECT_EQ(PacketName(moho::PT_ResetSerial), "RESETSERIAL");
  EXPECT_EQ(PacketName(moho::PT_SerialReset), "SERIALRESET");
  EXPECT_EQ(PacketName(moho::PT_Data), "DATA");
  EXPECT_EQ(PacketName(moho::PT_Ack), "ACK");
  EXPECT_EQ(PacketName(moho::PT_KeepAlive), "KEEPALIVE");
  EXPECT_EQ(PacketName(moho::PT_Goodbye), "GOODBYE");
  EXPECT_EQ(PacketName(moho::PT_NATTraversal), "NATTRAVERSAL");
  EXPECT_EQ(PacketName(9), "09");
  EXPECT_EQ(PacketName(0xAB), "ab");
}

TEST(
  NetStamps,
  ConnectionStateNames
)
{
  EXPECT_STREQ(moho::NetConnectionStateToStr(moho::kNetStatePending), "PENDING");
  EXPECT_STREQ(moho::NetConnectionStateToStr(moho::kNetStateConnecting), "CONNECTING");
  EXPECT_STREQ(moho::NetConnectionStateToStr(moho::kNetStateAnswering), "ANSWERING");
  EXPECT_STREQ(moho::NetConnectionStateToStr(moho::kNetStateEstablishing), "ESTABLISHING");
  EXPECT_STREQ(moho::NetConnectionStateToStr(moho::kNetStateTimedOut), "TIMEDOUT");
  EXPECT_STREQ(moho::NetConnectionStateToStr(moho::kNetStateErrored), "ERRORED");
  EXPECT_STREQ(moho::NetConnectionStateToStr(static_cast<moho::ENetConnectionState>(6)), "???");
}

TEST(
  NetStamps,
  RingCountsPushedStampsInOrder
)
{
  auto ring = NewRing();
  EXPECT_TRUE(ring->empty());
  EXPECT_EQ(ring->size(), 0u);

  EXPECT_EQ(ring->Push(0, 100, 10), 1u) << "Push returns the next write slot";
  ring->Add(1, 200, 20);
  const moho::SSendStamp third = Stamp(0, 300, 30);
  ring->Append(&third);
  ring->push(Stamp(1, 400, 40));

  EXPECT_FALSE(ring->empty());
  ASSERT_EQ(ring->size(), 4u);
  EXPECT_EQ(ring->Get(0).timestampUs, 100u);
  EXPECT_EQ(ring->Get(1).direction, 1u);
  EXPECT_EQ(ring->Get(1).payloadSizeBytes, 20u);
  EXPECT_EQ(ring->Get(2).timestampUs, 300u);
  EXPECT_EQ(ring->Get(3).payloadSizeBytes, 40u);

  ring->Reset();
  EXPECT_TRUE(ring->empty());
  EXPECT_EQ(ring->size(), 0u);
}

// One slot always stays free: a full ring holds cap - 1 stamps, and each write past that drops the oldest.
TEST(
  NetStamps,
  RingKeepsTheNewestCapMinusOneStamps
)
{
  constexpr std::uint32_t cap = moho::SSendStampBuffer::cap;
  auto ring = NewRing();
  for (std::uint32_t i = 0; i < cap + 10u; ++i) {
    (void)ring->Push(0, static_cast<long long>(i), 1);
  }
  ASSERT_EQ(ring->size(), cap - 1u);
  EXPECT_EQ(ring->Get(0).timestampUs, 11u) << "stamps 0..10 were dropped";
  EXPECT_EQ(ring->Get(cap - 2u).timestampUs, static_cast<std::uint64_t>(cap + 9u));

  // The other write path (`push`) drops the oldest after writing, with the same result.
  auto other = NewRing();
  for (std::uint32_t i = 0; i < cap + 10u; ++i) {
    other->push(Stamp(1, i, 2));
  }
  ASSERT_EQ(other->size(), cap - 1u);
  EXPECT_EQ(other->Get(0).timestampUs, 11u);
}

// GetBetween(now, span): the stamps at or after now - span, in order; the window keeps now - span and now.
TEST(
  NetStamps,
  WindowHoldsTheStampsOfTheLastSpan
)
{
  auto ring = NewRing();
  for (const std::uint64_t t : {10u, 20u, 30u, 40u}) {
    (void)ring->Push(static_cast<int>(t / 10u % 2u), static_cast<long long>(t), static_cast<int>(t));
  }

  const moho::SSendStampWindow last = ring->GetBetween(45, 20);
  ASSERT_EQ(last.StampCount(), 2u);
  EXPECT_EQ(last.items[0].timestampUs, 30u);
  EXPECT_EQ(last.items[1].timestampUs, 40u);
  EXPECT_EQ(last.windowDurationUs, 25u);
  EXPECT_EQ(last.windowEndTimeUs, 45u);

  EXPECT_EQ(ring->GetBetween(40, 20).StampCount(), 3u) << "a stamp exactly at now - span is in";
  EXPECT_EQ(ring->GetBetween(100, 10).StampCount(), 0u);
  EXPECT_EQ(ring->GetBetween(40, 40).StampCount(), 4u);

  // Across the ring's wrap the order is still oldest first.
  auto wrapped = NewRing();
  for (std::uint32_t i = 0; i < moho::SSendStampBuffer::cap + 5u; ++i) {
    (void)wrapped->Push(0, static_cast<long long>(i), 1);
  }
  const moho::SSendStampWindow tail = wrapped->GetBetween(moho::SSendStampBuffer::cap + 4u, 2);
  ASSERT_EQ(tail.StampCount(), 3u);
  EXPECT_EQ(tail.items[0].timestampUs, moho::SSendStampBuffer::cap + 2u);
  EXPECT_EQ(tail.items[2].timestampUs, moho::SSendStampBuffer::cap + 4u);
}

TEST(
  NetStamps,
  WindowReservesAndAppends
)
{
  moho::SSendStampWindow window(25, 45);
  EXPECT_EQ(window.StampCount(), 0u);
  window.ReserveStamps(8);
  EXPECT_GE(window.items.capacity(), 8u);
  window.ReserveStamps(2); // never shrinks
  EXPECT_GE(window.items.capacity(), 8u);
  window.AppendStamp(Stamp(1, 5, 6));
  ASSERT_EQ(window.StampCount(), 1u);
  EXPECT_EQ(window.items[0].payloadSizeBytes, 6u);
}

// Four samples over [1000, 1400) us with a 100 us averaging window: each sample is the bytes of the last 100 us
// in bytes per second (x 10,000), then the inner samples are averaged with their neighbours' original values.
TEST(
  NetStamps,
  BandwidthSeriesAveragesTheLastWindowAndSmoothsInnerSamples
)
{
  moho::SSendStampWindow stamps(0, 0);
  stamps.AppendStamp(Stamp(0, 950, 300)); // before the range, inside the first window
  stamps.AppendStamp(Stamp(0, 1050, 1000));
  stamps.AppendStamp(Stamp(1, 1150, 500));
  stamps.AppendStamp(Stamp(0, 1250, 2000));

  moho::SBandwidthUsageSeries series;
  moho::NET_BuildBandwidthUsageSeries(series, stamps, 4, 1000, 1400, 100);
  ASSERT_EQ(series.SampleCount(), 4u);

  // Before smoothing: outbound 3e6, 1e7, 0, 2e7; inbound 0, 0, 5e6, 0.
  constexpr float third = 1.0f / 3.0f;
  EXPECT_FLOAT_EQ(series.samples[0].outboundBytesPerSec, 3.0e6f);
  EXPECT_FLOAT_EQ(series.samples[0].inboundBytesPerSec, 0.0f);
  EXPECT_FLOAT_EQ(series.samples[1].outboundBytesPerSec, (3.0e6f + 1.0e7f + 0.0f) * third);
  EXPECT_FLOAT_EQ(series.samples[1].inboundBytesPerSec, (0.0f + 0.0f + 5.0e6f) * third);
  EXPECT_FLOAT_EQ(series.samples[2].outboundBytesPerSec, (1.0e7f + 0.0f + 2.0e7f) * third);
  EXPECT_FLOAT_EQ(series.samples[2].inboundBytesPerSec, (0.0f + 5.0e6f + 0.0f) * third);
  EXPECT_FLOAT_EQ(series.samples[3].outboundBytesPerSec, 2.0e7f);
  EXPECT_FLOAT_EQ(series.samples[3].inboundBytesPerSec, 0.0f);
}

TEST(
  NetStamps,
  BandwidthSeriesEdgeCases
)
{
  moho::SSendStampWindow stamps(0, 0);
  stamps.AppendStamp(Stamp(1, 1050, 100));

  moho::SBandwidthUsageSeries series;
  series.ResizeSamples(7);
  moho::NET_BuildBandwidthUsageSeries(series, stamps, 0, 1000, 1400, 100);
  EXPECT_EQ(series.SampleCount(), 0u) << "no samples asked";

  series.ResizeSamples(7);
  moho::NET_BuildBandwidthUsageSeries(series, stamps, 4, 1000, 1400, 0);
  EXPECT_EQ(series.SampleCount(), 0u) << "no averaging window";

  // Two samples: nothing to smooth, so the raw rates stay.
  moho::NET_BuildBandwidthUsageSeries(series, stamps, 2, 1000, 1200, 100);
  ASSERT_EQ(series.SampleCount(), 2u);
  EXPECT_FLOAT_EQ(series.samples[0].inboundBytesPerSec, 0.0f);
  EXPECT_FLOAT_EQ(series.samples[1].inboundBytesPerSec, 1.0e6f);

  // No stamps at all.
  moho::NET_BuildBandwidthUsageSeries(series, moho::SSendStampWindow(0, 0), 3, 1000, 1300, 100);
  ASSERT_EQ(series.SampleCount(), 3u);
  for (const moho::SBandwidthUsageSample& sample : series.samples) {
    EXPECT_FLOAT_EQ(sample.outboundBytesPerSec, 0.0f);
    EXPECT_FLOAT_EQ(sample.inboundBytesPerSec, 0.0f);
  }
}

// One GPGNet argument: a type byte (0 number, 1 string, 2 data) and an int32, or a uint32 length and that many bytes.
TEST(
  NetStamps,
  SocketArgumentsDecodeByType
)
{
  const moho::SNetCommandArg number = Decode(std::string(1, '\0') + Le32(0xFFFFFFFEu));
  EXPECT_EQ(number.mType, moho::SNetCommandArg::NETARG_Num);
  EXPECT_EQ(number.mNum, -2);

  const moho::SNetCommandArg text = Decode(std::string(1, '\1') + Le32(5) + "hello");
  EXPECT_EQ(text.mType, moho::SNetCommandArg::NETARG_String);
  EXPECT_STREQ(text.mStr.c_str(), "hello");

  const std::string payload("\x00\x01\xff", 3);
  const moho::SNetCommandArg data = Decode(std::string(1, '\2') + Le32(3) + payload);
  EXPECT_EQ(data.mType, moho::SNetCommandArg::NETARG_Data);
  ASSERT_EQ(data.mStr.size(), 3u);
  EXPECT_EQ(std::string(data.mStr.data(), data.mStr.size()), payload);

  const moho::SNetCommandArg empty = Decode(std::string(1, '\1') + Le32(0));
  EXPECT_EQ(empty.mType, moho::SNetCommandArg::NETARG_String);
  EXPECT_TRUE(empty.mStr.empty());

  EXPECT_THROW((void)Decode(std::string(1, '\3') + Le32(0)), std::runtime_error);
}

TEST(
  NetStamps,
  LengthPrefixedPayloadReadsExactlyItsBytes
)
{
  const std::string bytes = Le32(3) + "abcXYZ";
  gpg::MemBufferStream stream(gpg::CopyMemBuffer(bytes.data(), bytes.size()));
  gpg::BinaryReader reader(&stream);
  EXPECT_STREQ(moho::NET_ReadLengthPrefixedArgPayload(reader).c_str(), "abc");
  char next = 0;
  reader.ReadExact(next);
  EXPECT_EQ(next, 'X') << "the reader stops right after the payload";
}
