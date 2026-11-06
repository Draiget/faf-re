// Engine addition (replay timeline): reading a replay's length without disturbing the stream.
//
// The viewer's timeline gets its length from `VCR_ScanReplayBeats`, in the middle of setting up the session: the
// replay then plays from where the scan began, so a scan that doesn't come back would lose the replay's first
// messages. The ideas here come from GodFuper's tests in PR #302.
//
// usage: faf_replay_scan_tests

#include <cstdint>
#include <cstdio>
#include <string>
#include <gtest/gtest.h>

#include "gpg/core/streams/MemBufferStream.h"
#include "moho/misc/SessionStartup.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ECmdStreamOp.h"

namespace
{
#define CHECK(condition) EXPECT_TRUE(condition)

  void WriteAdvance(gpg::Stream& stream, const std::int32_t beats)
  {
    moho::CMessage message(moho::ECmdStreamOp::CMDST_Advance);
    {
      moho::CMessageStream output(message);
      output.Write(reinterpret_cast<const char*>(&beats), sizeof(beats));
    }
    stream.Write(message.mBuff.data(), message.mBuff.size());
  }

  void WriteOther(gpg::Stream& stream)
  {
    const moho::CMessage message(moho::ECmdStreamOp::CMDST_SetCommandSource, 1u);
    stream.Write(message.mBuff.data(), message.mBuff.size());
  }

  [[nodiscard]] std::uint64_t Position(gpg::Stream& stream)
  {
    return stream.VirtTell(gpg::Stream::ModeReceive);
  }

  TEST(Existing_ReplayScan, EmptyStream)
  {
    gpg::MemBufferStream stream(256);
    CHECK(moho::VCR_ScanReplayBeats(stream) == 0);
    CHECK(Position(stream) == 0u);
  }

  TEST(Existing_ReplayScan, OnlyAdvanceMessagesCount)
  {
    gpg::MemBufferStream stream(1024);
    WriteOther(stream);
    WriteAdvance(stream, 10);
    WriteOther(stream);
    WriteAdvance(stream, 25);
    WriteAdvance(stream, 65);
    CHECK(moho::VCR_ScanReplayBeats(stream) == 100);
    CHECK(Position(stream) == 0u);

    // The stream reads as if nothing had happened.
    moho::CMessage first;
    CHECK(first.Read(&stream));
    CHECK(first.GetType().raw() == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_SetCommandSource));
  }

  TEST(Existing_ReplayScan, ComesBackToWhereItBegan)
  {
    gpg::MemBufferStream stream(1024);
    const std::string header = "the replay's header";
    stream.Write(header.data(), header.size());
    char read[32];
    CHECK(stream.Read(read, header.size()) == header.size());
    WriteAdvance(stream, 15);
    WriteAdvance(stream, 30);
    CHECK(moho::VCR_ScanReplayBeats(stream) == 45);
    CHECK(Position(stream) == header.size());
  }

  TEST(Existing_ReplayScan, TruncatedLastMessage)
  {
    gpg::MemBufferStream stream(256);
    WriteAdvance(stream, 50);
    const char partial[] = {'\x00', '\x07'};
    stream.Write(partial, sizeof(partial));
    CHECK(moho::VCR_ScanReplayBeats(stream) == 50);
    CHECK(Position(stream) == 0u);
  }

  TEST(Existing_ReplayScan, NegativeBeatsCountAsNone)
  {
    gpg::MemBufferStream stream(256);
    WriteAdvance(stream, 20);
    WriteAdvance(stream, -5);
    WriteAdvance(stream, 1);
    CHECK(moho::VCR_ScanReplayBeats(stream) == 21);
  }
} // namespace
