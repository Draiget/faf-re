#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "gpg/core/streams/MemBufferStream.h"
#include "moho/misc/SessionStartup.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/sim/CWldSession.h"
#include "moho/misc/LaunchInfoBase.h"
#include <cmath>

namespace
{
  int gFailures = 0;
  int gChecks = 0;

#define CHECK(cond)                                                                \
  do {                                                                             \
    ++gChecks;                                                                     \
    if (!(cond)) {                                                                 \
      ++gFailures;                                                                 \
      std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                \
    }                                                                              \
  } while (0)

  struct Bytes
  {
    std::string data;

    template <class T>
    Bytes& Put(const T& value)
    {
      data.append(reinterpret_cast<const char*>(&value), sizeof(value));
      return *this;
    }
    Bytes& U8(std::uint8_t v) { return Put(v); }
    Bytes& I32(std::int32_t v) { return Put(v); }
    Bytes& U32(std::uint32_t v) { return Put(v); }
    Bytes& F32(float v) { return Put(v); }
    Bytes& Str(const char* s)
    {
      data.append(s, std::strlen(s) + 1);
      return *this;
    }
    Bytes& Raw(const std::string& s)
    {
      data += s;
      return *this;
    }
  };

  std::string LuaString(const char* s) { return Bytes{}.U8(1).Str(s).data; }
  std::string LuaTable(const std::string& entries) { return "\x04" + entries + "\x05"; }

  moho::CMessage MakeAdvanceMessage(const std::int32_t beatDelta)
  {
    moho::CMessage msg(moho::ECmdStreamOp::CMDST_Advance);
    moho::CMessageStream stream(msg);
    stream.WriteInt32(beatDelta);
    return msg;
  }

  moho::CMessage MakeOtherMessage(const moho::ECmdStreamOp op, const std::string& payload)
  {
    moho::CMessage msg(op);
    if (!payload.empty()) {
      msg.Append(payload.data(), payload.size());
    }
    return msg;
  }

  void WriteMessage(gpg::Stream& dest, const moho::CMessage& msg)
  {
    dest.Write(msg.mBuff.data(), msg.mBuff.size());
  }

  void TestEmptyStream()
  {
    gpg::MemBufferStream stream(256);
    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 0);
  }

  void TestNullStream()
  {
    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(nullptr);
    CHECK(beats == 0);
  }

  void TestSingleAdvanceMessage()
  {
    gpg::MemBufferStream stream(256);
    const moho::CMessage advance = MakeAdvanceMessage(42);
    WriteMessage(stream, advance);

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 42);

    // Verify stream was rewound to position 0
    const std::uint64_t pos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(pos == 0);

    // Verify message can be read again
    moho::CMessage readBack;
    CHECK(readBack.ReadMessage(&stream));
    CHECK(readBack.GetType().raw() == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_Advance));
  }

  void TestMultipleAdvanceAndOtherMessages()
  {
    gpg::MemBufferStream stream(1024);

    // Mixed stream of commands:
    // non-advance, advance(10), non-advance, advance(25), advance(65)
    WriteMessage(stream, MakeOtherMessage(moho::ECmdStreamOp::CMDST_SetCommandSource, "\x01"));
    WriteMessage(stream, MakeAdvanceMessage(10));
    WriteMessage(stream, MakeOtherMessage(moho::ECmdStreamOp::CMDST_ProcessInfoPair, "\x00\x01\x02\x03"));
    WriteMessage(stream, MakeAdvanceMessage(25));
    WriteMessage(stream, MakeAdvanceMessage(65));

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 100);

    // Verify stream was rewound to 0
    const std::uint64_t pos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(pos == 0);

    // Verify reading first message yields the initial SetCommandSource
    moho::CMessage firstMsg;
    CHECK(firstMsg.ReadMessage(&stream));
    CHECK(firstMsg.GetType().raw() == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_SetCommandSource));
  }

  void TestStreamOffsetRewind()
  {
    gpg::MemBufferStream stream(1024);

    // Simulate dummy header data at start
    const std::string dummyHeader = "PREAMBLE_DATA_1234567890";
    stream.Write(dummyHeader.data(), dummyHeader.size());

    // Advance stream read head past header
    char buf[32];
    const size_t bytesRead = stream.Read(buf, dummyHeader.size());
    CHECK(bytesRead == dummyHeader.size());
    const std::uint64_t headerEndPos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(headerEndPos == dummyHeader.size());

    // Now write advance messages into stream
    WriteMessage(stream, MakeAdvanceMessage(15));
    WriteMessage(stream, MakeAdvanceMessage(30));

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 45);

    // Crucial check: verify stream position rewound to headerEndPos, not 0!
    const std::uint64_t rewoundPos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(rewoundPos == headerEndPos);
  }

  void TestTruncatedStream()
  {
    gpg::MemBufferStream stream(256);
    WriteMessage(stream, MakeAdvanceMessage(50));

    // Append partial packet (e.g. 2 bytes only)
    const char partialHeader[] = {'\x00', '\x07'}; // opcode 0, size low byte 7, missing rest
    stream.Write(partialHeader, sizeof(partialHeader));

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 50);

    const std::uint64_t pos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(pos == 0);
  }

  void TestSessionInfoDefaultTotalBeats()
  {
    moho::SWldSessionInfo sessionInfo{};
    CHECK(sessionInfo.mTotalBeats == 0);
  }

  void TestVCRSetupReplaySessionCalculatesTotalBeats()
  {
    const auto lengthPrefixed = [](const std::string& s) {
      return Bytes{}.U32(static_cast<std::uint32_t>(s.size())).Raw(s).data;
    };
    const std::string preamble =
      Bytes{}.Str("Supreme Commander v1.50.3835").Str("\r\n").Raw("Replay v1.9\r\n").Str("/maps/x/x.scmap").Str("\r\n\x1a").data;
    const auto makeHeader = [&](const std::string& mods, const std::string& scenario, const std::string& army) {
      return Bytes{}
        .Raw(preamble)
        .Raw(lengthPrefixed(mods))
        .Raw(lengthPrefixed(scenario))
        .U8(1).Str("player").I32(0)
        .U8(0)
        .U8(1).Raw(lengthPrefixed(army)).U8(0).U8(0xFF)
        .data;
    };
    const std::string goodMods = LuaTable(std::string{});
    const std::string goodScenario = LuaTable(LuaString("name") + LuaString("x"));
    const std::string goodArmy = LuaTable(LuaString("PlayerName") + LuaString("p"));
    const std::string seed = Bytes{}.I32(1234).data;
    const std::string header = makeHeader(goodMods, goodScenario, goodArmy) + seed;

    char directory[MAX_PATH]{};
    GetTempPathA(MAX_PATH, directory);
    const std::string path = std::string(directory) + "faf_replay_setup_test.scfareplay";

    FILE* const file = std::fopen(path.c_str(), "wb");
    CHECK(file != nullptr);
    if (file != nullptr) {
      std::fwrite(header.data(), 1, header.size(), file);

      // Write three advance packets: 10 + 25 + 65 = 100 beats
      const moho::CMessage adv1 = MakeAdvanceMessage(10);
      const moho::CMessage adv2 = MakeAdvanceMessage(25);
      const moho::CMessage adv3 = MakeAdvanceMessage(65);
      std::fwrite(adv1.mBuff.data(), 1, adv1.mBuff.size(), file);
      std::fwrite(adv2.mBuff.data(), 1, adv2.mBuff.size(), file);
      std::fwrite(adv3.mBuff.data(), 1, adv3.mBuff.size(), file);
      std::fclose(file);
    }

    msvc8::string reason;
    msvc8::auto_ptr<moho::SWldSessionInfo> sessionInfo = moho::VCR_SetupReplaySession(path.c_str(), &reason);
    std::remove(path.c_str());

    CHECK(sessionInfo.get() != nullptr);
    if (sessionInfo.get() != nullptr) {
      CHECK(sessionInfo->mIsReplay == true);
      CHECK(sessionInfo->mTotalBeats == 100);
    }
  }

  void TestCWldSessionScrubbingStateTransitions()
  {
    // Test static pending restart target
    moho::CWldSession::sPendingRestartScrubTarget = -1;
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);

    // Mock CWldSession buffer
    alignas(moho::CWldSession) std::uint8_t buffer[sizeof(moho::CWldSession)];
    std::memset(buffer, 0, sizeof(buffer));
    moho::CWldSession* const session = reinterpret_cast<moho::CWldSession*>(buffer);

    session->mScrubTargetBeat = -1;
    session->mScrubStartBeat = 0;
    session->mIsScrubbing = false;
    session->mTotalReplayBeats = 1000;
    session->mGameTick = 100;
    session->IsReplay = false;

    // Test 1: Non-replay guard - refuse to scrub if not replay
    session->StartScrubToBeat(500);
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    // Test 2: Forward scrub when IsReplay is true
    session->IsReplay = true;
    session->StartScrubToBeat(500);
    CHECK(session->IsScrubbing() == true);
    CHECK(session->mScrubStartBeat == 100);
    CHECK(session->mScrubTargetBeat == 500);
    CHECK(session->GetTotalReplayBeats() == 1000);

    // Test 3: Scrub progress calculation
    session->mGameTick = 100;
    CHECK(session->GetScrubProgress() == 0.0f);
    session->mGameTick = 300;
    CHECK(std::abs(session->GetScrubProgress() - 0.5f) < 1e-4f);
    session->mGameTick = 500;
    CHECK(session->GetScrubProgress() == 1.0f);

    // Test 4: Clamp to total replay beats
    session->mGameTick = 200;
    session->StartScrubToBeat(1500);
    CHECK(session->mScrubTargetBeat == 1000);

    // Test 5: Target <= current tick cancels/completes
    session->StartScrubToBeat(200);
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    // Test 6a: Backward seek without mLaunchInfo bails out safely
    session->mGameTick = 500;
    session->StartScrubToBeat(250);
    CHECK(session->IsScrubbing() == false);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);

    // Test 6b: Backward seek with mLaunchInfo triggers pending restart target
    struct DummyLaunchInfo : moho::LaunchInfoBase
    {
      void Create(boost::SharedPtrRaw<void>& outCreated) override {}
    };
    session->mLaunchInfo.reset(new DummyLaunchInfo());
    session->StartScrubToBeat(250);
    CHECK(session->IsScrubbing() == false);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == 250);
    session->mLaunchInfo.reset();

    // Test 7: CancelScrub resets state and clears pending restart target
    moho::CWldSession::sPendingRestartScrubTarget = 100;
    session->mIsScrubbing = true;
    session->mScrubTargetBeat = 800;
    session->CancelScrub();
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);
  }

  struct TestCase
  {
    const char* name;
    void (*func)();
  };

  const TestCase kTests[] = {
    {"empty stream", &TestEmptyStream},
    {"null stream", &TestNullStream},
    {"single advance", &TestSingleAdvanceMessage},
    {"multiple mixed messages", &TestMultipleAdvanceAndOtherMessages},
    {"stream offset rewind", &TestStreamOffsetRewind},
    {"truncated stream", &TestTruncatedStream},
    {"session info default total beats", &TestSessionInfoDefaultTotalBeats},
    {"vcr setup replay session calculates total beats", &TestVCRSetupReplaySessionCalculatesTotalBeats},
    {"wldsession scrubbing state transitions", &TestCWldSessionScrubbingStateTransitions},
  };
} // namespace

int main()
{
  for (const TestCase& test : kTests) {
    const int failuresBefore = gFailures;
    test.func();
    if (gFailures == failuresBefore) {
      std::printf("ok   %s\n", test.name);
    } else {
      std::printf("FAIL %s\n", test.name);
    }
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures;
}
