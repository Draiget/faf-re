// Engine addition, dedicated server: a player's seat (remote/ServerClient.h) with a real client
// manager: it keeps up with the server's beats whatever its player does, takes only what a player
// may send, and ends as a lockstep ejection ends.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_seat_tests
// Run:   build/linux-clang-x64-release-plain/faf_seat_tests   (exit code = failures)

#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

#include "gpg/core/streams/BinaryReader.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/EClientMsg.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/net/IMessageReceiver.h"
#include "remote/ServerClient.h"

namespace
{
  using faf::remote::CServerClient;
  using moho::ECmdStreamOp;

  int gChecks = 0;
  int gFailures = 0;

  void Check(const bool ok, const char* const what)
  {
    ++gChecks;
    if (!ok) {
      ++gFailures;
      std::printf("FAILED: %s\n", what);
    }
  }

  constexpr std::uint32_t kServerSource = 0u;
  constexpr std::uint32_t kSeatOneSource = 1u;
  constexpr std::uint32_t kSeatTwoSource = 2u;

  /** What the sim would get, in order: each op's type, and the source for `SetCommandSource`. */
  class CMergedStream final : public moho::IMessageReceiver
  {
  public:
    struct SEntry
    {
      std::uint8_t type;
      int source;
    };

    void ReceiveMessage(moho::CMessage* const message, moho::CMessageDispatcher*) override
    {
      SEntry entry{message->GetType().raw(), -1};
      if (entry.type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_SetCommandSource)) {
        moho::CMessageStream stream(*message, moho::CMessageStream::Access::kReadOnly);
        gpg::BinaryReader reader(&stream);
        std::uint8_t source = 0xFFu;
        reader.ReadExact(source);
        entry.source = source;
      }
      mEntries.push_back(entry);
    }

    [[nodiscard]] int Count(const ECmdStreamOp op) const
    {
      int count = 0;
      for (const SEntry& entry : mEntries) {
        count += entry.type == static_cast<std::uint8_t>(op) ? 1 : 0;
      }
      return count;
    }

    /** The source named last before the first `op`; -1: none. */
    [[nodiscard]] int SourceOf(const ECmdStreamOp op) const
    {
      int source = -1;
      for (const SEntry& entry : mEntries) {
        if (entry.source >= 0) {
          source = entry.source;
        } else if (entry.type == static_cast<std::uint8_t>(op)) {
          return source;
        }
      }
      return -1;
    }

    std::vector<SEntry> mEntries;
  };

  /** A manager as the server makes one: its own client, then two seats. */
  struct SGame
  {
    SGame()
      : manager(moho::CLIENT_CreateClientManager(3u, nullptr, 0, false))
    {
      manager->CreateLocalClient("Server", 0, 0, kServerSource);
      one = &CServerClient::Create(*manager, "One", 1, 1, kSeatOneSource);
      two = &CServerClient::Create(*manager, "Two", 2, 2, kSeatTwoSource);
      manager->PushReceiver(0u, 0x32u, &merged);
    }

    void IssueBeats(const std::int32_t beats)
    {
      moho::CMessage advance(ECmdStreamOp::CMDST_Advance);
      moho::CMessageStream stream(advance);
      stream.Write(beats);
      manager->ProcessClients(advance);
    }

    [[nodiscard]] int Available()
    {
      manager->DoBeat();
      int beat = 0;
      manager->GetAvailableBeat(beat);
      return beat;
    }

    [[nodiscard]] static std::uint32_t Queued(moho::IClient& client)
    {
      std::uint32_t beat = 0u;
      client.GetQueuedBeat(beat);
      return beat;
    }

    CMergedStream merged;
    std::unique_ptr<moho::CClientManagerImpl> manager;
    CServerClient* one = nullptr;
    CServerClient* two = nullptr;
  };

  void Policy()
  {
    using faf::remote::SeatMaySend;
    int allowed = 0;
    for (std::size_t op = 0; op < CServerClient::kOpCount; ++op) {
      allowed += SeatMaySend(static_cast<ECmdStreamOp>(op)) ? 1 : 0;
    }
    Check(allowed == 12, "a player may send 12 kinds of op");
    for (const ECmdStreamOp op : {ECmdStreamOp::CMDST_IssueCommand, ECmdStreamOp::CMDST_LuaSimCallback, ECmdStreamOp::CMDST_RequestPause}) {
      Check(SeatMaySend(op), "orders, callbacks and pause are a player's");
    }
    for (const ECmdStreamOp op :
         {ECmdStreamOp::CMDST_Advance, ECmdStreamOp::CMDST_SetCommandSource, ECmdStreamOp::CMDST_CommandSourceTerminated,
          ECmdStreamOp::CMDST_VerifyChecksum, ECmdStreamOp::CMDST_EndGame}) {
      Check(!SeatMaySend(op), "beats, sources, checksums and the game's end are the server's");
    }
    for (const ECmdStreamOp op :
         {ECmdStreamOp::CMDST_CreateUnit, ECmdStreamOp::CMDST_CreateProp, ECmdStreamOp::CMDST_DestroyEntity, ECmdStreamOp::CMDST_WarpEntity,
          ECmdStreamOp::CMDST_DebugCommand, ECmdStreamOp::CMDST_ExecuteLuaInSim, ECmdStreamOp::CMDST_SingleStep}) {
      Check(!SeatMaySend(op), "cheat and debug ops are refused");
    }
  }

  void SilentSeatsNeverHoldTheGame()
  {
    SGame game;
    game.IssueBeats(1);
    Check(SGame::Queued(*game.one) == 1u && SGame::Queued(*game.two) == 1u, "a beat is queued on every seat");
    Check(game.Available() == 1, "the beat is available though no player sent anything");
    game.IssueBeats(5);
    Check(SGame::Queued(*game.one) == 6u && SGame::Queued(*game.two) == 6u, "several beats at once are all queued");
    Check(game.Available() == 6, "and all available");
  }

  void CommandsGoInTheNextBeatUnderTheSeatsSource()
  {
    SGame game;
    moho::CMessage pause(ECmdStreamOp::CMDST_RequestPause);
    Check(game.two->ReceiveCommand(pause), "a player's pause is taken");
    Check(SGame::Queued(*game.two) == 0u, "a command queues no beat");
    Check(game.Available() == 0, "and makes no beat available");
    game.IssueBeats(1);
    (void)game.Available();
    game.manager->UpdateStates(1);
    Check(game.merged.Count(ECmdStreamOp::CMDST_RequestPause) == 1, "the sim gets it");
    Check(game.merged.SourceOf(ECmdStreamOp::CMDST_RequestPause) == static_cast<int>(kSeatTwoSource), "under that seat's source");
  }

  void ForgedOpsNeverReachTheSim()
  {
    SGame game;
    moho::CMessage advance(ECmdStreamOp::CMDST_Advance);
    moho::CMessageStream advanceStream(advance);
    const std::int32_t beats = 100000;
    advanceStream.Write(beats);
    Check(!game.one->ReceiveCommand(advance), "a player's beats are refused");
    Check(SGame::Queued(*game.one) == 0u, "and queue nothing");
    Check(game.one->Refused(ECmdStreamOp::CMDST_Advance) == 1u, "and are counted");

    moho::CMessage source(ECmdStreamOp::CMDST_SetCommandSource);
    moho::CMessageStream sourceStream(source);
    const auto stolen = static_cast<std::uint8_t>(kSeatTwoSource);
    sourceStream.Write(stolen);
    Check(!game.one->ReceiveCommand(source), "a player can't claim another source");

    moho::CMessage end(ECmdStreamOp::CMDST_EndGame);
    Check(!game.one->ReceiveCommand(end), "a player can't end the game");
    moho::CMessage warp(ECmdStreamOp::CMDST_WarpEntity);
    Check(!game.one->ReceiveCommand(warp), "a player can't warp a unit");
    moho::CMessage unknown(moho::MessageType(static_cast<std::uint8_t>(40u)));
    Check(!game.one->ReceiveCommand(unknown), "a type that is no command is refused");
    moho::CMessage ack(moho::EClientMsg::CLIMSG_Ack);
    Check(!game.one->ReceiveCommand(ack), "a player can't send client messages as commands");

    game.IssueBeats(1);
    (void)game.Available();
    game.manager->UpdateStates(1);
    Check(game.merged.Count(ECmdStreamOp::CMDST_EndGame) == 0, "the sim never sees them");
    Check(game.merged.Count(ECmdStreamOp::CMDST_WarpEntity) == 0, "the sim never sees them");
  }

  void EjectionEndsTheSourceAndFreesTheGame()
  {
    SGame game;
    game.IssueBeats(1);
    (void)game.Available();
    game.manager->UpdateStates(1);
    game.two->Eject();
    Check(!game.two->NoEjectionPending(), "the seat is ending");

    moho::CMessage pause(ECmdStreamOp::CMDST_RequestPause);
    Check(!game.two->ReceiveCommand(pause), "an ending seat takes nothing");

    game.IssueBeats(1);
    Check(SGame::Queued(*game.two) == 1u, "an ending seat queues no more beats");
    Check(game.Available() == 2, "and holds nothing up");
    game.manager->UpdateStates(2);
    Check(game.merged.Count(ECmdStreamOp::CMDST_CommandSourceTerminated) == 1, "the sim is told, as in a lockstep ejection");
    Check(game.merged.SourceOf(ECmdStreamOp::CMDST_CommandSourceTerminated) == static_cast<int>(kSeatTwoSource), "for that source");

    game.IssueBeats(1);
    Check(game.Available() == 3, "the game goes on");
    game.manager->UpdateStates(3);
    Check(game.merged.Count(ECmdStreamOp::CMDST_CommandSourceTerminated) == 1, "and it's said once");
  }

  void TheHookRunsAheadOfEachBeat()
  {
    SGame game;
    std::vector<std::int32_t> beats;
    game.one->SetBeatHook([&beats](CServerClient& seat, const std::int32_t beat) {
      beats.push_back(beat);
      std::uint32_t queued = 0u;
      seat.GetQueuedBeat(queued);
      Check(static_cast<std::int32_t>(queued) == beat, "the beat isn't queued yet");
    });
    game.IssueBeats(3);
    Check(beats.size() == 3u && beats[0] == 0 && beats[1] == 1 && beats[2] == 2, "once per beat, in order");
  }

  void LoadedCountsForTheStart()
  {
    SGame game;
    game.manager->Cleanup();
    (void)game.Available();
    Check(!game.manager->IsEveryoneReady(), "the game waits for players to load");
    game.one->MarkLoaded();
    (void)game.Available();
    Check(!game.manager->IsEveryoneReady(), "for every one of them");
    game.two->MarkLoaded();
    (void)game.Available();
    Check(game.manager->IsEveryoneReady(), "and starts when they have");
  }
} // namespace

int main()
{
  Policy();
  SilentSeatsNeverHoldTheGame();
  CommandsGoInTheNextBeatUnderTheSeatsSource();
  ForgedOpsNeverReachTheSim();
  EjectionEndsTheSourceAndFreesTheGame();
  TheHookRunsAheadOfEachBeat();
  LoadedCountsForTheStart();
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures;
}
