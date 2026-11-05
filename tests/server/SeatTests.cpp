// Engine addition, dedicated server: a player's seat (remote/ServerClient.h) with a real client
// manager: it keeps up with the server's beats whatever its player does, takes only what a player
// may send, and ends as a lockstep ejection ends.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_seat_tests
// Run:   build/linux-clang-x64-release-plain/faf_seat_tests   (exit code = failures)

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "gpg/core/streams/BinaryReader.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/EClientMsg.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/net/IMessageReceiver.h"
#include "remote/ServerClient.h"
#include "remote/ViewIdMap.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "server/SeatIntake.h"

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
      if (entry.type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_IssueCommand)) {
        mLastOrder.assign(message->mBuff.start_, message->mBuff.start_ + message->mBuff.Size());
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
    std::vector<char> mLastOrder; // as the sim gets it, its header too
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

  void PutU32(std::vector<std::uint8_t>& out, const std::uint32_t value)
  {
    for (int shift = 0; shift < 32; shift += 8) {
      out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
  }

  /** A whole stream message, as a player sends one. */
  [[nodiscard]] std::vector<std::uint8_t> Command(const ECmdStreamOp op, const std::vector<std::uint8_t>& payload = {})
  {
    const std::size_t whole = 3u + payload.size();
    std::vector<std::uint8_t> out{static_cast<std::uint8_t>(op), static_cast<std::uint8_t>(whole), static_cast<std::uint8_t>(whole >> 8)};
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
  }

  // Where an order's target id lies: header, one unit in the set, command ids, type, index, target's kind.
  constexpr std::size_t kOrderTargetAt = 3u + 8u + 8u + 1u + 4u + 1u;

  /** An attack order: `unit` on the entity `target`, with command id `commandId`. */
  [[nodiscard]] std::vector<std::uint8_t> AttackOrder(const std::uint32_t unit, const std::uint32_t commandId, const std::uint32_t target)
  {
    std::vector<std::uint8_t> payload;
    PutU32(payload, 1u);
    PutU32(payload, unit);
    PutU32(payload, commandId);
    PutU32(payload, 0xFFFFFFFFu);
    payload.push_back(static_cast<std::uint8_t>(moho::EUnitCommandType::UNITCOMMAND_Attack));
    PutU32(payload, 0xFFFFFFFFu);
    payload.push_back(1u); // AITARGET_Entity
    PutU32(payload, target);
    payload.push_back(0u); // AITARGET_None
    PutU32(payload, 0xFFFFFFFFu);
    payload.push_back(0u); // no blueprint
    PutU32(payload, 0u);   // no cells
    PutU32(payload, 1u);
    PutU32(payload, 1u);
    payload.push_back(2u); // Lua nil
    payload.push_back(1u); // clear the queue
    return Command(ECmdStreamOp::CMDST_IssueCommand, payload);
  }

  void TheIntakeHandsOnWhatItCanTranslate()
  {
    using faf::remote::net::ECommandAnswer;
    SGame game;
    faf::server::CSeatIntake intake;
    intake.AddSeat(1, *game.one);
    intake.SetArmy(1, 0);

    faf::remote::CViewIdMap map(0);
    constexpr std::uint32_t kSimBlip = 0x30100123u; // an enemy's blip: family 3, source byte 1
    const std::uint32_t viewBlip = map.EntityId(kSimBlip);
    Check(viewBlip != kSimBlip, "a blip has its own number in a view");

    constexpr std::uint32_t kSeenUnit = 0x00100009u;
    constexpr std::uint32_t kHiddenUnit = 0x00100007u;
    std::vector<std::pair<std::uint64_t, ECommandAnswer>> answers;
    const auto drain = [&] {
      intake.Drain(
        nullptr, [&map](const std::int32_t army) -> const faf::remote::CViewIdMap* { return army == 0 ? &map : nullptr; },
        [](const std::int32_t army, const std::uint32_t id) { return army == 0 && id == kSeenUnit; },
        [&answers](const std::int32_t uid, std::vector<std::uint8_t> message) {
          Check(uid == 1, "the answer goes to who asked");
          faf::remote::net::ByteReader reader(message.data(), message.size());
          Check(reader.Byte() == static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::CommandAnswer), "it's an answer");
          const std::uint64_t beat = reader.Varint();
          const auto answer = static_cast<ECommandAnswer>(reader.Byte());
          Check(reader.Ok() && reader.AtEnd(), "and nothing else");
          answers.emplace_back(beat, answer);
        }
      );
    };
    const auto push = [&intake](const std::vector<std::uint8_t>& command) { return intake.Push(1, command.data(), command.size()); };

    // In the order sent, each answered, whichever way it ends.
    game.IssueBeats(3);
    (void)game.Available();
    const std::vector<std::uint8_t> order = AttackOrder(0x00000001u, 0x01000001u, viewBlip);
    Check(push(order), "an order is taken");
    Check(push(AttackOrder(0x00000001u, 0x01000002u, 0x3FFFFFFFu)), "so is one naming what the view never saw, for now");
    std::vector<std::uint8_t> truncated = order;
    truncated.resize(order.size() - 8u);
    truncated[1] = static_cast<std::uint8_t>(truncated.size());
    truncated[2] = static_cast<std::uint8_t>(truncated.size() >> 8);
    Check(push(truncated), "and one cut short");
    Check(push(Command(ECmdStreamOp::CMDST_CreateUnit)), "and a cheat");
    Check(push(Command(ECmdStreamOp::CMDST_RequestPause)), "and a pause");
    drain();
    Check(answers.size() == 5u, "every command gets an answer");
    if (answers.size() == 5u) {
      Check(answers[0].second == ECommandAnswer::Applied && answers[0].first == 3u, "the order applied, in the next beat");
      Check(answers[1].second == ECommandAnswer::Dropped, "an id the view was never given stops it");
      Check(answers[2].second == ECommandAnswer::Dropped, "a command that doesn't decode stops");
      Check(answers[3].second == ECommandAnswer::Refused, "a cheat is refused");
      Check(answers[4].second == ECommandAnswer::Applied && answers[4].first == 3u, "a pause applied");
    }
    Check(intake.Applied() == 2u && intake.Dropped() == 2u && intake.Refused() == 1u, "and they're counted");
    Check(intake.IdsTranslated() >= 1u, "the blip's id was translated");

    game.IssueBeats(1);
    (void)game.Available();
    game.manager->UpdateStates(4);
    Check(game.merged.Count(ECmdStreamOp::CMDST_IssueCommand) == 1, "only the good order reaches the sim");
    Check(game.merged.SourceOf(ECmdStreamOp::CMDST_IssueCommand) == static_cast<int>(kSeatOneSource), "under the seat's source");
    Check(game.merged.mLastOrder.size() == order.size(), "the same size as sent");
    if (game.merged.mLastOrder.size() == order.size()) {
      std::uint32_t target = 0u;
      std::memcpy(&target, game.merged.mLastOrder.data() + kOrderTargetAt, sizeof(target));
      Check(target == kSimBlip, "with the sim's id for the blip");
      std::vector<char> expected(order.begin(), order.end());
      std::memcpy(expected.data() + kOrderTargetAt, &kSimBlip, sizeof(kSimBlip));
      Check(std::memcmp(expected.data(), game.merged.mLastOrder.data(), expected.size()) == 0, "and otherwise the bytes sent");
    }

    // A real unit keeps the sim's number, so anyone can guess one: it must be one the view holds.
    answers.clear();
    Check(push(AttackOrder(0x00000001u, 0x01000003u, kHiddenUnit)), "an order on a unit the view doesn't hold is taken");
    Check(push(AttackOrder(0x00000001u, 0x01000004u, kSeenUnit)), "and one on a unit it does");
    drain();
    Check(answers.size() == 2u, "both are answered");
    if (answers.size() == 2u) {
      Check(answers[0].second == ECommandAnswer::Dropped, "a target the view doesn't hold stops the order");
      Check(answers[1].second == ECommandAnswer::Applied, "a target it holds doesn't");
    }

    // A flood waits its turn, and past the limit the player is told on.
    answers.clear();
    const std::vector<std::uint8_t> pause = Command(ECmdStreamOp::CMDST_RequestPause);
    for (std::size_t i = 0; i < faf::server::CSeatIntake::kMaxCommandsPerBeat + 10u; ++i) {
      (void)push(pause);
    }
    drain();
    Check(answers.size() == faf::server::CSeatIntake::kMaxCommandsPerBeat, "one beat takes only so many");
    drain();
    Check(answers.size() == faf::server::CSeatIntake::kMaxCommandsPerBeat + 10u, "the rest go next beat");
    answers.clear();
    std::size_t taken = 0;
    for (std::size_t i = 0; i < faf::server::CSeatIntake::kMaxWaiting + 10u; ++i) {
      taken += push(pause) ? 1u : 0u;
    }
    Check(taken == faf::server::CSeatIntake::kMaxWaiting, "and only so many can wait");
    intake.Forget(1);
    drain();
    Check(answers.empty(), "what a player leaves behind goes with them");

    // Big commands wait too.
    SGame other;
    faf::server::CSeatIntake bytes;
    bytes.AddSeat(1, *other.one);
    const std::vector<std::uint8_t> big = Command(ECmdStreamOp::CMDST_RequestPause, std::vector<std::uint8_t>(40000u, 0u));
    (void)bytes.Push(1, big.data(), big.size());
    (void)bytes.Push(1, big.data(), big.size());
    std::size_t answered = 0;
    const auto count = [&answered](std::int32_t, std::vector<std::uint8_t>) { ++answered; };
    const auto noMaps = [](std::int32_t) -> const faf::remote::CViewIdMap* { return nullptr; };
    const auto holdsNothing = [](std::int32_t, std::uint32_t) { return false; };
    bytes.Drain(nullptr, noMaps, holdsNothing, count);
    Check(answered == 1u, "one beat takes only so many bytes");
    bytes.Drain(nullptr, noMaps, holdsNothing, count);
    Check(answered == 2u, "and the next takes the rest");
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
  TheIntakeHandsOnWhatItCanTranslate();
  LoadedCountsForTheStart();
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures;
}
