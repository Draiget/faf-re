// Engine addition, dedicated server: a player's seat (remote/ServerClient.h) with a real client
// manager: it keeps up with the server's beats whatever its player does, takes only what a player
// may send, and ends as a lockstep ejection ends.
//
// Build: cmake --build --preset linux-clang-x64-release-plain --target faf_seat_tests
// Run:   build/linux-clang-x64-release-plain/faf_seat_tests   (exit code = failures)

#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "gpg/core/streams/BinaryReader.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/EClientMsg.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/net/IMessageReceiver.h"
#include "netlink/EngineLinks.h"
#include "remote/ServerClient.h"
#include "remote/client/ServerRelayConnector.h"
#include "remote/client/ViewMerge.h"
#include "remote/ViewIdMap.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/net/LobbySignals.h"
#include "server/LobbySignaller.h"
#include "server/LobbyRelay.h"
#include "server/SeatIntake.h"

namespace
{
  using faf::remote::CServerClient;
  using moho::ECmdStreamOp;

  void Check(const bool ok, const char* const what)
  {
    EXPECT_TRUE(ok) << what;
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

TEST(Existing_Seat, Policy) { Policy(); }
TEST(Existing_Seat, SilentSeatsNeverHoldTheGame) { SilentSeatsNeverHoldTheGame(); }
TEST(Existing_Seat, CommandsGoInTheNextBeatUnderTheSeatsSource) { CommandsGoInTheNextBeatUnderTheSeatsSource(); }
TEST(Existing_Seat, ForgedOpsNeverReachTheSim) { ForgedOpsNeverReachTheSim(); }
TEST(Existing_Seat, EjectionEndsTheSourceAndFreesTheGame) { EjectionEndsTheSourceAndFreesTheGame(); }
TEST(Existing_Seat, TheHookRunsAheadOfEachBeat) { TheHookRunsAheadOfEachBeat(); }
TEST(Existing_Seat, TheIntakeHandsOnWhatItCanTranslate) { TheIntakeHandsOnWhatItCanTranslate(); }
TEST(Existing_Seat, LoadedCountsForTheStart) { LoadedCountsForTheStart(); }

// Plan WP2.13, WPR.51: the lobby relay (server/LobbyRelay.h).
namespace
{
  using faf::server::CLobbyRelay;
  using faf::server::ELobbyRelayVerdict;
  using faf::server::SLobbyRelayLimits;

  /** A Lobby frame's body: varint `to`, then `message`. */
  std::vector<std::uint8_t> LobbyBody(const std::uint32_t to, const std::vector<std::uint8_t>& message)
  {
    std::vector<std::uint8_t> body;
    faf::remote::net::ByteWriter writer(body);
    writer.Varint(to);
    writer.Bytes(message.data(), message.size());
    return body;
  }

  struct SRelayed
  {
    ELobbyRelayVerdict verdict;
    std::int32_t to = -1;
    std::vector<std::uint8_t> frame;
    std::vector<std::uint8_t> message;
  };

  SRelayed Relay(CLobbyRelay& relay, const std::int32_t from, const std::vector<std::uint8_t>& body, const std::uint64_t nowUs)
  {
    SRelayed result{};
    std::span<const std::uint8_t> message;
    result.verdict = relay.Take(from, body, nowUs, result.to, result.frame, message);
    result.message.assign(message.begin(), message.end());
    return result;
  }
} // namespace

TEST(LobbyRelay, ForwardsWithTheSenderTheServerWrites)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  const std::vector<std::uint8_t> hello = {7u, 1u, 2u, 3u};
  const SRelayed relayed = Relay(relay, 1001, LobbyBody(1002, hello), 1'000'000u);
  ASSERT_EQ(relayed.verdict, ELobbyRelayVerdict::Forward);
  EXPECT_EQ(relayed.to, 1002);
  std::vector<std::uint8_t> expected;
  faf::remote::net::ByteWriter writer(expected);
  writer.Byte(static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::Lobby));
  writer.Varint(1001u);
  writer.Bytes(hello.data(), hello.size());
  EXPECT_EQ(relayed.frame, expected);

  // Uid 0 is the server, the lobby's host.
  const SRelayed toServer = Relay(relay, 1002, LobbyBody(0, hello), 1'000'000u);
  EXPECT_EQ(toServer.verdict, ELobbyRelayVerdict::ToServer);
  EXPECT_EQ(toServer.message, hello);
  const std::vector<std::uint8_t> fromServer = CLobbyRelay::FrameFromServer(hello);
  EXPECT_EQ(fromServer, (std::vector<std::uint8_t>{static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::Lobby), 0u, 7u, 1u, 2u, 3u}));
}

TEST(LobbyRelay, OnlyBetweenParticipants)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  const std::vector<std::uint8_t> hello = {1u};
  EXPECT_EQ(Relay(relay, 999, LobbyBody(1001, hello), 1u).verdict, ELobbyRelayVerdict::UnknownSender);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1003, hello), 1u).verdict, ELobbyRelayVerdict::UnknownTarget);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1001, hello), 1u).verdict, ELobbyRelayVerdict::UnknownTarget);
  relay.RemoveParticipant(1002);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, hello), 1u).verdict, ELobbyRelayVerdict::UnknownTarget);
  EXPECT_EQ(Relay(relay, 1002, LobbyBody(1001, hello), 1u).verdict, ELobbyRelayVerdict::UnknownSender);
}

TEST(LobbyRelay, MalformedFramesAreDropped)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  EXPECT_EQ(Relay(relay, 1001, {}, 1u).verdict, ELobbyRelayVerdict::Malformed);                       // nothing
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, {}), 1u).verdict, ELobbyRelayVerdict::Malformed);      // no message
  EXPECT_EQ(Relay(relay, 1001, {0xEAu, 0x87u}, 1u).verdict, ELobbyRelayVerdict::Malformed);           // a uid cut short
  EXPECT_EQ(Relay(relay, 1001, {0xEAu, 0x87u, 0x80u, 0x00u, 5u}, 1u).verdict, ELobbyRelayVerdict::Malformed); // a long form
  EXPECT_EQ(Relay(relay, 1001, {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x0Fu, 5u}, 1u).verdict, ELobbyRelayVerdict::Malformed); // past 31 bits
}

TEST(LobbyRelay, CapsEachSendersSizeAndRate)
{
  SLobbyRelayLimits limits;
  limits.maxMessageBytes = 100;
  limits.bytesPerSecond = 1000.0;
  limits.burstBytes = 2000.0;
  limits.messagesPerSecond = 10.0;
  limits.burstMessages = 5.0;
  CLobbyRelay relay(limits);
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  relay.AddParticipant(1003);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, std::vector<std::uint8_t>(101u, 1u)), 1'000'000u).verdict, ELobbyRelayVerdict::TooLarge);

  // Five messages at once, then the sixth waits for the bucket to fill (10 a second: 0.1 s each).
  const std::vector<std::uint8_t> small(10u, 1u);
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, small), 1'000'000u).verdict, ELobbyRelayVerdict::Forward) << i;
  }
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, small), 1'000'000u).verdict, ELobbyRelayVerdict::TooFast);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, small), 1'050'000u).verdict, ELobbyRelayVerdict::TooFast);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, small), 1'110'000u).verdict, ELobbyRelayVerdict::Forward);
  // Another sender has a bucket of its own.
  EXPECT_EQ(Relay(relay, 1003, LobbyBody(1002, small), 1'110'000u).verdict, ELobbyRelayVerdict::Forward);

  // Bytes: 2000 at once, then 1000 a second; messages plentiful, so only bytes run out.
  SLobbyRelayLimits byteLimits = limits;
  byteLimits.messagesPerSecond = 1000.0;
  byteLimits.burstMessages = 1000.0;
  CLobbyRelay bytes(byteLimits);
  bytes.AddParticipant(1001);
  bytes.AddParticipant(1002);
  const std::vector<std::uint8_t> big(100u, 1u);
  int sent = 0;
  std::uint64_t now = 10'000'000u;
  for (int i = 0; i < 80; ++i, now += 50'000u) { // 2000 bytes a second asked for, over 3.95 s
    sent += Relay(bytes, 1001, LobbyBody(1002, big), now).verdict == ELobbyRelayVerdict::Forward ? 1 : 0;
  }
  // The 2000-byte burst plus 3.95 s at 1000 a second: about 5950 bytes, 59 of the 80 messages.
  EXPECT_GE(sent, 57);
  EXPECT_LE(sent, 61);
  EXPECT_EQ(bytes.Count(ELobbyRelayVerdict::TooFast), static_cast<std::uint64_t>(80 - sent));
}

TEST(LobbyRelay, ClosedAtLaunch)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  relay.Close();
  EXPECT_FALSE(relay.Open());
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, {1u}), 1u).verdict, ELobbyRelayVerdict::Closed);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(0, {1u}), 1u).verdict, ELobbyRelayVerdict::Closed);
  EXPECT_EQ(relay.Count(ELobbyRelayVerdict::Closed), 2u);
}

// Plan WP2.2, WP2.12: the server's lobby signals (remote/net/LobbySignals.h, server/LobbySignaller.h).
namespace
{
  using faf::remote::net::ELobbySignal;
  using faf::remote::net::SLobbySignal;
  using faf::server::CLobbySignaller;

  SLobbySignal Decoded(const std::vector<std::uint8_t>& message)
  {
    SLobbySignal signal;
    EXPECT_TRUE(faf::remote::net::DecodeLobbySignal(message, signal));
    return signal;
  }

  /** The signals for `uid`, in order, as "kind uid name text". */
  std::vector<std::string> SignalsTo(const std::vector<CLobbySignaller::SOutgoing>& out, const std::int32_t uid)
  {
    std::vector<std::string> mine;
    for (const CLobbySignaller::SOutgoing& message : out) {
      if (message.to == uid) {
        const SLobbySignal signal = Decoded(message.message);
        mine.push_back(std::to_string(static_cast<int>(signal.kind)) + " " + std::to_string(signal.uid) + " " + signal.name + " " + signal.text);
      }
    }
    return mine;
  }
} // namespace

TEST(LobbySignals, RoundTripAndRefuseWhatIsNotOne)
{
  for (const SLobbySignal& signal :
       {SLobbySignal{ELobbySignal::Host, faf::remote::net::kLobbySignalAutoLobby, 0, "Ann", "/maps/x/x_scenario.lua"},
        SLobbySignal{ELobbySignal::Join, 0, 1001, "Bo", "Ann"}, SLobbySignal{ELobbySignal::ConnectToPeer, 0, 0x7FFFFFFF, "Cy", ""},
        SLobbySignal{ELobbySignal::DisconnectFromPeer, 0, 1003, "", ""}, SLobbySignal{ELobbySignal::LaunchRefused, 0, 0, "", "the map"},
        SLobbySignal{ELobbySignal::Launching, 0, 0, "", ""}}) {
    const SLobbySignal back = Decoded(faf::remote::net::EncodeLobbySignal(signal));
    EXPECT_EQ(back.kind, signal.kind);
    EXPECT_EQ(back.flags, signal.flags);
    EXPECT_EQ(back.uid, signal.uid);
    EXPECT_EQ(back.name, signal.name);
    EXPECT_EQ(back.text, signal.text);
  }
  SLobbySignal out;
  std::vector<std::uint8_t> bytes = faf::remote::net::EncodeLobbySignal(SLobbySignal{ELobbySignal::Join, 0, 1001, "Bo", "Ann"});
  bytes.push_back(0u);
  EXPECT_FALSE(faf::remote::net::DecodeLobbySignal(bytes, out)); // bytes left over
  bytes.pop_back();
  bytes.pop_back();
  EXPECT_FALSE(faf::remote::net::DecodeLobbySignal(bytes, out)); // cut short
  bytes = faf::remote::net::EncodeLobbySignal(SLobbySignal{ELobbySignal::Join, 0, 1001, "Bo", "Ann"});
  bytes[0] = 9u;
  EXPECT_FALSE(faf::remote::net::DecodeLobbySignal(bytes, out)); // no such kind
  const std::vector<std::uint8_t> longName = {2u, 0u, 1u, 0x81u, 0x02u}; // a 257-byte name
  EXPECT_FALSE(faf::remote::net::DecodeLobbySignal(longName, out));
}

TEST(LobbySignaller, RolesWaitForTheHostThenEveryPairIsIntroduced)
{
  CLobbySignaller signaller("/maps/m/m_scenario.lua");
  signaller.AddParticipant(1001, "Ann"); // first in the match: the logical host
  signaller.AddParticipant(1002, "Bo");
  signaller.AddParticipant(1003, "Cy");
  EXPECT_EQ(signaller.Host(), 1001);
  std::vector<CLobbySignaller::SOutgoing> out;

  // Bo is in before the host: nothing yet.
  signaller.OnJoined(1002, out);
  EXPECT_TRUE(out.empty());
  EXPECT_EQ(signaller.InLobby(), 0u);

  // The host comes: it hosts, learns of Bo before Bo learns whom to join.
  signaller.OnJoined(1001, out);
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[0].to, 1001);
  EXPECT_EQ(SignalsTo(out, 1001), (std::vector<std::string>{"1 0 Ann /maps/m/m_scenario.lua", "3 1002 Bo "}));
  EXPECT_EQ(out[2].to, 1002);
  EXPECT_EQ(SignalsTo(out, 1002), (std::vector<std::string>{"2 1001 Bo Ann"}));
  EXPECT_EQ(signaller.InLobby(), 2u);

  // Cy: the host first, then Cy joins, then Bo and Cy both ways.
  out.clear();
  signaller.OnJoined(1003, out);
  EXPECT_EQ(SignalsTo(out, 1001), (std::vector<std::string>{"3 1003 Cy "}));
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"2 1001 Cy Ann", "3 1002 Bo "}));
  EXPECT_EQ(SignalsTo(out, 1002), (std::vector<std::string>{"3 1003 Cy "}));
  EXPECT_EQ(out.front().to, 1001);

  // Twice in, someone not in the match: nothing.
  out.clear();
  signaller.OnJoined(1003, out);
  signaller.OnJoined(999, out);
  EXPECT_TRUE(out.empty());

  // Bo leaves: the rest are told; the host leaves: the lobby can't go on.
  signaller.OnLeft(1002, out);
  EXPECT_EQ(SignalsTo(out, 1001), (std::vector<std::string>{"4 1002 Bo "}));
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"4 1002 Bo "}));
  out.clear();
  signaller.OnLeft(1001, out);
  EXPECT_TRUE(signaller.HostLeft());
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"4 1001 Ann "}));
  EXPECT_EQ(signaller.InLobby(), 1u);
}

TEST(LobbySignaller, AJoinerWhoLeftBeforeItsRoleIsNotAnnounced)
{
  CLobbySignaller signaller("");
  signaller.AddParticipant(1001, "Ann");
  signaller.AddParticipant(1002, "Bo");
  std::vector<CLobbySignaller::SOutgoing> out;
  signaller.OnJoined(1002, out);
  signaller.OnLeft(1002, out);
  signaller.OnJoined(1001, out);
  EXPECT_EQ(SignalsTo(out, 1001), (std::vector<std::string>{"1 0 Ann "}));
  EXPECT_TRUE(SignalsTo(out, 1002).empty());
}

// Plan WP2.13, WP12.1: the client's relay connector (remote/client/ServerRelayConnector.h) against the server's relay
// and signals in one process. `CLobby` isn't in this build, so the test makes its calls as the signals ask: the host
// accepts each participant it is told of (`ConnectToPeer`), a joiner connects to the host and sends Join on ConnMade.
namespace
{
  using faf::remote::CLobbyInbox;
  using faf::remote::CServerRelayConnector;
  using faf::remote::IRelayChannel;

  /** One client's channel to the in-process server, its frames in a `CLobbyInbox` as the client's are. */
  struct SLoopChannel final : IRelayChannel
  {
    std::vector<std::vector<std::uint8_t>> out;
    CLobbyInbox inbox;
    std::vector<std::int32_t> gone;
    bool up = true;

    void SendLobbyFrame(const std::span<const std::uint8_t> frame) override { out.emplace_back(frame.begin(), frame.end()); }
    bool TakeLobbyFrame(std::vector<std::uint8_t>& frame) override { return inbox.TakeLobbyFrame(frame); }
    bool Up() const override { return up; }
    void TakeGone(std::vector<std::int32_t>& uids) override
    {
      uids.insert(uids.end(), gone.begin(), gone.end());
      gone.clear();
    }
  };

  /** What a lobby would receive: each message's type and bytes, and the connection it came on. */
  struct SRecorder final : moho::IMessageReceiver
  {
    struct SReceived
    {
      std::uint8_t type;
      std::vector<std::uint8_t> bytes;
      moho::INetConnection* connection;
    };
    std::vector<SReceived> received;

    void ReceiveMessage(moho::CMessage* const message, moho::CMessageDispatcher* const dispatcher) override
    {
      const auto* const start = reinterpret_cast<const std::uint8_t*>(message->mBuff.start_);
      received.push_back(
        SReceived{start[0], std::vector<std::uint8_t>(start, start + message->mBuff.Size()), static_cast<moho::INetConnection*>(dispatcher)}
      );
    }
    [[nodiscard]] std::size_t Count(const std::uint8_t type, const moho::INetConnection* const on) const
    {
      return static_cast<std::size_t>(
        std::count_if(received.begin(), received.end(), [&](const SReceived& r) { return r.type == type && r.connection == on; })
      );
    }
  };

  /** The server: the relay between clients, and the signals it sends as participants come and go. */
  struct SLoopServer
  {
    CLobbyRelay relay;
    CLobbySignaller signaller{"/maps/m/m_scenario.lua"};
    std::map<std::int32_t, SLoopChannel*> clients;

    void Signal(const std::vector<CLobbySignaller::SOutgoing>& out)
    {
      for (const CLobbySignaller::SOutgoing& message : out) {
        clients.at(message.to)->inbox.Push(CLobbyRelay::FrameFromServer(message.message));
      }
    }
    void Joined(const std::int32_t uid)
    {
      std::vector<CLobbySignaller::SOutgoing> out;
      signaller.OnJoined(uid, out);
      Signal(out);
    }
    void Left(const std::int32_t uid)
    {
      std::vector<CLobbySignaller::SOutgoing> out;
      signaller.OnLeft(uid, out);
      Signal(out);
    }
    void Pump()
    {
      for (auto& [uid, channel] : clients) {
        for (const std::vector<std::uint8_t>& frame : std::exchange(channel->out, {})) {
          std::int32_t to = 0;
          std::vector<std::uint8_t> forward;
          std::span<const std::uint8_t> message;
          if (relay.Take(uid, std::span<const std::uint8_t>(frame).subspan(1), 1'000'000u, to, forward, message) == ELobbyRelayVerdict::Forward) {
            clients.at(to)->inbox.Push(forward);
          }
        }
      }
    }
  };

  void WriteMessage(moho::INetConnection& connection, const std::vector<std::uint8_t>& message)
  {
    std::vector<std::uint8_t> copy = message;
    moho::NetDataSpan span(copy.data(), copy.data() + copy.size());
    connection.Write(&span);
  }

  [[nodiscard]] u_long AddressOf(const std::int32_t uid)
  {
    return static_cast<u_long>(faf::netlink::EngineAddressFor(uid).addrHost);
  }

  [[nodiscard]] u_short PortOf(const std::int32_t uid)
  {
    return faf::netlink::EngineAddressFor(uid).portHost;
  }

  constexpr std::uint8_t kJoin = 100;
  constexpr std::uint8_t kWelcome = 102;
  constexpr std::uint8_t kDirectScript = 107;
  constexpr std::uint8_t kConnMade = 201;
  constexpr std::uint8_t kConnLostEof = 203;
} // namespace

TEST(RelayConnector, EngineAddressesMapBackToUids)
{
  for (const std::int32_t uid : {1, 1001, 0x00FFFFFF, 0x01000000, 0x7FFFFFFF}) {
    EXPECT_EQ(CServerRelayConnector::UidForAddress(AddressOf(uid), PortOf(uid)), uid) << uid;
  }
  EXPECT_EQ(CServerRelayConnector::UidForAddress(0x7F000001u, 27019u), 0); // a real address: nobody's
  EXPECT_EQ(CServerRelayConnector::UidForAddress(0xF0000001u, 80u), 0);     // in 240/4 but no engine port
}

TEST(RelayConnector, ASignalHoldsBackWhatCameAfterIt)
{
  CLobbyInbox inbox;
  const std::vector<std::uint8_t> signal = CLobbyRelay::FrameFromServer(
    faf::remote::net::EncodeLobbySignal(SLobbySignal{ELobbySignal::ConnectToPeer, 0, 1002, "Bo", ""})
  );
  const std::vector<std::uint8_t> fromBo = {static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::Lobby), 0xEAu, 0x07u, kJoin, 3u, 0u};
  inbox.Push(signal);
  inbox.Push(fromBo);
  std::vector<std::uint8_t> frame;
  EXPECT_FALSE(inbox.TakeLobbyFrame(frame)); // Bo's Join waits for the signal that announces Bo
  SLobbySignal taken;
  ASSERT_TRUE(inbox.TakeSignal(taken));
  EXPECT_EQ(taken.uid, 1002);
  EXPECT_FALSE(inbox.TakeSignal(taken));
  ASSERT_TRUE(inbox.TakeLobbyFrame(frame));
  EXPECT_EQ(frame, fromBo);

  // A malformed signal is dropped, and what came after it flows.
  inbox.Push(CLobbyRelay::FrameFromServer(std::vector<std::uint8_t>{9u, 0u}));
  inbox.Push(fromBo);
  EXPECT_FALSE(inbox.TakeSignal(taken));
  EXPECT_EQ(inbox.DroppedSignals(), 1u);
  EXPECT_TRUE(inbox.TakeLobbyFrame(frame));
}

TEST(RelayConnector, TheHostAcceptsWhomTheServerNamesAndTheJoinerConnects)
{
  SRecorder lobbyA;
  SRecorder lobbyB;
  SLoopChannel channelA;
  SLoopChannel channelB;
  SLoopServer server;
  server.relay.AddParticipant(1001);
  server.relay.AddParticipant(1002);
  server.signaller.AddParticipant(1001, "Ann");
  server.signaller.AddParticipant(1002, "Bo");
  server.clients = {{1001, &channelA}, {1002, &channelB}};
  auto* const connectorA = new CServerRelayConnector(channelA);
  auto* const connectorB = new CServerRelayConnector(channelB);
  const auto listen = [](SRecorder& lobby, moho::INetConnection* const connection) {
    connection->PushReceiver(100, 120, &lobby);
    connection->PushReceiver(200, 210, &lobby);
  };

  server.Joined(1002);
  server.Joined(1001);
  SLobbySignal signal;
  // Ann hosts; as `ConnectToPeer` on a host (`CLobby::ConnectToPeer`), she accepts Bo's engine address.
  ASSERT_TRUE(channelA.inbox.TakeSignal(signal));
  EXPECT_EQ(signal.kind, ELobbySignal::Host);
  ASSERT_TRUE(channelA.inbox.TakeSignal(signal));
  ASSERT_EQ(signal.kind, ELobbySignal::ConnectToPeer);
  moho::INetConnection* const aToB = connectorA->Accept(AddressOf(signal.uid), PortOf(signal.uid));
  listen(lobbyA, aToB);
  // Bo joins Ann at her engine address: ConnMade, then Join.
  ASSERT_TRUE(channelB.inbox.TakeSignal(signal));
  ASSERT_EQ(signal.kind, ELobbySignal::Join);
  EXPECT_EQ(signal.uid, 1001);
  moho::INetConnection* const bToA = connectorB->Connect(AddressOf(signal.uid), PortOf(signal.uid));
  listen(lobbyB, bToA);
  connectorB->Pull();
  ASSERT_EQ(lobbyB.Count(kConnMade, bToA), 1u);
  WriteMessage(*bToA, {kJoin, 3u, 0u});
  server.Pump();
  connectorA->Pull();
  EXPECT_EQ(lobbyA.Count(kConnMade, aToB), 1u);
  EXPECT_EQ(lobbyA.Count(kJoin, aToB), 1u); // on the connection the host made for 1002
  u_long address = 0;
  u_short port = 0;
  EXPECT_FALSE(connectorA->FindNextAddress(address, port));
  WriteMessage(*aToB, {kWelcome, 3u, 0u});
  server.Pump();
  connectorB->Pull();
  EXPECT_EQ(lobbyB.Count(kWelcome, bToA), 1u);

  // Script data arrives as from the participant that sent it.
  const std::vector<std::uint8_t> script = {kDirectScript, 6u, 0u, 104u, 105u, 33u};
  WriteMessage(*bToA, script);
  server.Pump();
  connectorA->Pull();
  ASSERT_EQ(lobbyA.Count(kDirectScript, aToB), 1u);
  EXPECT_EQ(lobbyA.received.back().bytes, script);

  // A peer can't make up this side's connection events; a message with a wrong size is dropped.
  WriteMessage(*aToB, {kConnLostEof, 3u, 0u});
  WriteMessage(*aToB, {kDirectScript, 9u, 0u, 120u});
  server.Pump();
  connectorB->Pull();
  EXPECT_EQ(lobbyB.Count(kConnLostEof, bToA), 0u);
  EXPECT_EQ(connectorB->DroppedFrames(), 2u);

  // The host leaves: Bo is told, and his connection to her ends once (CLobby: "HostLeft").
  server.Left(1001);
  ASSERT_TRUE(channelB.inbox.TakeSignal(signal));
  EXPECT_EQ(signal.kind, ELobbySignal::DisconnectFromPeer);
  channelB.gone.push_back(signal.uid);
  connectorB->Pull();
  connectorB->Pull();
  EXPECT_EQ(lobbyB.Count(kConnLostEof, bToA), 1u);

  // The channel gone: every connection of that side is lost, once.
  channelA.up = false;
  connectorA->Pull();
  connectorA->Pull();
  EXPECT_EQ(lobbyA.Count(kConnLostEof, aToB), 1u);

  connectorA->Destroy();
  connectorB->Destroy();
}

// Plan WP2.14: the host's launch against the match (server/LobbySignaller.h).
TEST(LaunchCheck, TheMatchsMapAndSeatsAndNoSimMods)
{
  using faf::server::CheckLaunch;
  using faf::server::SLaunchFacts;
  const SLaunchFacts match{"/maps/SCMP_009/SCMP_009_scenario.lua", {1001, 1002}, 0};
  EXPECT_EQ(CheckLaunch(SLaunchFacts{"/maps/scmp_009/scmp_009_scenario.lua", {1002, 1001}, 0}, match), ""); // case, order
  EXPECT_NE(CheckLaunch(SLaunchFacts{"/maps/SCMP_010/SCMP_010_scenario.lua", {1001, 1002}, 0}, match).find("map"), std::string::npos);
  EXPECT_NE(CheckLaunch(SLaunchFacts{match.scenario, {1001}, 0}, match).find("slots"), std::string::npos);        // a seat empty
  EXPECT_NE(CheckLaunch(SLaunchFacts{match.scenario, {1001, 1002, 1003}, 0}, match).find("slots"), std::string::npos); // a stranger
  EXPECT_NE(CheckLaunch(SLaunchFacts{match.scenario, {1001, 1002}, 1}, match).find("sim mods"), std::string::npos);
}

TEST(LaunchCheck, ARequestIsItsKindThenTheConfiguration)
{
  const std::vector<std::uint8_t> configuration = {4u, 1u, 2u};
  const std::vector<std::uint8_t> message = faf::remote::net::EncodeLaunchRequest(configuration);
  EXPECT_EQ(message, (std::vector<std::uint8_t>{faf::remote::net::kLobbyLaunchRequest, 4u, 1u, 2u}));
  std::span<const std::uint8_t> back;
  ASSERT_TRUE(faf::remote::net::IsLaunchRequest(message, back));
  EXPECT_EQ(std::vector<std::uint8_t>(back.begin(), back.end()), configuration);
  EXPECT_FALSE(faf::remote::net::IsLaunchRequest(std::vector<std::uint8_t>{faf::remote::net::kLobbyLaunchRequest}, back));
  EXPECT_FALSE(faf::remote::net::IsLaunchRequest(faf::remote::net::EncodeLobbySignal(SLobbySignal{}), back));
}

// Plan WP11 step 3: a client's view is its own frame and its team's, less the team's blips of its own units.
TEST(ViewMerge, OwnAndTeamLessBlipsOfOwnUnits)
{
  using faf::remote::client::CViewFrameMerger;
  const auto record = [](const std::uint32_t id) {
    faf::remote::wire::SEntityRecord r{};
    r.id = id;
    return r;
  };
  faf::remote::wire::SViewFrame own;
  own.frameId = 7;
  own.beat = 42;
  own.entities = {record(0x00500001u), record(0x00500009u)}; // army 5's units
  faf::remote::wire::SViewFrame team;
  team.entities = {record(0x00500001u), record(0x00600002u), record(0x20000003u), record(0x30500004u), record(0x30600005u)};
  faf::remote::wire::SViewFrame merged;
  std::uint64_t leftOut = 0;
  CViewFrameMerger::Merge(own, &team, 5, merged, leftOut);
  std::vector<std::uint32_t> ids;
  for (const auto& r : merged.entities) {
    ids.push_back(r.id);
  }
  // The own unit once, the ally's unit, the prop, the blip of army 6; the blip of army 5's own unit left out.
  EXPECT_EQ(ids, (std::vector<std::uint32_t>{0x00500001u, 0x00500009u, 0x00600002u, 0x20000003u, 0x30600005u}));
  EXPECT_EQ(leftOut, 1u);
  EXPECT_EQ(merged.beat, 42u);
  EXPECT_EQ(merged.frameId, 7u);
  EXPECT_TRUE(CViewFrameMerger::IsBlipOfArmy(0x30500004u, 5));
  EXPECT_FALSE(CViewFrameMerger::IsBlipOfArmy(0x30500004u, -1));
  EXPECT_FALSE(CViewFrameMerger::IsBlipOfArmy(0x00500001u, 5));

  // No team frame (cut from the team): the own frame alone.
  CViewFrameMerger::Merge(own, nullptr, 5, merged, leftOut);
  EXPECT_EQ(merged.entities.size(), 2u);
}
