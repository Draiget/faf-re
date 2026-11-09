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
#include "moho/net/ELobbyMsg.h"
#include "netlink/EngineLinks.h"
#include "remote/FocusAndCameras.h"
#include "remote/SpeedLimit.h"
#include "remote/ContentCheck.h"
#include "remote/ServerClient.h"
#include "remote/client/ServerRelayConnector.h"
#include "remote/client/ViewMerge.h"
#include "remote/ViewIdMap.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"
#include "remote/net/LobbySignals.h"
#include "server/LinkSpeed.h"
#include "server/LobbySignaller.h"
#include "server/LobbyRelay.h"
#include "server/LobbyScriptData.h"
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

// Plan WPR.49: the lobby's script data as the relay reads it (server/LobbyScriptData.h).
namespace
{
  using faf::server::SLuaBytesValue;

  SLuaBytesValue LuaString(const std::string& text)
  {
    SLuaBytesValue value;
    value.kind = SLuaBytesValue::EKind::String;
    value.text = text;
    return value;
  }

  SLuaBytesValue LuaNumber(const float number)
  {
    SLuaBytesValue value;
    value.kind = SLuaBytesValue::EKind::Number;
    std::memcpy(value.raw, &number, sizeof(number));
    return value;
  }

  SLuaBytesValue LuaTable(std::vector<std::pair<SLuaBytesValue, SLuaBytesValue>> pairs)
  {
    SLuaBytesValue value;
    value.kind = SLuaBytesValue::EKind::Table;
    for (auto& [key, item] : pairs) {
      value.keys.push_back(std::move(key));
      value.values.push_back(std::move(item));
    }
    return value;
  }

  std::vector<std::uint8_t> LuaBytes(const SLuaBytesValue& value)
  {
    std::vector<std::uint8_t> bytes;
    faf::server::WriteLuaBytes(value, bytes);
    return bytes;
  }

  /** A whole `CLobby` message: type, 16-bit whole size, payload. */
  std::vector<std::uint8_t> LobbyMessage(const moho::ELobbyMsg type, const std::vector<std::uint8_t>& payload)
  {
    const std::size_t size = 3u + payload.size();
    std::vector<std::uint8_t> message = {static_cast<std::uint8_t>(type), static_cast<std::uint8_t>(size), static_cast<std::uint8_t>(size >> 8u)};
    message.insert(message.end(), payload.begin(), payload.end());
    return message;
  }

  /** The value of `key` in the `Options` (or `GameInfo.GameOptions`) of script data, as a string. */
  std::string OptionIn(const std::vector<std::uint8_t>& payload, const std::string& key)
  {
    SLuaBytesValue root;
    if (!faf::server::ParseLuaBytes(payload, root)) {
      return "<unreadable>";
    }
    SLuaBytesValue* options = root.Field("Options");
    if (options == nullptr) {
      SLuaBytesValue* const info = root.Field("GameInfo");
      options = info != nullptr ? info->Field("GameOptions") : nullptr;
    }
    const SLuaBytesValue* const value = options != nullptr ? options->Field(key) : nullptr;
    return value == nullptr ? "<none>" : value->text;
  }
} // namespace

TEST(LobbyScriptData, ReadsAndWritesTheLobbysByteForm)
{
  const SLuaBytesValue value = LuaTable({{LuaString("Type"), LuaString("GameOptions")},
                                         {LuaNumber(1.0f), LuaTable({{LuaString("a"), SLuaBytesValue{}}})}});
  const std::vector<std::uint8_t> bytes = LuaBytes(value);
  // tag 4, "Type" string, "GameOptions" string, number 1.0f, table {a = nil}, end.
  EXPECT_EQ(bytes.front(), 4u);
  EXPECT_EQ(bytes.back(), 5u);
  SLuaBytesValue back;
  ASSERT_TRUE(faf::server::ParseLuaBytes(bytes, back));
  EXPECT_EQ(LuaBytes(back), bytes);
  ASSERT_NE(back.Field("Type"), nullptr);
  EXPECT_TRUE(back.Field("Type")->IsString("GameOptions"));

  // Cut short, bytes left over, an unknown tag, nesting past the limit: not one value.
  EXPECT_FALSE(faf::server::ParseLuaBytes(std::span<const std::uint8_t>(bytes).first(bytes.size() - 1u), back));
  std::vector<std::uint8_t> longer = bytes;
  longer.push_back(2u);
  EXPECT_FALSE(faf::server::ParseLuaBytes(longer, back));
  EXPECT_FALSE(faf::server::ParseLuaBytes(std::vector<std::uint8_t>{9u}, back));
  std::vector<std::uint8_t> deep;
  for (int i = 0; i < 40; ++i) {
    deep.insert(deep.end(), {4u, 1u, 'k', 0u});
  }
  deep.push_back(2u);
  deep.insert(deep.end(), 40u, 5u);
  EXPECT_FALSE(faf::server::ParseLuaBytes(deep, back));
}

// Plan WP15.4: the server's pause count written into a `Sync` table's bytes, nothing else of it changed.
TEST(LobbyScriptData, SetTableNumberChangesOneNumber)
{
  const std::vector<std::uint8_t> sync = LuaBytes(LuaTable({{LuaString("PausedBy"), LuaNumber(2.0f)},
                                                            {LuaString("TimeoutsRemaining"), LuaNumber(-1.0f)},
                                                            {LuaString("Score"), LuaTable({{LuaString("x"), LuaString("y")}})}}));
  std::vector<std::uint8_t> out;
  ASSERT_TRUE(faf::server::SetTableNumber(sync, "TimeoutsRemaining", 3.0f, out));
  EXPECT_EQ(out.size(), sync.size());
  SLuaBytesValue back;
  ASSERT_TRUE(faf::server::ParseLuaBytes(out, back));
  float value = 0.0f;
  std::memcpy(&value, back.Field("TimeoutsRemaining")->raw, sizeof(value));
  EXPECT_EQ(value, 3.0f);
  std::memcpy(&value, back.Field("PausedBy")->raw, sizeof(value));
  EXPECT_EQ(value, 2.0f);
  ASSERT_NE(back.Field("Score"), nullptr);
  EXPECT_TRUE(back.Field("Score")->Field("x")->IsString("y"));
  // A key that isn't there, or isn't a number, and bytes that don't read: nothing written.
  std::vector<std::uint8_t> untouched = {7u};
  EXPECT_FALSE(faf::server::SetTableNumber(sync, "Missing", 1.0f, untouched));
  EXPECT_FALSE(faf::server::SetTableNumber(sync, "Score", 1.0f, untouched));
  EXPECT_FALSE(faf::server::SetTableNumber(std::vector<std::uint8_t>{4u, 1u}, "TimeoutsRemaining", 1.0f, untouched));
  EXPECT_EQ(untouched, (std::vector<std::uint8_t>{7u}));
}

TEST(LobbyScriptData, PinnedOptionsGetTheMatchsValues)
{
  const faf::server::SPinnedOptions pinned = {{"Victory", LuaBytes(LuaString("demoralization"))}, {"Share", LuaBytes(LuaString("FullShare"))}};

  // A host's change of a pinned option and of a free one: the pinned one goes back to the match's.
  std::vector<std::uint8_t> options = LuaBytes(LuaTable({{LuaString("Type"), LuaString("GameOptions")},
                                                          {LuaString("Options"), LuaTable({{LuaString("Victory"), LuaString("sandbox")},
                                                                                           {LuaString("UnitCap"), LuaString("500")}})}}));
  EXPECT_TRUE(faf::server::PinGameOptions(options, pinned));
  EXPECT_EQ(OptionIn(options, "Victory"), "demoralization");
  EXPECT_EQ(OptionIn(options, "UnitCap"), "500");
  EXPECT_EQ(OptionIn(options, "Share"), "<none>"); // a change names only what it changes
  // Already the match's: left as it is.
  EXPECT_FALSE(faf::server::PinGameOptions(options, pinned));

  // The whole game state a joiner gets: every pinned option, those the host left out too.
  std::vector<std::uint8_t> info = LuaBytes(LuaTable(
    {{LuaString("Type"), LuaString("GameInfo")},
     {LuaString("GameInfo"), LuaTable({{LuaString("GameOptions"), LuaTable({{LuaString("Victory"), LuaString("assassination")}})}})}}
  ));
  EXPECT_TRUE(faf::server::PinGameOptions(info, pinned));
  EXPECT_EQ(OptionIn(info, "Victory"), "demoralization");
  EXPECT_EQ(OptionIn(info, "Share"), "FullShare");

  // Anything else, readable or not, isn't touched.
  std::vector<std::uint8_t> chat = LuaBytes(LuaTable({{LuaString("Type"), LuaString("Chat")}, {LuaString("Victory"), LuaString("x")}}));
  const std::vector<std::uint8_t> chatBefore = chat;
  EXPECT_FALSE(faf::server::PinGameOptions(chat, pinned));
  EXPECT_EQ(chat, chatBefore);
  std::vector<std::uint8_t> garbage = {104u, 105u, 33u};
  EXPECT_FALSE(faf::server::PinGameOptions(garbage, pinned));
}

// Plan WP17.6: an organiser-run lobby's player readies up and nothing else.
namespace
{
  SLuaBytesValue LuaBoolean(const bool value)
  {
    SLuaBytesValue out;
    out.kind = SLuaBytesValue::EKind::Boolean;
    out.raw[0] = value ? 1u : 0u;
    return out;
  }

  std::vector<std::uint8_t> PlayerOptions(std::vector<std::pair<SLuaBytesValue, SLuaBytesValue>> options)
  {
    return LuaBytes(LuaTable({{LuaString("Type"), LuaString("PlayerOptions")}, {LuaString("Slot"), LuaNumber(1.0f)},
                              {LuaString("Options"), LuaTable(std::move(options))}}));
  }
} // namespace

TEST(LobbyScriptData, APlayersOwnOptionsKeepOnlyReady)
{
  using faf::server::EPlayerScript;
  // Faction and team go; Ready stays, and so does the rest of the message.
  std::vector<std::uint8_t> mixed = PlayerOptions({{LuaString("Faction"), LuaNumber(3.0f)}, {LuaString("Ready"), LuaBoolean(true)}, {LuaString("Team"), LuaNumber(2.0f)}});
  EXPECT_EQ(faf::server::LimitPlayerScript(mixed), EPlayerScript::Rewritten);
  SLuaBytesValue back;
  ASSERT_TRUE(faf::server::ParseLuaBytes(mixed, back));
  ASSERT_NE(back.Field("Options"), nullptr);
  EXPECT_EQ(back.Field("Options")->keys.size(), 1u);
  ASSERT_NE(back.Field("Options")->Field("Ready"), nullptr);
  EXPECT_EQ(back.Field("Options")->Field("Ready")->raw[0], 1u);
  EXPECT_NE(back.Field("Slot"), nullptr);
  // Ready alone: as it was.
  std::vector<std::uint8_t> ready = PlayerOptions({{LuaString("Ready"), LuaBoolean(false)}});
  const std::vector<std::uint8_t> readyBefore = ready;
  EXPECT_EQ(faf::server::LimitPlayerScript(ready), EPlayerScript::Unchanged);
  EXPECT_EQ(ready, readyBefore);
  // Nothing but a colour: nothing left to send.
  std::vector<std::uint8_t> colour = PlayerOptions({{LuaString("PlayerColor"), LuaNumber(4.0f)}});
  EXPECT_EQ(faf::server::LimitPlayerScript(colour), EPlayerScript::Refused);
  // The requests to the host.
  for (const char* const request : {"MovePlayer", "RequestColor", "RequestConvertToObserver", "RequestConvertToPlayer"}) {
    std::vector<std::uint8_t> asked = LuaBytes(LuaTable({{LuaString("Type"), LuaString(request)}, {LuaString("RequestedSlot"), LuaNumber(2.0f)}}));
    EXPECT_EQ(faf::server::LimitPlayerScript(asked), EPlayerScript::Refused) << request;
  }
  // Chat, game options, garbage: not this rule's.
  std::vector<std::uint8_t> chat = LuaBytes(LuaTable({{LuaString("Type"), LuaString("Chat")}, {LuaString("Text"), LuaString("gl hf")}}));
  EXPECT_EQ(faf::server::LimitPlayerScript(chat), EPlayerScript::Unchanged);
  std::vector<std::uint8_t> garbage = {104u, 105u, 33u};
  EXPECT_EQ(faf::server::LimitPlayerScript(garbage), EPlayerScript::Unchanged);
}

TEST(LobbyRelay, OrganisedLobbysPlayersOnlyReadyUp)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  relay.SetHost(1001);
  const auto script = [](const std::vector<std::uint8_t>& payload) { return LobbyMessage(moho::ELobbyMsg::LOBMSG_BroadcastScriptData, payload); };
  // A player's move request: dropped and counted.
  const std::vector<std::uint8_t> move = LuaBytes(LuaTable({{LuaString("Type"), LuaString("MovePlayer")}, {LuaString("RequestedSlot"), LuaNumber(1.0f)}}));
  EXPECT_EQ(Relay(relay, 1002, LobbyBody(1001, script(move)), 1u).verdict, ELobbyRelayVerdict::Locked);
  EXPECT_EQ(relay.Count(ELobbyRelayVerdict::Locked), 1u);
  // A player's faction and ready: on with Ready alone.
  const SRelayed options = Relay(relay, 1002, LobbyBody(1001, script(PlayerOptions({{LuaString("Faction"), LuaNumber(2.0f)}, {LuaString("Ready"), LuaBoolean(true)}}))), 1u);
  ASSERT_EQ(options.verdict, ELobbyRelayVerdict::Forward);
  // The frame: the Lobby kind, the sender's uid (two varint bytes for 1002), then the message as it goes on.
  const std::vector<std::uint8_t> forwarded(options.frame.begin() + 3, options.frame.end());
  ASSERT_GT(forwarded.size(), 3u);
  EXPECT_EQ(forwarded.size(), static_cast<std::size_t>(forwarded[1]) | (static_cast<std::size_t>(forwarded[2]) << 8u));
  SLuaBytesValue back;
  ASSERT_TRUE(faf::server::ParseLuaBytes(std::span<const std::uint8_t>(forwarded).subspan(3u), back));
  EXPECT_EQ(back.Field("Options")->keys.size(), 1u);
  EXPECT_NE(back.Field("Options")->Field("Ready"), nullptr);
  EXPECT_EQ(relay.PlayerOptionsLimited(), 1u);
  // The host's own messages, chat and the rest go as they are.
  const std::vector<std::uint8_t> hostMove = script(PlayerOptions({{LuaString("Faction"), LuaNumber(2.0f)}}));
  const SRelayed host = Relay(relay, 1001, LobbyBody(1002, hostMove), 1u);
  EXPECT_EQ(std::vector<std::uint8_t>(host.frame.begin() + 3, host.frame.end()), hostMove);
  const std::vector<std::uint8_t> chat = script(LuaBytes(LuaTable({{LuaString("Type"), LuaString("Chat")}})));
  const SRelayed chatted = Relay(relay, 1002, LobbyBody(1001, chat), 1u);
  EXPECT_EQ(std::vector<std::uint8_t>(chatted.frame.begin() + 3, chatted.frame.end()), chat);
  // A player-hosted lobby's players change what they like.
  CLobbyRelay player;
  player.SetControl(faf::server::ELobbyControl::Player);
  player.AddParticipant(1001);
  player.AddParticipant(1002);
  player.SetHost(1001);
  EXPECT_EQ(Relay(player, 1002, LobbyBody(1001, script(move)), 1u).verdict, ELobbyRelayVerdict::Forward);
}

// Plan WP17.2: where each participant sits (as the host's lobby says) and who is ready, for the control service.
TEST(LobbyRelay, ReadsSlotsAndReadyForTheControlService)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  relay.SetHost(1001);
  const auto script = [](const std::vector<std::uint8_t>& payload) { return LobbyMessage(moho::ELobbyMsg::LOBMSG_BroadcastScriptData, payload); };
  const auto readyAt = [](const float slot, const bool ready) {
    return LuaBytes(LuaTable({{LuaString("Type"), LuaString("PlayerOptions")}, {LuaString("Slot"), LuaNumber(slot)},
                              {LuaString("Options"), LuaTable({{LuaString("Ready"), LuaBoolean(ready)}})}}));
  };
  EXPECT_EQ(relay.LobbySlotOf(1002), 0);
  EXPECT_FALSE(relay.ReadyOf(1002).has_value());
  // The host seats 1002 (`SlotAssigned`, OwnerID as lobby.lua's string) and tells it the whole game (`GameInfo`).
  const std::vector<std::uint8_t> assigned = LuaBytes(LuaTable(
    {{LuaString("Type"), LuaString("SlotAssigned")}, {LuaString("Slot"), LuaNumber(3.0f)}, {LuaString("Options"), LuaTable({{LuaString("OwnerID"), LuaString("1002")}})}}
  ));
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, script(assigned)), 1u).verdict, ELobbyRelayVerdict::Forward);
  EXPECT_EQ(relay.LobbySlotOf(1002), 3);
  const std::vector<std::uint8_t> info = LuaBytes(LuaTable(
    {{LuaString("Type"), LuaString("GameInfo")},
     {LuaString("GameInfo"),
      LuaTable({{LuaString("PlayerOptions"),
                 LuaTable({{LuaNumber(1.0f), LuaTable({{LuaString("OwnerID"), LuaString("1001")}})},
                           {LuaNumber(2.0f), LuaTable({{LuaString("OwnerID"), LuaString("1002")}})}})}})}}
  ));
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, LobbyMessage(moho::ELobbyMsg::LOBMSG_DirectScriptData, info)), 2u).verdict, ELobbyRelayVerdict::Forward);
  EXPECT_EQ(relay.LobbySlotOf(1001), 1);
  EXPECT_EQ(relay.LobbySlotOf(1002), 2);
  // A player can't seat anyone.
  const std::vector<std::uint8_t> claimed = LuaBytes(LuaTable(
    {{LuaString("Type"), LuaString("SlotMove")}, {LuaString("NewSlot"), LuaNumber(1.0f)}, {LuaString("Options"), LuaTable({{LuaString("OwnerID"), LuaString("1002")}})}}
  ));
  (void)Relay(relay, 1002, LobbyBody(1001, script(claimed)), 3u);
  EXPECT_EQ(relay.LobbySlotOf(1002), 2);
  // 1002 readies up (its own options; the Slot it names doesn't matter); the host sets 1002's slot back to not ready
  // and readies itself; the same state again is no change.
  (void)Relay(relay, 1002, LobbyBody(1001, script(readyAt(7.0f, true))), 4u);
  EXPECT_EQ(relay.ReadyOf(1002), std::optional<bool>(true));
  (void)Relay(relay, 1001, LobbyBody(1002, script(readyAt(2.0f, false))), 5u);
  (void)Relay(relay, 1001, LobbyBody(1002, script(readyAt(1.0f, true))), 6u);
  (void)Relay(relay, 1001, LobbyBody(1002, script(readyAt(1.0f, true))), 7u);
  // The host's message for a slot nobody sits in counts for nobody.
  (void)Relay(relay, 1001, LobbyBody(1002, script(readyAt(5.0f, true))), 8u);
  EXPECT_EQ(relay.ReadyOf(1002), std::optional<bool>(false));
  EXPECT_EQ(relay.ReadyOf(1001), std::optional<bool>(true));
  const std::vector<std::pair<std::int32_t, bool>> changes = relay.TakeReadyChanges();
  const std::vector<std::pair<std::int32_t, bool>> expected = {{1002, true}, {1002, false}, {1001, true}};
  EXPECT_EQ(changes, expected);
  EXPECT_TRUE(relay.TakeReadyChanges().empty());
}

TEST(LobbyRelay, EjectsOfParticipantsNeverArrive)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  const std::vector<std::uint8_t> reason = {'K', 'i', 'c', 'k', 0u};
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, LobbyMessage(moho::ELobbyMsg::LOBMSG_Rejected, reason)), 1u).verdict, ELobbyRelayVerdict::EjectIgnored);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, LobbyMessage(moho::ELobbyMsg::LOBMSG_DeletePeer, {0xEAu, 0x03u, 0u, 0u})), 1u).verdict,
            ELobbyRelayVerdict::EjectIgnored);
  EXPECT_EQ(relay.Count(ELobbyRelayVerdict::EjectIgnored), 2u);
  // The rest of the lobby's talk goes on.
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, LobbyMessage(moho::ELobbyMsg::LOBMSG_EstablishedPeers, {0xFFu, 0xFFu, 0xFFu, 0xFFu})), 1u).verdict,
            ELobbyRelayVerdict::Forward);
}

// Plan WP17.1: a player-hosted lobby's host keeps a host's powers; nobody else gets them.
TEST(LobbyRelay, PlayerHostedLobbyLetsOnlyTheHostEject)
{
  CLobbyRelay relay;
  relay.SetControl(faf::server::ELobbyControl::Player);
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  relay.AddParticipant(1003);
  const std::vector<std::uint8_t> reason = {'K', 'i', 'c', 'k', 0u};
  const std::vector<std::uint8_t> kick = LobbyMessage(moho::ELobbyMsg::LOBMSG_Rejected, reason);
  // No host known yet: dropped.
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, kick), 1u).verdict, ELobbyRelayVerdict::EjectIgnored);
  relay.SetHost(1001);
  const SRelayed fromHost = Relay(relay, 1001, LobbyBody(1002, kick), 1u);
  EXPECT_EQ(fromHost.verdict, ELobbyRelayVerdict::EjectForwarded);
  EXPECT_EQ(fromHost.to, 1002);
  EXPECT_EQ(fromHost.message, kick);
  // Another participant can't eject, the host's notice to the others goes, and after a succession the old host can't.
  EXPECT_EQ(Relay(relay, 1003, LobbyBody(1002, kick), 1u).verdict, ELobbyRelayVerdict::EjectIgnored);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1003, LobbyMessage(moho::ELobbyMsg::LOBMSG_DeletePeer, {0xEAu, 0x03u, 0u, 0u})), 1u).verdict,
            ELobbyRelayVerdict::EjectForwarded);
  relay.SetHost(1003);
  EXPECT_EQ(Relay(relay, 1001, LobbyBody(1002, kick), 1u).verdict, ELobbyRelayVerdict::EjectIgnored);
  EXPECT_EQ(Relay(relay, 1003, LobbyBody(1002, kick), 1u).verdict, ELobbyRelayVerdict::EjectForwarded);
  EXPECT_EQ(relay.Count(ELobbyRelayVerdict::EjectIgnored), 3u);
  EXPECT_EQ(relay.Count(ELobbyRelayVerdict::EjectForwarded), 3u);

  // Nothing is pinned in a player-hosted lobby: the host's options go as sent.
  relay.PinOptions({{"Victory", LuaBytes(LuaString("demoralization"))}});
  const std::vector<std::uint8_t> payload = LuaBytes(
    LuaTable({{LuaString("Type"), LuaString("GameOptions")}, {LuaString("Options"), LuaTable({{LuaString("Victory"), LuaString("sandbox")}})}})
  );
  const std::vector<std::uint8_t> options = LobbyMessage(moho::ELobbyMsg::LOBMSG_BroadcastScriptData, payload);
  const SRelayed sent = Relay(relay, 1003, LobbyBody(1002, options), 1u);
  ASSERT_EQ(sent.verdict, ELobbyRelayVerdict::Forward);
  EXPECT_EQ(std::vector<std::uint8_t>(sent.frame.begin() + 3, sent.frame.end()), options);
  EXPECT_EQ(relay.OptionsPinned(), 0u);
}

TEST(LobbyRelay, ReadsTheLobbyControl)
{
  EXPECT_EQ(faf::server::ReadLobbyControl("organiser"), faf::server::ELobbyControl::Organiser);
  EXPECT_EQ(faf::server::ReadLobbyControl("player"), faf::server::ELobbyControl::Player);
  EXPECT_FALSE(faf::server::ReadLobbyControl("Player").has_value());
  EXPECT_FALSE(faf::server::ReadLobbyControl("").has_value());
  // Organised is the default: WPR.49's rules hold unless the match says otherwise.
  EXPECT_EQ(CLobbyRelay().Control(), faf::server::ELobbyControl::Organiser);
}

TEST(LobbyRelay, ScriptDataCarriesThePinnedOptions)
{
  CLobbyRelay relay;
  relay.AddParticipant(1001);
  relay.AddParticipant(1002);
  relay.PinOptions({{"Victory", LuaBytes(LuaString("demoralization"))}});
  const std::vector<std::uint8_t> payload = LuaBytes(
    LuaTable({{LuaString("Type"), LuaString("GameOptions")}, {LuaString("Options"), LuaTable({{LuaString("Victory"), LuaString("sandbox")}})}})
  );
  const SRelayed relayed = Relay(relay, 1001, LobbyBody(1002, LobbyMessage(moho::ELobbyMsg::LOBMSG_BroadcastScriptData, payload)), 1u);
  ASSERT_EQ(relayed.verdict, ELobbyRelayVerdict::Forward);
  EXPECT_EQ(relay.OptionsPinned(), 1u);
  // The frame: Lobby, varint 1001 (two bytes), then a whole message whose size says what it is now.
  ASSERT_GT(relayed.frame.size(), 6u);
  const std::vector<std::uint8_t> message(relayed.frame.begin() + 3, relayed.frame.end());
  EXPECT_EQ(message[0], static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_BroadcastScriptData));
  EXPECT_EQ(static_cast<std::size_t>(message[1]) | (static_cast<std::size_t>(message[2]) << 8u), message.size());
  EXPECT_EQ(OptionIn(std::vector<std::uint8_t>(message.begin() + 3, message.end()), "Victory"), "demoralization");
  // A message with nothing pinned in it goes as it came.
  const std::vector<std::uint8_t> hello = LobbyMessage(moho::ELobbyMsg::LOBMSG_DirectScriptData, {104u, 105u, 33u});
  const SRelayed same = Relay(relay, 1001, LobbyBody(1002, hello), 1u);
  EXPECT_EQ(std::vector<std::uint8_t>(same.frame.begin() + 3, same.frame.end()), hello);
  EXPECT_EQ(relay.OptionsPinned(), 1u);
}

// Plan WP17.8: the mods a player's game runs, and the UI mods a match allows.
TEST(ContentCheck, ModReportsAndTheUiModPolicy)
{
  using faf::remote::SModEntry;
  const std::vector<SModEntry> mods = {{false, "sim-mod-uid", ""}, {true, "ui-allowed", "3"}, {true, "ui-extra", "1.2"}};
  const std::vector<std::uint8_t> message = faf::remote::EncodeModReport(mods);
  EXPECT_EQ(message[0], static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::ModReport));
  std::vector<SModEntry> back;
  ASSERT_TRUE(faf::remote::DecodeModReport(message, back));
  EXPECT_EQ(back, mods);
  // Cut short, a byte left over, a kind that isn't one: not a report.
  EXPECT_FALSE(faf::remote::DecodeModReport(std::span<const std::uint8_t>(message).first(message.size() - 1u), back));
  std::vector<std::uint8_t> longer = message;
  longer.push_back(0u);
  EXPECT_FALSE(faf::remote::DecodeModReport(longer, back));
  std::vector<std::uint8_t> badKind = message;
  badKind[2] = 7u; // the first mod's kind byte (after the message kind and the count)
  EXPECT_FALSE(faf::remote::DecodeModReport(badKind, back));
  // None at all is a report too.
  ASSERT_TRUE(faf::remote::DecodeModReport(faf::remote::EncodeModReport({}), back));
  EXPECT_TRUE(back.empty());
  // An empty uid or one past the limit isn't sent.
  ASSERT_TRUE(faf::remote::DecodeModReport(faf::remote::EncodeModReport({{true, "", "1"}, {true, std::string(201, 'x'), "1"}}), back));
  EXPECT_TRUE(back.empty());

  // UI mods outside the allowlist; sim mods are the launch's, never judged here.
  EXPECT_EQ(faf::remote::UiModsOutside(mods, {"ui-allowed"}), (std::vector<std::string>{"ui-extra"}));
  EXPECT_EQ(faf::remote::UiModsOutside(mods, {}), (std::vector<std::string>{"ui-allowed", "ui-extra"}));
  EXPECT_TRUE(faf::remote::UiModsOutside(mods, {"ui-allowed", "ui-extra"}).empty());
}

// Plan WP2.6: content reports (remote/ContentCheck.h).
TEST(ContentCheck, ReportsAndVerdicts)
{
  using faf::remote::EContentCheck;
  using faf::remote::EContentVerdict;
  using faf::remote::SContentReport;
  const SContentReport report{0x0123456789ABCDEFull, 0xFEDCBA9876543210ull};
  const std::vector<std::uint8_t> message = faf::remote::EncodeContentReport(report);
  EXPECT_EQ(message.size(), 17u);
  EXPECT_EQ(message[0], static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::ContentReport));
  SContentReport back;
  ASSERT_TRUE(faf::remote::DecodeContentReport(message, back));
  EXPECT_EQ(back, report);
  EXPECT_FALSE(faf::remote::DecodeContentReport(std::span<const std::uint8_t>(message).first(16), back));
  std::vector<std::uint8_t> other = message;
  other[0] = static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::Loaded);
  EXPECT_FALSE(faf::remote::DecodeContentReport(other, back));

  // The mod set whatever the order; not the empty set's hash for one mod.
  EXPECT_EQ(faf::remote::HashModUids({"b", "a"}), faf::remote::HashModUids({"a", "b"}));
  EXPECT_NE(faf::remote::HashModUids({"a"}), faf::remote::HashModUids({}));
  EXPECT_NE(faf::remote::HashModUids({"ab"}), faf::remote::HashModUids({"a", "b"}));

  const SContentReport differs{report.blueprints, report.mods + 1u};
  EXPECT_EQ(faf::remote::JudgeContent(report, &report), EContentVerdict::Same);
  EXPECT_EQ(faf::remote::JudgeContent(report, &differs), EContentVerdict::Differs);
  EXPECT_EQ(faf::remote::JudgeContent(report, nullptr), EContentVerdict::Missing);
  EXPECT_TRUE(faf::remote::RefusesPlayer(EContentCheck::Refuse, EContentVerdict::Differs));
  EXPECT_TRUE(faf::remote::RefusesPlayer(EContentCheck::Refuse, EContentVerdict::Missing));
  EXPECT_FALSE(faf::remote::RefusesPlayer(EContentCheck::Refuse, EContentVerdict::Same));
  EXPECT_FALSE(faf::remote::RefusesPlayer(EContentCheck::Warn, EContentVerdict::Differs));
  EXPECT_FALSE(faf::remote::RefusesPlayer(EContentCheck::Off, EContentVerdict::Missing));
  EXPECT_TRUE(faf::remote::ReadContentCheck("refuse") == EContentCheck::Refuse);
  EXPECT_TRUE(faf::remote::ReadContentCheck("warn") == EContentCheck::Warn);
  EXPECT_TRUE(faf::remote::ReadContentCheck("off") == EContentCheck::Off);
  EXPECT_FALSE(faf::remote::ReadContentCheck("Refuse").has_value());
}

TEST(ContentCheck, ModUidsFromTheLaunchsGameMods)
{
  // `GameMods` as FAF's lobby launches it (`Mods.GetGameMods`: a list of mod infos), in the byte form a launch holds.
  const std::vector<std::uint8_t> bytes = LuaBytes(LuaTable({{LuaNumber(1.0f), LuaTable({{LuaString("uid"), LuaString("mod-b")}, {LuaString("name"), LuaString("B")}})},
                                                              {LuaNumber(2.0f), LuaTable({{LuaString("uid"), LuaString("mod-a")}})}}));
  std::vector<std::string> uids = faf::remote::ReadModUids(std::string(bytes.begin(), bytes.end()));
  std::sort(uids.begin(), uids.end());
  EXPECT_EQ(uids, (std::vector<std::string>{"mod-a", "mod-b"}));
  // `{[uid] = true}`, as the lobby keeps them before the launch.
  SLuaBytesValue yes;
  yes.kind = SLuaBytesValue::EKind::Boolean;
  yes.raw[0] = 1u;
  const std::vector<std::uint8_t> byKey = LuaBytes(LuaTable({{LuaString("mod-c"), yes}}));
  EXPECT_EQ(faf::remote::ReadModUids(std::string(byKey.begin(), byKey.end())), (std::vector<std::string>{"mod-c"}));
  EXPECT_TRUE(faf::remote::ReadModUids({}).empty());
  const std::vector<std::uint8_t> none = LuaBytes(LuaTable({}));
  EXPECT_TRUE(faf::remote::ReadModUids(std::string(none.begin(), none.end())).empty());
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

  // Bo leaves: the rest are told.
  signaller.OnLeft(1002, out);
  EXPECT_EQ(SignalsTo(out, 1001), (std::vector<std::string>{"4 1002 Bo "}));
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"4 1002 Bo "}));
  // Plan WPR.50: the host leaves: Cy, the next who is here, hosts its lobby anew; nobody hears of Ann leaving.
  out.clear();
  signaller.OnLeft(1001, out);
  EXPECT_FALSE(signaller.HostLeft());
  EXPECT_EQ(signaller.Host(), 1003);
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"1 0 Cy /maps/m/m_scenario.lua"}));
  EXPECT_EQ(out.size(), 1u);
  EXPECT_EQ(signaller.InLobby(), 1u);
  // Cy leaves too: nobody is left to host.
  out.clear();
  signaller.OnLeft(1003, out);
  EXPECT_TRUE(signaller.HostLeft());
  EXPECT_EQ(signaller.Host(), 0);
  EXPECT_TRUE(out.empty());
}

// Plan WPR.50: logical-host succession.
TEST(LobbySignaller, TheNextInTheMatchTakesOverAndEveryoneStartsAgain)
{
  CLobbySignaller signaller("/maps/m/m_scenario.lua");
  signaller.AddParticipant(1001, "Ann");
  signaller.AddParticipant(1002, "Bo");
  signaller.AddParticipant(1003, "Cy");
  signaller.AddParticipant(1004, "Di");
  std::vector<CLobbySignaller::SOutgoing> out;
  for (const std::int32_t uid : {1001, 1002, 1003, 1004}) {
    signaller.OnJoined(uid, out);
  }
  EXPECT_EQ(signaller.InLobby(), 4u);
  out.clear();

  // Ann goes quiet: Bo hosts; Cy and Di join Bo, the host hearing of each first, and meet each other again.
  signaller.OnAway(1001, out);
  EXPECT_EQ(signaller.Host(), 1002);
  EXPECT_EQ(signaller.Successions(), 1u);
  EXPECT_EQ(SignalsTo(out, 1002), (std::vector<std::string>{"1 0 Bo /maps/m/m_scenario.lua", "3 1003 Cy ", "3 1004 Di "}));
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"2 1002 Cy Bo", "3 1004 Di "}));
  EXPECT_EQ(SignalsTo(out, 1004), (std::vector<std::string>{"2 1002 Di Bo", "3 1003 Cy "}));
  EXPECT_TRUE(SignalsTo(out, 1001).empty());
  EXPECT_EQ(out.front().to, 1002);
  EXPECT_EQ(signaller.InLobby(), 3u);

  // Ann is heard again: she joins Bo's lobby as anyone would.
  out.clear();
  signaller.OnBack(1001, out);
  EXPECT_EQ(signaller.Host(), 1002);
  EXPECT_EQ(SignalsTo(out, 1002), (std::vector<std::string>{"3 1001 Ann "}));
  EXPECT_EQ(SignalsTo(out, 1001), (std::vector<std::string>{"2 1002 Ann Bo", "3 1003 Cy ", "3 1004 Di "}));
  EXPECT_EQ(out.front().to, 1002);
  EXPECT_EQ(signaller.InLobby(), 4u);

  // A joiner quiet and back keeps its role: nothing to say.
  out.clear();
  signaller.OnAway(1004, out);
  signaller.OnBack(1004, out);
  EXPECT_TRUE(out.empty());

  // Bo leaves: after him in the match's order comes Cy (then Di, then round to Ann).
  signaller.OnLeft(1002, out);
  EXPECT_EQ(signaller.Host(), 1003);
  EXPECT_EQ(SignalsTo(out, 1003).front(), "1 0 Cy /maps/m/m_scenario.lua");
  EXPECT_EQ(SignalsTo(out, 1001).front(), "2 1003 Ann Cy");
  EXPECT_EQ(SignalsTo(out, 1004).front(), "2 1003 Di Cy");
}

TEST(LobbySignaller, ASuccessorStillToComeOrAwayIsWaitedFor)
{
  CLobbySignaller signaller("");
  signaller.AddParticipant(1001, "Ann");
  signaller.AddParticipant(1002, "Bo");
  signaller.AddParticipant(1003, "Cy");
  std::vector<CLobbySignaller::SOutgoing> out;
  signaller.OnJoined(1001, out);
  signaller.OnJoined(1003, out);
  out.clear();

  // Ann leaves: Cy, who is here, comes before Bo, who isn't yet.
  signaller.OnLeft(1001, out);
  EXPECT_EQ(signaller.Host(), 1003);
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"1 0 Cy "}));
  out.clear();
  signaller.OnJoined(1002, out);
  EXPECT_EQ(SignalsTo(out, 1002), (std::vector<std::string>{"2 1003 Bo Cy"}));

  // Cy goes quiet, then Bo: Bo took over, and was away when roles went out; nobody hears anything until Bo is back.
  out.clear();
  signaller.OnAway(1003, out);
  EXPECT_EQ(signaller.Host(), 1002);
  EXPECT_EQ(SignalsTo(out, 1002), (std::vector<std::string>{"1 0 Bo "}));
  out.clear();
  signaller.OnAway(1002, out);
  EXPECT_EQ(signaller.Host(), 1003); // the next who hasn't left: Cy, away as well
  EXPECT_TRUE(out.empty());
  signaller.OnBack(1003, out);
  EXPECT_EQ(signaller.Host(), 1003);
  EXPECT_EQ(SignalsTo(out, 1003), (std::vector<std::string>{"1 0 Cy "}));
  EXPECT_FALSE(signaller.HostLeft());
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
    int connectorsGone = 0;

    void SendLobbyFrame(const std::span<const std::uint8_t> frame) override { out.emplace_back(frame.begin(), frame.end()); }
    bool TakeLobbyFrame(std::vector<std::uint8_t>& frame) override { return inbox.TakeLobbyFrame(frame); }
    bool Up() const override { return up; }
    void TakeGone(std::vector<std::int32_t>& uids) override
    {
      uids.insert(uids.end(), gone.begin(), gone.end());
      gone.clear();
    }
    void ConnectorGone() override { ++connectorsGone; }
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

  // A participant the server says left: that connection ends once (CLobby: "PeerDisconnected").
  channelB.gone.push_back(1001);
  connectorB->Pull();
  connectorB->Pull();
  EXPECT_EQ(lobbyB.Count(kConnLostEof, bToA), 1u);

  // Plan WPR.50: the host leaves: Bo hosts now, and his game makes its lobby again; the old lobby's connector, destroyed
  // with it, frees the channel for the new one.
  server.Left(1001);
  ASSERT_TRUE(channelB.inbox.TakeSignal(signal));
  EXPECT_EQ(signal.kind, ELobbySignal::Host);
  connectorB->Destroy();
  EXPECT_EQ(channelB.connectorsGone, 1);

  // The channel gone: every connection of that side is lost, once.
  channelA.up = false;
  connectorA->Pull();
  connectorA->Pull();
  EXPECT_EQ(lobbyA.Count(kConnLostEof, aToB), 1u);

  connectorA->Destroy();
  EXPECT_EQ(channelA.connectorsGone, 1);
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

// Plan WP10.7: a server-mode player's sim-speed limit: lockstep's formula over the median view cost, and its message.
TEST(SpeedLimit, LockstepsFormulaAndTheMessage)
{
  using faf::remote::SpeedLimitOfBeatMs;
  EXPECT_EQ(SpeedLimitOfBeatMs(100.0), 0);   // ten beats a second: +0
  EXPECT_EQ(SpeedLimitOfBeatMs(10.0), 10);   // a hundred: +10
  EXPECT_EQ(SpeedLimitOfBeatMs(50.0), 3);    // twenty: 10 log10(2) = 3.01, rounded down
  EXPECT_EQ(SpeedLimitOfBeatMs(200.0), -4);  // five: -3.01, rounded down as RATE_GameRateToSpeed does
  EXPECT_EQ(SpeedLimitOfBeatMs(0.0), faf::remote::kMaxSpeedLimit);
  EXPECT_EQ(SpeedLimitOfBeatMs(100000.0), faf::remote::kMinSpeedLimit);
  faf::remote::CSpeedMeter meter;
  for (std::size_t i = 0; i + 1 < faf::remote::CSpeedMeter::kWindow; ++i) {
    meter.Add(i % 8 == 0 ? 400.0 : 20.0); // a slow beat now and then
  }
  EXPECT_FALSE(meter.Limit().has_value()); // not before a full window
  meter.Add(20.0);
  EXPECT_EQ(meter.Limit(), std::optional<int>(6)); // the median, 20 ms: fifty beats a second, +6
  // A machine at a step's edge: reported once it holds for a window, not at every flip.
  faf::remote::CSpeedMeter edge;
  int reports = 0;
  std::optional<int> last;
  for (int view = 0; view < 400; ++view) {
    edge.Add(view % 2 == 0 ? 20.0 : 19.0); // +6 and +7 views alternate; the median holds +6 or +7
    if (const std::optional<int> settled = edge.Settled(); settled) {
      ++reports;
      last = settled;
    }
  }
  EXPECT_EQ(reports, 1);
  EXPECT_TRUE(last == std::optional<int>(6) || last == std::optional<int>(7));
  for (int view = 0; view < 100; ++view) {
    edge.Add(200.0); // the machine slows: -4, reported once it holds
    if (const std::optional<int> settled = edge.Settled(); settled) {
      ++reports;
      last = settled;
    }
  }
  EXPECT_EQ(reports, 2);
  EXPECT_EQ(last, std::optional<int>(-4));
  for (const int limit : {-10, -3, 0, 7, 50}) {
    EXPECT_EQ(faf::remote::DecodeSpeedLimit(faf::remote::EncodeSpeedLimit(limit)), std::optional<int>(limit)) << limit;
  }
  EXPECT_EQ(faf::remote::DecodeSpeedLimit(faf::remote::EncodeSpeedLimit(99)), std::optional<int>(50)); // clamped when sent
  std::vector<std::uint8_t> past = faf::remote::EncodeSpeedLimit(0);
  past[1] = 61u; // 51
  EXPECT_FALSE(faf::remote::DecodeSpeedLimit(past).has_value());
  std::vector<std::uint8_t> longer = faf::remote::EncodeSpeedLimit(0);
  longer.push_back(0u);
  EXPECT_FALSE(faf::remote::DecodeSpeedLimit(longer).has_value());
  EXPECT_FALSE(faf::remote::DecodeSpeedLimit(std::vector<std::uint8_t>{static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::Chat), 10u}).has_value());
}

// Plan WP11.1: SetArmyIndex's request and answer, and the cameras SetGeomCams sends.
TEST(FocusAndCameras, MessagesRoundTrip)
{
  for (const int army : {-1, 0, 2, 15, faf::remote::kMaxFocusArmy}) {
    EXPECT_EQ(faf::remote::DecodeFocusArmy(faf::remote::EncodeFocusArmy(army)), std::optional<int>(army)) << army;
  }
  std::vector<std::uint8_t> past = faf::remote::EncodeFocusArmy(0);
  past[1] = static_cast<std::uint8_t>(faf::remote::kMaxFocusArmy + 2);
  EXPECT_FALSE(faf::remote::DecodeFocusArmy(past).has_value());
  std::vector<faf::remote::SCameraReport> cameras(2);
  cameras[0].viewProjection[5] = 1.5f;
  cameras[1].lodScale = 0.25f;
  std::vector<faf::remote::SCameraReport> back;
  ASSERT_TRUE(faf::remote::DecodeCameras(faf::remote::EncodeCameras(cameras), back));
  EXPECT_EQ(back, cameras);
  std::vector<faf::remote::SCameraReport> many(9);
  ASSERT_TRUE(faf::remote::DecodeCameras(faf::remote::EncodeCameras(many), back));
  EXPECT_EQ(back.size(), faf::remote::kMaxCameras); // at most four go
  std::vector<std::uint8_t> cut = faf::remote::EncodeCameras(cameras);
  cut.pop_back();
  EXPECT_FALSE(faf::remote::DecodeCameras(cut, back));
}

// Plan WP10.7 step 2: a link that falls further behind holds the game a step at a time; one that catches up lets go a
// step at a time; one that is far but steady (its delay, not its throughput) never holds it.
TEST(LinkSpeed, FallingBehindHoldsTheGameSteadyDelayDoesNot)
{
  using faf::server::CLinkSpeedGovernor;
  using faf::server::SLinkSample;
  CLinkSpeedGovernor governor;
  const auto at = [&governor](const double now, const int speed, const double behindSeconds) {
    const SLinkSample seat{1002, behindSeconds, false};
    return governor.Update(now, speed, 10, std::span<const SLinkSample>(&seat, 1u));
  };
  EXPECT_TRUE(at(0.0, 10, 3.0).empty());    // 3 s behind: the window starts
  EXPECT_TRUE(at(5.0, 10, 9.0).empty());    // within the window: nothing
  auto news = at(10.0, 10, 4.0);            // 4 s behind, 1 s further: held a step under +10
  ASSERT_EQ(news.size(), 1u);
  EXPECT_EQ(news[0].limit, std::optional<int>(9));
  EXPECT_EQ(governor.Slowest(), (std::optional<std::pair<int, std::int32_t>>(std::make_pair(9, 1002))));
  news = at(20.0, 9, 6.3);                  // still falling behind at +9: +8
  ASSERT_EQ(news.size(), 1u);
  EXPECT_EQ(news[0].limit, std::optional<int>(8));
  EXPECT_TRUE(at(30.0, 8, 1.6).empty());    // caught up: calm window 1
  EXPECT_TRUE(at(40.0, 8, 0.3).empty());     // 2
  news = at(50.0, 8, 0.1);                   // 3: a step up
  ASSERT_EQ(news.size(), 1u);
  EXPECT_EQ(news[0].limit, std::optional<int>(9));
  EXPECT_TRUE(at(60.0, 9, 0.1).empty());
  EXPECT_TRUE(at(70.0, 9, 0.1).empty());
  news = at(80.0, 9, 0.1);                   // the next step reaches the requested +10: the limit goes
  ASSERT_EQ(news.size(), 1u);
  EXPECT_FALSE(news[0].limit.has_value());
  EXPECT_FALSE(governor.Slowest().has_value());
  // A far link: 3 s behind every window, never further: no limit.
  CLinkSpeedGovernor steady;
  for (int window = 0; window < 10; ++window) {
    const SLinkSample seat{1001, 3.0, false};
    EXPECT_TRUE(steady.Update(10.0 * window, 10, 10, std::span<const SLinkSample>(&seat, 1u)).empty()) << window;
  }
  // A held link whose player leaves lets go of the game.
  CLinkSpeedGovernor leaving;
  SLinkSample seat{1003, 3.0, false};
  (void)leaving.Update(0.0, 10, 10, std::span<const SLinkSample>(&seat, 1u));
  seat.behindSeconds = 5.0;
  ASSERT_EQ(leaving.Update(10.0, 10, 10, std::span<const SLinkSample>(&seat, 1u)).size(), 1u);
  seat.gone = true;
  news = leaving.Update(11.0, 9, 10, std::span<const SLinkSample>(&seat, 1u));
  ASSERT_EQ(news.size(), 1u);
  EXPECT_FALSE(news[0].limit.has_value());
  EXPECT_FALSE(leaving.Slowest().has_value());
}
