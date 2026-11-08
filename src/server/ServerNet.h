#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "remote/ContentCheck.h"
#include "remote/SeatRoster.h"
#include "remote/net/GameLinks.h"
#include "server/LobbyRelay.h"
#include "server/SeatIntake.h"

// Engine addition, dedicated server (plan WP1.1, WP3.5, WP10.1, WP10.5): the players' network. Its own
// thread takes what arrives on the socket and hands each player's commands to their seat, so a slow
// sim beat delays nobody's connection and a burst of datagrams delays no beat.
//
// A player who hasn't joined when the wait is over, or who stays away past the reconnect window, is
// ejected as a lockstep game would eject them. A game whose seats nobody ever sat in has no reason to run.

namespace moho
{
  class CClientManagerImpl;
}

namespace faf::remote
{
  class CServerClient;
}

namespace faf::server
{
  struct SServerNetConfig
  {
    remote::net::SEndpoint listen;
    double joinSeconds = 120.0;
    double reconnectSeconds = 60.0;
    /** Views wait for a player who hasn't joined yet; off when nobody's expected, as they'd pile up. */
    bool holdViewsForJoin = true;
    /**
     * Plan WPR.50: in the lobby, a participant heard from for this long counts as away (`TakeLobbyPresence`), well
     * before its channel's own 10 s timeout, so a logical host that is gone is succeeded within 10 s. A client sends
     * a keepalive every quarter second while its game runs; a frozen lobby screen stops them too, so not much shorter.
     * 0: only the channel's timeout.
     */
    double lobbyAwaySeconds = 6.0;
  };

  class CServerNet final : private remote::net::CServerLinks::IEvents
  {
  public:
    explicit CServerNet(const SServerNetConfig& config);
    ~CServerNet() override;
    CServerNet(const CServerNet&) = delete;
    CServerNet& operator=(const CServerNet&) = delete;

    void AddSeat(std::int32_t uid, const char* name, const std::string& token, remote::CServerClient& seat);

    /** Before `Start`: an address the match knows a player by (`CServerLinks::AllowAddress`). */
    void AllowAddress(std::uint32_t ip) { mLinks.AllowAddress(ip); }

    /** Binds the socket and starts the thread. */
    [[nodiscard]] bool Start(std::string& error);
    /** Stops the thread; no seat is touched after this returns. */
    void Stop();

    /**
     * A reliable message for a player, in order, from any thread: it waits until they've joined. `fresh`: a view
     * whose lanes are whole (`CViewLanes::RequestFresh`), which a returning player starts from.
     */
    void QueueView(std::int32_t uid, std::vector<std::uint8_t> message, bool fresh = false);
    /** Bytes sent to all players so far. */
    [[nodiscard]] std::uint64_t BytesSent() const noexcept { return mBytesSent.load(std::memory_order_relaxed); }

    /** The newest beat, for the players. */
    void NoteBeat(std::int32_t beat) noexcept { mBeat.store(beat, std::memory_order_relaxed); }

    /** Where the players' commands wait for the sim's thread. */
    [[nodiscard]] CSeatIntake& Intake() noexcept { return mIntake; }

    /** Players gone for good since the last call: nobody needs their views any more. */
    [[nodiscard]] std::vector<std::int32_t> TakeGone();
    /** Players back since the last call, who hold no view now: their next one must be fresh (plan WP14.1). */
    [[nodiscard]] std::vector<std::int32_t> TakeReturned();

    /** A player who lost the connection (`away`), or came back or left the game since. */
    struct SPresence
    {
      std::int32_t uid;
      bool away;
    };
    /** Who went away or stopped being away since the last call, in order. */
    [[nodiscard]] std::vector<SPresence> TakePresence();

    /**
     * Plan WP2.13: lobby messages between participants are relayed on the network thread (`CLobbyRelay`); one for
     * the server itself (uid 0) waits here. From any thread.
     */
    struct SLobbyMessage
    {
      std::int32_t from = 0;
      std::vector<std::uint8_t> message;
    };
    [[nodiscard]] std::vector<SLobbyMessage> TakeLobbyMessages();
    /** A lobby signal from the server to a participant, in order, once they've joined. From any thread. */
    void QueueLobbyFromServer(std::int32_t uid, const std::vector<std::uint8_t>& message);
    /** Participants whose channel came up for the first time since the last call, for the lobby's signals. */
    [[nodiscard]] std::vector<std::int32_t> TakeLobbyJoined();
    /** Participants out of the game since the last call, for the lobby's signals (the game's views read `TakeGone`). */
    [[nodiscard]] std::vector<std::int32_t> TakeLobbyLeft();
    /**
     * Plan WPR.50: while the lobby is open, participants who went quiet (`lobbyAwaySeconds`, or their channel timed
     * out) or were heard again since the last call, in order.
     */
    [[nodiscard]] std::vector<SPresence> TakeLobbyPresence();
    /** At launch (plan WPR.51): the relay takes nothing more. From any thread. */
    void CloseLobby() noexcept { mCloseLobby.store(true, std::memory_order_relaxed); }
    /** Before `Start` (plan WPR.49): the game options the match pins (`CLobbyRelay::PinOptions`). */
    void PinLobbyOptions(SPinnedOptions pinned) { mLobby.PinOptions(std::move(pinned)); }
    /** Forwarded lobby messages whose pinned options were written back; after `Stop`. */
    [[nodiscard]] std::uint64_t LobbyOptionsPinned() const noexcept { return mLobby.OptionsPinned(); }

    /**
     * Plan WP2.6: the server's own content, once its rules are loaded, and what the match says to do with a player
     * whose report differs. Reports that came before are judged then; a player who loaded with no report counts as
     * one whose content differs. From any thread.
     */
    void SetContentCheck(remote::EContentCheck mode, const remote::SContentReport& expected);

    /** What arrived that wasn't a player's, for the console; after `Stop`. */
    [[nodiscard]] std::string LinkReport() const;

    /** Lines for the console since the last call. */
    [[nodiscard]] std::vector<std::string> TakeNews();
    /** The wait is over and nobody ever joined. */
    [[nodiscard]] bool NobodyCame() const noexcept { return mNobodyCame.load(std::memory_order_relaxed); }

    [[nodiscard]] remote::net::SEndpoint Local() const noexcept { return mLinks.Local(); }

  private:
    struct SSeat
    {
      std::string name;
      remote::CServerClient* seat = nullptr;
      bool joinedEver = false;
      bool loaded = false;
      bool lost = false;
      bool gone = false;
      // A returning player has lost the frames the next one is encoded against, so it waits for a fresh one (WP14.1).
      bool viewBroken = false;
      std::uint64_t lostAtUs = 0;
      std::uint64_t lastResyncUs = 0; // its last view sent whole on a `ViewMismatch`
      std::uint64_t bytesSeen = 0; // its channel's count; a new channel starts again
      bool lobbyAway = false;      // plan WPR.50: quiet in the lobby
      bool reported = false;       // plan WP2.6: its content report came
      remote::SContentReport report;
      bool contentJudged = false;
      // Plan WP11.4: its client in the session, as every player's roster lists it.
      int clientIndex = -1;
      std::vector<std::uint8_t> sources;
      bool startSent = false;   // its launch has gone: its game takes rosters and chat from now on
      bool rosterOwed = false;  // the next roster pass sends it the roster, changed or not
      remote::CChatBudget chatBudget;
    };

    void Run();
    /** Plan WPR.50: the lobby's view of who is quiet, each pass while it is open. */
    void WatchLobbyPresence(std::uint64_t nowUs);
    void NoteLobbyPresence(std::int32_t uid, SSeat& seat, bool away);
    /** Plan WP2.6: once the server's content is known, a seat with a report, or loaded without one. */
    void JudgeContent(std::int32_t uid, SSeat& seat);
    void Tick(std::uint64_t nowUs);
    void Remove(std::int32_t uid, SSeat& seat, const std::string& why);
    void Say(std::string line);
    void SendViews();
    void SendLobby();
    /** Plan WP11.4: the roster to every player whose launch has gone, when it changed (ping and quiet time once a second). */
    void SendRosters(std::uint64_t nowUs);
    [[nodiscard]] remote::wire::SRoster BuildRoster(std::uint64_t nowUs) const;
    void RelayChat(SSeat& from, const std::vector<std::uint8_t>& message);

    void OnJoined(std::int32_t uid, const remote::net::SEndpoint& from, bool returning) override;
    void OnMessage(std::int32_t uid, const std::vector<std::uint8_t>& message) override;
    void OnLost(std::int32_t uid) override;

    SServerNetConfig mConfig;
    CSeatIntake mIntake;
    remote::net::CServerLinks mLinks;
    std::map<std::int32_t, SSeat> mSeats;
    std::thread mThread;
    std::atomic<bool> mStop{false};
    std::atomic<bool> mNobodyCame{false};
    std::atomic<std::int32_t> mBeat{-1};
    std::int32_t mBeatSent = -1;
    std::uint64_t mStartUs = 0;
    std::uint64_t mNowUs = 0;
    bool mJoinWaitOver = false;
    std::vector<std::int32_t> mGone;          // under mNewsLock
    std::vector<std::int32_t> mReturned;      // likewise
    std::vector<SPresence> mPresence;         // likewise
    std::uint64_t mBadMessages = 0;
    std::uint64_t mViewMismatches = 0;
    remote::wire::SRoster mRosterSent; // the last sent to everyone, without a local index
    bool mRosterSentEver = false;
    std::uint64_t mRosterSentUs = 0;
    std::uint64_t mRosterCheckedUs = 0;
    std::uint64_t mRostersSent = 0;
    std::uint64_t mChatRelayed = 0;
    std::uint64_t mChatDropped = 0;
    static constexpr double kResyncSeconds = 10.0;
    // `OnMessage` runs inside the links' pass over their players, so they go once it's over.
    std::vector<std::int32_t> mToUnlink;

    struct SQueuedMessage
    {
      std::vector<std::uint8_t> bytes;
      bool fresh = false;
    };
    std::atomic<std::uint64_t> mBytesSent{0};
    std::mutex mViewLock;
    std::map<std::int32_t, std::vector<SQueuedMessage>> mViewQueue;
    // Each player's LaunchInfo and GameInfo, in the order queued, to send again on their return.
    std::map<std::int32_t, std::vector<std::vector<std::uint8_t>>> mStartMessages;
    // Each player's session-table records (`SessionTables`), every one queued: a returning player, whose client may
    // have missed some, gets a reset and all of them again before its whole view (plan WP11 step 4).
    std::map<std::int32_t, std::vector<std::vector<std::uint8_t>>> mTableLogs;
    std::vector<SQueuedMessage> mViewSending;

    std::mutex mNewsLock;
    std::vector<std::string> mNews;

    CLobbyRelay mLobby;                        // on the network thread
    std::vector<std::uint8_t> mLobbyFrame;     // the frame being relayed
    std::atomic<bool> mCloseLobby{false};
    std::uint64_t mLobbyUndelivered = 0;       // relayed to a participant with no channel
    std::vector<SLobbyMessage> mLobbyIn;       // for the host; under mNewsLock
    std::vector<std::int32_t> mLobbyLeft;      // likewise
    std::vector<std::int32_t> mLobbyJoined;    // likewise
    std::vector<SPresence> mLobbyPresence;     // likewise
    std::vector<SLobbyMessage> mLobbyOut;      // from the host, `from` being the participant it's for; under mViewLock

    // Plan WP2.6. Set from any thread under mNewsLock; the network thread takes it over once.
    bool mContentSet = false;                  // under mNewsLock
    remote::EContentCheck mContentModeIn = remote::EContentCheck::Off;
    remote::SContentReport mContentExpectedIn;
    bool mContentKnown = false;                // on the network thread
    remote::EContentCheck mContentMode = remote::EContentCheck::Off;
    remote::SContentReport mContentExpected;
  };
} // namespace faf::server
