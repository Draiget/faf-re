#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "remote/ContentCheck.h"
#include "remote/FocusAndCameras.h"
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
     * Plan WP10.7: each player's channel keeps a congestion window (`ChannelConfig::congestionControl`). Off by default:
     * on a 30 KB/s line with a 200 ms buffer it ended the resend flood (82 KB/s sent at the start instead of 811) but
     * delivered 22.2 KB/s of the 30 (Reno's sawtooth on a shallow buffer), less than sending flat out.
     */
    bool congestionControl = false;
    /**
     * Plan WPR.50: in the lobby, a participant heard from for this long counts as away (`TakeLobbyPresence`), well
     * before its channel's own 10 s timeout, so a logical host that is gone is succeeded within 10 s. A client sends
     * a keepalive every quarter second while its game runs; a frozen lobby screen stops them too, so not much shorter.
     * 0: only the channel's timeout.
     */
    double lobbyAwaySeconds = 6.0;
    /** Plan WP17.1: the match file's `MatchLobbyControl`: organised (WPR.49's rules) or player-hosted. */
    ELobbyControl lobbyControl = ELobbyControl::Organiser;
    /**
     * Plan WP17.8: the match file's `MatchUiMods`, the UI mods a player may run (empty: none); unset: any. A player who
     * runs another is judged under `MatchContentCheck` (warned, or out of the game), as reported by their game.
     */
    std::optional<std::vector<std::string>> uiModsAllowed;
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
      bool gone = false; // out of the game: no longer away, and not back either
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
    /** Plan WP17.2: a lobby message to `uid` in `from`'s name (`CLobbyRelay::FrameFrom`), queued like the server's own. */
    void QueueLobbyAs(std::int32_t uid, std::int32_t from, const std::vector<std::uint8_t>& message);
    /** Plan WP17.2: a new set of pinned options while the lobby is open; applied on the network thread. */
    void RequestPins(SPinnedOptions pinned);
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

    /** Plan WP17.2: a seat as the control API reports it, refreshed on the network thread. */
    struct SSeatState
    {
      std::int32_t uid = 0;
      std::string name;
      bool joined = false;
      bool loaded = false;
      bool lost = false;
      bool gone = false;
      bool away = false; // quiet in the lobby
      std::uint32_t pingMs = 0;
      // Plan WP17.2, WP17.8: the server's verdicts on what the player's game reported ("" until judged): content
      // "same", "differs" or "missing"; UI mods "allowed", "outside" or "missing"; and the UI mods it reported.
      std::string content;
      std::string mods;
      std::vector<std::string> uiMods;
      // Plan WP12.1: how far its game has loaded: "" before the launch, "loading", "rules" (its content report came, so
      // the rules are loaded), "loaded" (at the start barrier).
      std::string load;
      // Plan WP17.2: in the lobby, the ready state its own PlayerOptions last set: "yes", "no", or "" before it did.
      std::string ready;
      // Plan WP17.2: the lobby slot the host's lobby put it in (lobby.lua's slot, not the match's army); 0 before.
      int lobbySlot = 0;
      // Plan WP10.7: the sim-speed limit its game last reported (remote/SpeedLimit.h); nothing before it did.
      std::optional<int> speedLimit;
      // Plan WP11.1: camera updates its game sent (`SetGeomCams`, at most four a second).
      std::uint64_t cameraUpdates = 0;
      // Plan WP10.7: how far behind its link is: the reliable bytes it hasn't acked, and the beats between the newest
      // view queued and the newest it has acked whole (an estimate: other messages share the stream).
      std::uint64_t backlogBytes = 0;
      std::uint32_t behindBeats = 0;
      double behindSeconds = 0.0; // how long the oldest view it hasn't acked whole has waited
    };
    [[nodiscard]] std::vector<SSeatState> Seats();
    /** Plan WP17.2: each verdict made since the last call, as the seat stood then (uid, name and the verdict fields). */
    [[nodiscard]] std::vector<SSeatState> TakeJudged();
    /**
     * Plan WP10.7: the lowest sim-speed limit of the seats still in the game (not gone) that reported one, and whose;
     * nothing when none did. As `CClientManagerImpl::GetSimRate` takes the lowest client's. Any thread.
     */
    [[nodiscard]] std::optional<std::pair<int, std::int32_t>> SlowestSpeedLimit();
    /**
     * Plan WP11.1: a player's own army, the focus the server grants their `SetFocusArmy` requests; `FreeFocus` lets
     * them pick any (defeated, with `DefeatedPlayerView = "observe"`). Any thread.
     */
    void SetFocusRule(std::int32_t uid, int ownArmy);
    void FreeFocus(std::int32_t uid);
    /** Plan WP17.2: lobby ready states that changed since the last call (uid, ready), in order. */
    [[nodiscard]] std::vector<std::pair<std::int32_t, bool>> TakeReadyChanges();
    /**
     * Plan WP17.2: a participant out of the match (the organiser's eject, or a defeat with `DefeatedPlayerView =
     * "disconnect"`), as one who leaves is; done on the network thread. `reason` goes to the log whole. False: no such seat.
     */
    bool RequestEject(std::int32_t uid, std::string reason);
    /** Plan WP17.2: the organiser adds an address to the handshake allowlist or takes it off; done on the network thread. */
    void RequestAddress(std::uint32_t ip, bool allow);
    /**
     * Plan WP15.4 (#200): another person takes a seat during the game. The seat keeps its uid; its admission token and
     * name become `token` and `name`, the old player's channel goes, and the substitute joins as a player coming back
     * (launch info and a whole view again, the reconnect window running). False: no such seat, or it's out of the game.
     */
    bool RequestSubstitute(std::int32_t uid, const std::string& token, std::string name);
    /** Plan WP17.1: the current logical host (0: none), from the lobby's succession; its ejects go through in a player-hosted lobby. */
    void SetLobbyHost(const std::int32_t uid) noexcept { mLobbyHost.store(uid, std::memory_order_relaxed); }
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
      // Plan WP10.7: the reliable bytes queued to it from the views' path, and where each view's message ended in
      // them (with its beat), oldest first; the views behind the peer's acked prefix are dropped as it moves on.
      std::uint64_t viewBytesQueued = 0;
      struct SViewEnd
      {
        std::uint64_t offset = 0; // where the view's message ends in the views' bytes
        std::uint32_t beat = 0;
        std::uint64_t queuedUs = 0;
      };
      std::deque<SViewEnd> viewEnds;
      std::uint32_t lastViewBeat = 0;
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
      bool modsReported = false;   // plan WP17.8: its mod report came
      std::vector<remote::SModEntry> mods;
      bool modsJudged = false;
      std::string contentVerdict; // plan WP17.2: as SSeatState's
      std::string modsVerdict;
      std::optional<int> speedLimit; // plan WP10.7: the last its game reported
      std::vector<remote::SCameraReport> cameras; // plan WP11.1: its cameras, as last reported
      std::uint64_t cameraUpdates = 0;
      std::uint64_t camerasAtUs = 0;
      double cameraTokens = 0.0; // plan WP11.1: the camera updates it may still send now (refilled at eight a second)
      // Plan WP11.4: its client in the session, as every player's roster lists it.
      int clientIndex = -1;
      std::vector<std::uint8_t> sources;
      bool startSent = false;   // its launch has gone: its game takes rosters and chat from now on
      bool rosterOwed = false;  // the next roster pass sends it the roster, changed or not
      bool substituted = false; // plan WP15.4: another person was given the seat; their first join counts as a return
      remote::CChatBudget chatBudget;
    };

    void Run();
    /** Plan WPR.50: the lobby's view of who is quiet, each pass while it is open. */
    void WatchLobbyPresence(std::uint64_t nowUs);
    void NoteLobbyPresence(std::int32_t uid, SSeat& seat, bool away);
    /** Plan WP2.6: once the server's content is known, a seat with a report, or loaded without one. */
    void JudgeContent(std::int32_t uid, SSeat& seat);
    /** Plan WP17.8: once the server's content is known and a policy is set, a seat with a mod report, or loaded without one. */
    void JudgeMods(std::int32_t uid, SSeat& seat);
    /** The seat's verdicts so far, queued for `TakeJudged`. */
    void NoteJudged(std::int32_t uid, const SSeat& seat);
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
    std::vector<SSeatState> mJudged;
    std::vector<std::pair<std::int32_t, bool>> mReadyNews; // plan WP17.2 (`TakeReadyChanges`)          // plan WP17.2: each seat's verdicts as they were made (`TakeJudged`)
    std::uint64_t mBadMessages = 0;
    std::uint64_t mFocusRefused = 0;   // plan WP11.1
    std::uint64_t mCamerasDropped = 0; // plan WP11.1: camera updates past the bucket (eight a second, four at once)
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
    struct SFocusRule
    {
      int ownArmy = -1;
      bool free = false;
    };
    std::map<std::int32_t, SFocusRule> mFocusRules; // plan WP11.1, under mNewsLock
    std::vector<std::string> mNews;
    std::vector<SSeatState> mSeatStates;                         // under mNewsLock
    std::vector<std::pair<std::int32_t, std::string>> mEjects;   // likewise: uid, reason
    std::vector<std::pair<std::uint32_t, bool>> mAddressChanges; // likewise: ip, allow
    std::optional<SPinnedOptions> mPinsIn;                      // likewise
    struct SSubstitute
    {
      std::int32_t uid;
      std::string token;
      std::string name;
    };
    std::vector<SSubstitute> mSubstitutes;                      // likewise

    CLobbyRelay mLobby;                        // on the network thread
    std::vector<std::uint8_t> mLobbyFrame;     // the frame being relayed
    std::atomic<bool> mCloseLobby{false};
    std::atomic<std::int32_t> mLobbyHost{0};
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
