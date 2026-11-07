#pragma once

// One peer link that behaves on the wire like a link of FAF's Java ICE adapter
// (java-ice-adapter 3.3.14, PeerIceModule and PeerConnectivityCheckerModule),
// on libjuice. docs/LAUNCHER_ADAPTER_CONTRACT.md §5-§6, issue #229.
//
//   * ICE with one UDP component; the offerer is the controlling agent.
//   * No trickle: each side gathers fully and sends one CandidatesMessage.
//     The answerer answers the offerer's message with its own.
//   * Datagrams: 'd' + game datagram; 'e' + 8 bytes echo, sent every second by
//     the offerer and returned unchanged by the answerer.
//   * Timers and restarts as PeerIceModule: gathering 5 s, no answer 6 s after
//     sending candidates, ICE checks 15 s, no echo answer 10 s. Only the
//     offerer starts again: at once after a lost connection, 5 s after a
//     failed attempt. 1 / 2 attempts in the last 2 minutes drop host / host
//     and reflexive candidates.
//
// Threading: Start, OnSignal, Send, Tick and Close may be called from any
// thread. libjuice runs its own thread; received game datagrams are handed to
// onData from it. Every other callback runs inside Tick, which the owner calls
// at least every 100 ms. Callbacks run without the link's lock held.
// Engine addition, not recovered code.

#include "netlink/LinkKeys.h"
#include "netlink/PathChoice.h"
#include "netlink/Signal.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct juice_agent;

namespace faf::netlink
{
  class WebRtcChannel;
}

namespace faf::remote::net
{
  class NetChannel;
}

namespace faf::netlink
{
  // PeerIceModule's IceState, with the strings it reports through
  // onIceConnectionStateChanged.
  enum class LinkState
  {
    New,
    Gathering,
    AwaitingCandidates,
    Checking,
    Connected,
    Disconnected
  };
  const char* LinkStateName(LinkState state);

  struct LinkOptions
  {
    std::int64_t localId = 0;
    std::int64_t remoteId = 0;
    bool offerer = false;
    std::vector<IceServer> iceServers;
    bool forceRelay = false;
    // Local address for every host candidate; empty binds all interfaces.
    std::string bindAddress;
    std::uint16_t portRangeBegin = 0;
    std::uint16_t portRangeEnd = 0;
    // Issue #234: our links start their ICE ufrag with this prefix (empty:
    // libjuice picks ufrag and password, nothing is marked). The Java adapter
    // reads the ufrag only as an ICE credential. A link whose remote ufrag has
    // the same prefix sends a probe ('f' datagrams) once connected; a peer
    // that answers is ours. A Java peer never gets one: its ufrags are lower-
    // case letters and digits, and kOurUfragPrefix holds a '+'.
    std::string ufragPrefix;
    // Issue #235: send every game datagram a second time, this many
    // milliseconds after the first (0: right after it). -1 (default) is off.
    // The game drops a repeated DATA packet by its sequence number
    // (FUN_00486DB0), so the copy only matters when the first is lost.
    int duplicateGapMs = -1;
    // Issue #239: offer layer 2. Our ufrag then starts with ufragPrefix +
    // "w+", and with a peer that does the same and proved to be ours the
    // game datagrams move onto a WebRTC data channel (netlink/WebRtc.h).
    bool webrtc = false;
    // Tests only: drop this share (0-100) of game datagrams in Send, on
    // either path, to compare loss handling; on the redundant lane (#240), of
    // the lane's datagrams instead.
    int testDropPercent = 0;
    // Issue #240, layer 3: with a peer that is ours and offers it too, game
    // datagrams go in a net channel (src/remote/net) whose datagrams repeat
    // each one in up to this many later datagrams until it is acked, so one
    // lost datagram costs no resend wait. The ufrag then carries "c+" after
    // the prefix (and "w+"). 0 (default) is off: plain 'd' frames.
    int redundancy = 0;
    // Issue #289: with the lane on, offer to encrypt it. The ufrag then ends
    // in "k+" and a new X25519 public key per attempt (netlink/LinkKeys.h);
    // with a peer that offers one too, the lane's datagrams are sealed with
    // XChaCha20-Poly1305 both ways. Without the lane nothing is encrypted.
    bool encrypt = true;
  };

  // The prefix faf-netbridge and the engine use.
  inline constexpr const char* kOurUfragPrefix = "fnl+";

  struct LinkCallbacks
  {
    std::function<void(const CandidatesMessage&)> onSignal; // to the remote peer, via onIceMsg
    std::function<void(const std::uint8_t*, std::size_t)> onData; // game datagram from the peer
    std::function<void(LinkState)> onState;
    std::function<void(bool)> onConnected;
    std::function<void(const std::string&)> onLog;
    // Issue #234: the peer answered our probe (once per connection).
    std::function<void()> onOurPeer;
    // Issue #239: a WebRTC signal for the peer, JSON text, through iceMsg
    // like onSignal's message.
    std::function<void(const std::string&)> onSignalText;
  };

  /** Packets and bytes every link in this process has given to ICE, before UDP and IP headers. */
  struct WireTotals
  {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
  };
  WireTotals GetWireTotals();

  struct LinkStats
  {
    std::uint64_t dataSent = 0;
    std::uint64_t dataReceived = 0;
    std::uint64_t dataDropped = 0; // Send while not connected
    std::uint64_t duplicatesSent = 0;
    std::uint64_t echoesSent = 0;
    std::uint64_t echoesAnswered = 0;
    std::uint64_t invalidReceived = 0; // first byte neither 'd' nor 'e'
    std::uint32_t attempts = 0;
    double lastRttMs = -1;
    bool onWebRtc = false;         // issue #239: datagrams on the data channel
    std::uint64_t webRtcSent = 0;  // of dataSent
    // Issue #240: the redundant lane, while on.
    bool onLane = false;
    std::uint64_t laneRepeats = 0;     // copies sent
    std::uint64_t laneUnacked = 0;     // datagrams whose copies ran out before an ack
    std::uint64_t laneDuplicates = 0;  // copies received after the datagram itself
    std::uint64_t laneLost = 0;        // lane datagrams counted lost
    // Issue #322: the selected pair's candidate types ("host", "srflx", "prflx",
    // "relay") while connected, empty otherwise. Either "relay": through TURN.
    std::string localType;
    std::string remoteType;
    bool laneEncrypted = false;        // issue #289: the lane is on and sealed
    std::uint64_t laneUnauthenticated = 0; // lane datagrams dropped: not sealed with the agreed key
    double laneRttMs = -1;             // issue #322: the lane's smoothed RTT, both ends; -1 before a sample
    PathChoice choice;                 // issue #322: the path the player picked
  };

  class Link
  {
  public:
    using Clock = std::chrono::steady_clock;

    Link(LinkOptions options, LinkCallbacks callbacks);
    ~Link();
    Link(const Link&) = delete;
    Link& operator=(const Link&) = delete;

    // The offerer starts gathering; the answerer waits for the offer.
    void Start();
    // A CandidatesMessage from the peer (iceMsg).
    void OnSignal(const CandidatesMessage& remote);
    // Issue #239: a WebRTC signal from the peer (IsWebRtcSignal).
    void OnSignalText(const std::string& json);
    // Sends 'd' + data. Dropped while not connected, as the Java adapter does.
    bool Send(const void* data, std::size_t size);
    // Timers, state changes and restarts.
    void Tick();
    // Stops the link for good.
    void Close();
    // No more restarts after a loss (GPGNet GameEnded).
    void SetGameEnded();
    // Issue #321: drop the connection and connect again, as after a loss. The
    // offerer offers again at once; the answerer waits for the peer's next
    // offer, which comes when the peer's echo goes unanswered. Done in the
    // next Tick, so the callbacks run on the ticking thread. Issue #322: with a
    // choice, this and later attempts take that path. Any thread.
    void Reconnect(const std::optional<PathChoice>& choice = std::nullopt)
    {
      std::lock_guard lock(mMutex);
      if (choice) {
        mPendingChoice = choice;
      }
      mReconnectAsked = true;
    }

    LinkState GetState() const;
    bool IsConnected() const { return mConnected.load(); }
    // Issue #234: the peer on this connection proved to be ours.
    bool IsOurPeer() const { return mOurPeer.load(); }
    LinkStats GetStats() const;
    const LinkOptions& GetOptions() const { return mOptions; }

  private:
    struct Pending; // deferred callbacks, run after the lock is released
    struct Internals; // libjuice-facing state (Link.cpp)

    void InitiateLocked(Pending& out, const CandidatesMessage* remote);
    void SendCandidatesLocked(Pending& out, Clock::time_point now);
    void ApplyRemoteLocked(Pending& out, const CandidatesMessage& remote, Clock::time_point now);
    void ConnectionLostLocked(Pending& out, const char* reason, Clock::time_point now);
    // The remote's marks from its ufrag, and the lane keys (#289) when both offer them.
    void NoteRemoteUfragLocked(Pending& out, const std::string& ufrag);
    void NotePeerPathLocked(Pending& out, const std::string& path);
    void StartWebRtcLocked(Pending& out);
    void DropWebRtcLocked(Pending& out);
    void SetStateLocked(Pending& out, LinkState state);
    void DestroyAgentLocked();
    std::uint32_t AttemptsInLastTwoMinutesLocked(Clock::time_point now) const;
    bool AllowedLocked(CandidateType type, Clock::time_point now) const;
    bool UsableRemoteLocked(const Candidate& c, Clock::time_point now) const;
    std::string RemoteDescriptionLocked(const CandidatesMessage& remote, Clock::time_point now) const;
    void Run(Pending& p);
    void Log(Pending& out, std::string text);
    // Through the test shaping when it is on (FAF_NETLINK_TEST_SHAPING), else
    // straight out.
    bool SendFramed(const char* framed, std::size_t size);
    bool SendFramedNow(const char* framed, std::size_t size);
    bool SendWebRtc(const std::shared_ptr<WebRtcChannel>& rtc, const void* data, std::size_t size);
    // Issue #240. None of these is called with mMutex held, and none holds
    // mLaneMutex while it takes mMutex.
    void LaneDeliver(const std::uint8_t* data, std::size_t size);
    void LanePoll();
    void LaneTransmit(const std::vector<std::vector<std::uint8_t>>& datagrams);
    remote::net::NetChannel& LaneLocked(); // mLaneMutex held: the lane, new after a reset

    const LinkOptions mOptions;
    const LinkCallbacks mCallbacks;
    const std::unique_ptr<Internals> mIn;

    mutable std::mutex mMutex;
    juice_agent* mAgent = nullptr;
    LinkState mState = LinkState::New;
    bool mClosed = false;
    bool mGameEnded = false;
    bool mPendingAnswer = false; // answerer: go to checking once our candidates are out
    std::deque<CandidatesMessage> mInbox;
    std::deque<Clock::time_point> mAttemptTimes; // newest first, as connectivityAttemptTimes
    std::optional<Clock::time_point> mGatherDeadline;
    std::optional<Clock::time_point> mAwaitDeadline;
    std::optional<Clock::time_point> mCheckDeadline;
    std::optional<Clock::time_point> mRestartAt;
    std::atomic<bool> mReconnectAsked{false}; // issue #321
    std::optional<PathChoice> mPendingChoice;  // issue #322, under mMutex
    PathChoice mChoice;                        // under mMutex
    bool mChoicePicked = false;                // the player picked mChoice: tell our peer
    PathChoice::Mode mPeerMode = PathChoice::Mode::Auto; // the peer's pick, this attempt
    Clock::time_point mNextEcho{};
    std::atomic<std::int64_t> mLastEchoReplyMs{0};
    LinkStats mStats;
    std::atomic<std::uint64_t> mDataReceived{0};
    std::atomic<std::uint64_t> mInvalidReceived{0};
    std::atomic<std::uint64_t> mEchoesAnswered{0};
    std::atomic<std::int64_t> mLastRttMicros{-1};
    std::atomic<bool> mConnected{false};
    std::string mRemoteUfrag;
    bool mRemoteMarked = false;
    int mProbesSent = 0;
    Clock::time_point mNextProbe{};
    std::atomic<bool> mOurPeer{false};
    std::atomic<bool> mOurPeerReported{false};
    // Issue #239.
    bool mRemoteWebRtc = false;
    bool mWebRtcGaveUp = false; // for this connection
    std::shared_ptr<WebRtcChannel> mRtc;
    // mRtc for LaneTransmit, which must not take mMutex (see there). Held only to copy it.
    std::mutex mLaneRtcMutex;
    std::shared_ptr<WebRtcChannel> mLaneRtc;
    std::atomic<std::uint64_t> mWebRtcSent{0};
    // Issue #240.
    bool mRemoteLane = false;
    std::atomic<bool> mLaneActive{false};
    std::atomic<bool> mLaneReset{false}; // a new connection: the next use starts a new lane
    mutable std::mutex mLaneMutex;
    std::unique_ptr<remote::net::NetChannel> mLane;
    // Issue #289. mKeyPair: this attempt's, under mMutex. mLaneKeys: what the
    // next lane is sealed with, under mLaneMutex; set before the connection
    // comes up and cleared with the agent, so every lane gets the keys of its
    // own connection and no key outlives it. mLaneKeyed mirrors it under mMutex.
    // Issue #322: the selected pair's candidate types, under mMutex.
    std::string mLocalType;
    std::string mRemoteType;
    LinkKeyPair mKeyPair;
    std::optional<remote::net::ChannelKeys> mLaneKeys;
    bool mLaneKeyed = false;
  };
} // namespace faf::netlink
