#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include "CMessage.h"
#include "PeerFeatures.h"
#include "gpg/core/streams/PipeStream.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"

namespace gpg
{
  class Stream;
}

namespace moho
{
  class ISTIDriver;
  class CClientBase;
  class CClientManagerImpl;
  class CNetClient;
  struct SWldSessionInfo;
  class LaunchInfoBase;

  /**
   * Engine addition, not in the binary (issue #275): plays a recorded command
   * stream into the clients of a live session, so a client that lost its game
   * catches up and then takes its seat again.
   *
   * A replay session funnels every source through one `CReplayClient`. This
   * splits the recorded stream back into one queue per client instead, so the
   * session has the live roster from the first beat. `CClientBase::UpdateState`
   * merges the queues in client order, the order the stream was recorded in.
   *
   * While catching up nothing this client's driver or UI says leaves the
   * manager, and the driver issues no beats. From the handover beat on the
   * driver issues this client's beats as in any live game.
   */
  class CRejoinFeed
  {
  public:
    /**
     * `handoverBeat` is the last beat whose advance comes from the recording
     * for the local client. With `live`, the peers settle it, and send what the
     * recording does not hold yet; `recordingPeer` is the client index of the
     * peer whose replay `recording` is. The clients' later data comes from their links.
     * With `skipBeats`, the sim comes from a save of that beat, so the recording's
     * first beats only count, and go to this client's own replay.
     */
    CRejoinFeed(
      CClientManagerImpl& manager, std::unique_ptr<gpg::Stream> recording, int handoverBeat, bool live, int recordingPeer = -1, int skipBeats = 0
    );
    ~CRejoinFeed();

    /// Called at the top of `DoBeat`: queues the recorded beats now due.
    void Pump();

    /// Called by `ProcessClients`: true when `msg` was handled here.
    [[nodiscard]] bool Route(CMessage& msg);

    /**
     * Called on the issue thread after `DoBeat`: true while the driver must not
     * issue beats. On the call that ends that, sets `nextIssueBeat` to the beat
     * the driver issues first.
     */
    [[nodiscard]] bool HoldIssue(int32_t& nextIssueBeat);

    [[nodiscard]] bool CatchingUp() const { return mCatchingUp; }

    /// The beats a sim loaded from a save starts past; 0 without one.
    [[nodiscard]] int32_t SkippedBeats() const { return mSkippedBeats; }

    /// Where this client has got taking its seat back, for its own player and its peers.
    [[nodiscard]] SRejoinStatus Status() const;

    /// Called by `CNetClient::ReceiveMessage`: true when `msg` was taken here.
    [[nodiscard]] bool TakeIncoming(CNetClient& client, CMessage& msg);

  private:
    /// Reads past the beats the save holds, keeping what the clients would have learned.
    void SkipRecordedBeats(int32_t beats);
    /// Tells the peers where this client has got, so their players can see it.
    void ReportStatus();
    /// The live end of catching up: the backlog, then what the peers said meanwhile.
    void FinishCatchUp();
    /// One peer's report. When every peer has reported, settles the cut and tells them.
    void NotePeerReport(const CNetClient& peer, CMessage& msg);
    /// Queues one client's messages from `backlog`, skipping those of beats up to `skipThrough`. Returns the beat it reached.
    int32_t QueueBacklog(CClientBase& client, gpg::PipeStream& backlog, int32_t startBeat, int32_t skipThrough, int32_t stopAt);
    /// Reads one recorded beat: other clients' data into their queues, the local client's into `mHeld`.
    [[nodiscard]] bool ReadRecordedBeat();
    /// Moves one beat of `mHeld` into the local client's queue.
    void DeliverLocalBeat();
    /// The local client's advance from the driver: brings its queue `beatDelta` beats on.
    void DeliverLocalBeats(int32_t beatDelta);
    /// Files "`client` has data through `beat`" on every client but the local one, which hears it from its own queue.
    void NoteAcks(int clientIndex, int32_t beat);
    /// The recording ended: as `CReplayClient::Start` at the end of its stream.
    void EndOfRecording();

    CClientManagerImpl& mManager;
    std::unique_ptr<gpg::Stream> mRecording;
    CClientBase* mLocal;
    CMessage mMessage;
    gpg::PipeStream mHeld;
    int mHeldBeats = 0;
    CClientBase* mRecordedSource = nullptr;
    int32_t mReadBeat = 0;
    int32_t mHandoverBeat;
    bool mCatchingUp = true;
    bool mHandoverPending = false;
    bool mEnded = false;
    int mDriverAdvances = 0;
    int32_t mDriverBeats = 0;
    bool mLive;
    bool mBacklogComplete = false;
    int32_t mMergedBeat = 0;
    int mRecordingPeer;
    int mPeersReported = 0;
    int32_t mSkippedBeats = 0;
    std::chrono::steady_clock::time_point mReportedAt{};
    std::chrono::steady_clock::time_point mBackAt{};
    // Per reporting peer: its dispatched beat, and the queued beat of every client.
    std::vector<int32_t> mPeerDispatched;
    std::vector<std::vector<int32_t>> mPeerQueued;
    // Per peer, each client's stream position there: where that peer's copy of the client's
    // stream starts. It can be past the peer's dispatched beat after a multi-beat Advance
    // (issue #275). Empty when the peer's build doesn't send it.
    std::vector<std::vector<int32_t>> mPeerStreamDispatched;
    // [peer][client]: what that peer holds of that client's stream.
    std::vector<std::vector<std::unique_ptr<gpg::PipeStream>>> mBacklog;
    std::vector<std::vector<CMessage>> mHeldIncoming;
  };

  /**
   * Engine addition (issue #275): the client manager of a session that plays
   * `recording` as client `localSource` of a live game, with the driver taking
   * over at `handoverBeat`. Other clients stay fed from the recording, so
   * headless can check the handover against the recorded checksums without a
   * network. Client indices are the command sources, as `BuildLaunchInfo`
   * assigns them.
   */
  [[nodiscard]] CClientManagerImpl* REJOIN_CreateRehearsalManager(
    const LaunchInfoBase& launchInfo,
    std::unique_ptr<gpg::Stream> recording,
    int localSource,
    int handoverBeat,
    int skipBeats = 0
  );

  /**
   * Engine addition (issue #275), on the issue thread with `mLock` held, with
   * net_RejoinAccept on: a peer that reconnected from its old address gets a new
   * link in place of the old one, and everything it needs that its recording of
   * the game does not hold. Anything else that connects is rejected.
   */
  void REJOIN_ServeRestartedPeers(CClientManagerImpl& manager);

  /**
   * Engine addition (issue #275), with `mLock` held: `seat` has a new link and has not
   * had its backlog yet. The command stream stays off that link until then, as all of
   * it will be in the backlog, and would otherwise reach the client twice.
   */
  [[nodiscard]] bool REJOIN_BacklogPending(const CNetClient& seat);

  /**
   * Engine addition (issue #275), with `mLock` held, as the player here votes to eject
   * `seat` and its link closes: a client on its way back hears why, and so does one
   * that comes back later.
   */
  void REJOIN_NoteSeatEjected(CClientManagerImpl& manager, CNetClient& seat);

  /**
   * Engine addition (issue #275), with `mLock` held: `peer`, back from a restart,
   * asks for what it lost, or says where its old stream ends. In that case whatever
   * this client holds past that beat goes; no client can have run it, as a beat
   * runs only once every client holds it.
   */
  void REJOIN_HandlePeerMessage(CClientManagerImpl& manager, CNetClient& peer, CMessage& msg);

  /**
   * Engine addition (issue #275): `sink` with a copy of everything written to it
   * kept in memory, so a peer back from a restart can be sent the recording,
   * whatever `sink` is (FAF's live replay stream cannot be read back).
   */
  [[nodiscard]] std::unique_ptr<gpg::Stream> REJOIN_WrapRecording(std::unique_ptr<gpg::Stream> sink);

  /// Engine addition (issue #275): what follows on `stream` is the command stream.
  void REJOIN_SealRecordingHeader(gpg::Stream* stream);

  /**
   * Engine addition (issue #275): starts setting up the session of a client taking
   * its seat back: links to `peers`, written `address:port=source,...`, and asks the
   * first one for the game's recording. Client indices are the command sources, as
   * `BuildLaunchInfo` assigns them. `REJOIN_PollSetup` does the rest, once a frame.
   */
  [[nodiscard]] bool REJOIN_BeginSetup(
    const char* peers,
    int localSource,
    unsigned short localPort,
    fa::string* failureReason
  );

  /// Whether `REJOIN_BeginSetup` has started something `REJOIN_PollSetup` hasn't finished.
  [[nodiscard]] bool REJOIN_SetupPending();

  /// How much of the recording has come, 0 to 1, or negative before its size is known.
  [[nodiscard]] float REJOIN_SetupProgress();

  /**
   * One frame of the wait. The session once everything has come; otherwise null,
   * with `*failed` set and `failureReason` filled if it never will.
   */
  [[nodiscard]] fa::auto_ptr<SWldSessionInfo> REJOIN_PollSetup(fa::string* failureReason, bool* failed);

  /**
   * Engine addition (issue #275): when a save came with this client's seat, makes
   * the session's launch info load it, as `CSavedGame::CreateSinglePlayerSessionInfo`
   * builds a saved game's. Called before the driver is created.
   */
  void REJOIN_PrepareRestore(SWldSessionInfo& sessionInfo);

  /// Engine addition (issue #275): main thread, each frame: asks `driver` for a save a peer is waiting for.
  void REJOIN_MainFrame(ISTIDriver& driver);
} // namespace moho
