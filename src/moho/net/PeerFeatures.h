#pragma once

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "moho/net/RejoinKey.h"

namespace moho
{
  class CClientManagerImpl;
  class CMessageStream;
  class CNetClient;
  struct CMessage;

  /**
   * Engine addition, not in the binary (issue #285): what a player's engine can
   * do with other players. A feature that needs them to run our engine adds one
   * entry here and asks `CPeerFeatures`; see docs/PEER_FEATURES.md. Values travel
   * as bit positions, so they never change or get reused.
   */
  enum class EPeerFeature : std::uint8_t
  {
    /// `CommandStreamCheck`'s hash after the fields of `CLIMSG_Ack`.
    OrderStreamCheck = 0,
    /// wld_SkewCorrection: this client's display clock keeps to real time.
    SkewCorrection = 1,
    /// net_FastRetransmit: this client acknowledges within net_FastAckDelay.
    FastAck = 2,
    /// Announced in the lobby: this client can prove a style (LobbyPeerFeatures.h).
    SignedStyle = 3,
    /// A client that restarts can take its seat back (issue #275).
    Rejoin = 4,
  };

  /// The first payload byte of a peer features message; other values are feature traffic.
  inline constexpr std::uint8_t kPeerKindAnnounce = 0;

  /// What one announcement says, in the game and in the lobby alike.
  struct SPeerAnnouncement
  {
    std::uint64_t mask{0};
    std::string build;
  };

  [[nodiscard]] constexpr std::uint64_t PeerFeatureBit(const EPeerFeature feature) noexcept
  {
    return std::uint64_t{1} << static_cast<std::uint8_t>(feature);
  }

  /// Writes the announcement payload, with this build's name.
  void WritePeerAnnouncement(CMessageStream& stream, std::uint64_t mask);

  /// False when the payload is not an announcement.
  [[nodiscard]] bool ReadPeerAnnouncement(const char* payload, std::size_t size, SPeerAnnouncement& out);

  /// The first payload byte of `CLIMSG_PeerFeatures`. A kind a client doesn't know, it ignores.
  enum class EPeerMessageKind : std::uint8_t
  {
    Announce = 0,
    RejoinBacklog = 1,
    RejoinInfo = 2,
    /// Where a client taking its seat back has got: an `ERejoinStage`, then a float progress.
    RejoinProgress = 3,
    /// How many bytes of recording and save follow (`int32`), so the client can say how far it has got.
    RejoinRecordingSize = 4,
    /// A client's public key for its seat (`RejoinKey.h`), to each peer that announced `Rejoin`.
    RejoinKey = 5,
    /// To a client asking for its seat back: 32 random bytes for it to sign.
    RejoinChallenge = 6,
    /// The answer: the 64-byte signature. Nothing of the game goes out before a good one.
    RejoinProof = 7,
    /// To a client that can't have its seat, just before its link closes, so it can say why: an `ERejoinRefusal`.
    RejoinRefused = 8,
  };

  /// Why a client can't have its seat back. Sent as a byte, so values never change.
  enum class ERejoinRefusal : std::uint8_t
  {
    /// It could not prove the seat is its player's.
    Key = 0,
    /// The player here voted to eject it.
    Ejected = 1,
  };

  /// Where a client taking its seat back has got. Sent as a byte, so values never change.
  enum class ERejoinStage : std::uint8_t
  {
    None = 0,
    /// Quiet or its link lost, and it hasn't come back. Known to each peer itself, never sent.
    Lost = 1,
    /// Back on a new link, receiving the game so far.
    Transfer = 2,
    /// Loading the map. The engine's load has no measure of how far it has got.
    Loading = 3,
    /// Running the game so far.
    CatchingUp = 4,
    /// Playing again. The players are told for `kRejoinBackSeconds`.
    Back = 5,
  };

  inline constexpr std::chrono::seconds kRejoinBackSeconds{8};

  struct SRejoinStatus
  {
    ERejoinStage stage{ERejoinStage::None};
    /// 0 to 1, or negative when this stage has no measure yet.
    float progress{-1.0f};
  };

  /// The name `GetSessionClients` gives Lua for `stage`.
  [[nodiscard]] const char* RejoinStageName(ERejoinStage stage);

  /**
   * Engine addition, not in the binary (issue #285): this client's announcement
   * and what the other clients announced. Everything is under the manager's lock.
   * Nothing here reaches the command stream, so the sim and replays never see it.
   */
  class CPeerFeatures
  {
  public:
    explicit CPeerFeatures(std::size_t clientCount);

    /// With net_PeerFeatures on: tells every peer what this client supports.
    void Announce(CClientManagerImpl& manager);

    /// The same to one peer, as a restarted one has forgotten everything.
    void AnnounceTo(CClientManagerImpl& manager, CNetClient& peer) const;

    /// Takes a peer's `CLIMSG_PeerFeatures`.
    void Receive(CClientManagerImpl& manager, CNetClient& client, CMessage& message);

    /// False for a client that has not announced: a retail client never does.
    [[nodiscard]] bool PeerSupports(int clientIndex, EPeerFeature feature) const;

    /// How long `clientIndex` holds an acknowledgement, in ms: what it announced (`FastAck`), or as
    /// this client does when it announced nothing.
    [[nodiscard]] std::int32_t PeerAckDelayMs(int clientIndex) const;

    /// wld_PreciseSharedStart: when this client's ready message was handled here, on the steady
    /// clock in microseconds; the first time counts, and 0 means not yet.
    void NoteReady(int clientIndex, std::int64_t handledUs);
    [[nodiscard]] std::int64_t ReadyUs(int clientIndex) const;

    /// Whether this client and every client still in the game support `feature`.
    [[nodiscard]] bool EveryoneSupports(CClientManagerImpl& manager, EPeerFeature feature) const;

    /// This client's link to `clientIndex` was lost, and the seat is held.
    void NoteRejoinLost(int clientIndex);

    /// A client came back on a new link.
    void NoteRejoinStarted(int clientIndex);

    /// The player here voted to eject the client on that seat, on the link it had.
    void NoteRejoinEjected(int clientIndex, std::uint32_t address, std::uint16_t port);

    /// The seat whose player was voted out from that address, or -1.
    [[nodiscard]] int FindEjectedSeat(std::uint32_t address, std::uint16_t port) const;

    /// Whether this client knows the seat's public key, and so can test a rejoin at all.
    [[nodiscard]] bool HasRejoinKey(int clientIndex) const;

    /// A new random challenge for the client on that seat, which replaces any earlier one.
    [[nodiscard]] SRejoinNonce StartRejoinChallenge(int clientIndex);

    /// Tests an answer to the seat's challenge, which can be used once.
    [[nodiscard]] bool CheckRejoinProof(int clientIndex, int localIndex, const SRejoinSignature& signature);

    /// Whether the client now on that seat has proved it is the seat's player.
    [[nodiscard]] bool RejoinProven(int clientIndex) const;

    /**
     * Where `clientIndex` has got taking its seat back. A client that has said
     * nothing for `kRejoinSilenceSeconds` counts as lost again, which brings the
     * Connectivity dialog and its eject timers back.
     */
    [[nodiscard]] SRejoinStatus RejoinStatus(int clientIndex) const;

    /// How long since `clientIndex` last said where it has got taking its seat back.
    [[nodiscard]] float RejoinSilenceSeconds(int clientIndex) const;

    /// What this client announces, for this session's switches.
    [[nodiscard]] static std::uint64_t LocalMask(const CClientManagerImpl& manager);

  private:
    struct SPeer
    {
      bool announced{false};
      SPeerAnnouncement announcement;
      std::int64_t readyUs{0};
      SRejoinStatus rejoin;
      std::chrono::steady_clock::time_point rejoinNoted{};
      SRejoinPublicKey key{};
      bool keyKnown{false};
      bool keySent{false};
      SRejoinNonce nonce{};
      bool challenged{false};
      bool proven{false};
      bool ejected{false};
      std::uint32_t ejectedAddress{0};
      std::uint16_t ejectedPort{0};
    };

    void SendKeyTo(CClientManagerImpl& manager, CNetClient& peer);

    /// Once every player has announced rejoin: tells a launcher that asked (`/rejoinoffer`).
    void OfferRejoinToLauncher(CClientManagerImpl& manager);

    std::vector<SPeer> mPeers;
    bool mRejoinOffered{false};
  };
} // namespace moho
