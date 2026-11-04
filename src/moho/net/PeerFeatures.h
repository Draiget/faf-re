#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace moho
{
  class CClientManagerImpl;
  class CMessageStream;
  class CMessageStream;
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
    void Announce(CClientManagerImpl& manager) const;

    /// Takes a peer's `CLIMSG_PeerFeatures`.
    void Receive(CClientManagerImpl& manager, const CNetClient& client, CMessage& message);

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

    /// What this client announces, for this session's switches.
    [[nodiscard]] static std::uint64_t LocalMask(const CClientManagerImpl& manager);

  private:
    struct SPeer
    {
      bool announced{false};
      SPeerAnnouncement announcement;
      std::int64_t readyUs{0};
    };
    std::vector<SPeer> mPeers;
  };
} // namespace moho
