#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace moho
{
  class CClientManagerImpl;
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
  };

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

    /// Whether this client and every client still in the game support `feature`.
    [[nodiscard]] bool EveryoneSupports(CClientManagerImpl& manager, EPeerFeature feature) const;

    /// What this client announces, for this session's switches.
    [[nodiscard]] static std::uint64_t LocalMask(const CClientManagerImpl& manager);

  private:
    struct SPeer
    {
      bool announced{false};
      std::uint64_t mask{0};
      std::string build;
    };
    std::vector<SPeer> mPeers;
  };
} // namespace moho
