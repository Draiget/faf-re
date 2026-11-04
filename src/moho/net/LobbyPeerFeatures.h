#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "PeerFeatures.h"
#include "remote/net/StyleProof.h"

struct lua_State;

namespace moho
{
  class CLobby;
  class SPeer;
  struct CMessage;

  /**
   * Engine addition, not in the binary: the peer announcement of PeerFeatures.h
   * while players are still in the lobby, where no game link exists yet. It says
   * which players run our engine, and carries each player's signed style
   * (docs/PEER_FEATURES.md). All of it is lobby traffic: the sim and replays never
   * see it. A retail client ignores `LOBMSG_PeerFeatures` and answers nothing.
   */
  class CLobbyPeerFeatures
  {
  public:
    explicit CLobbyPeerFeatures(const CLobby& lobby);
    ~CLobbyPeerFeatures();

    /// Makes the lobby script's slots show proven styles. Nothing when it isn't loaded.
    void InstallSlotStyles(lua_State* state);

    /// Shows `uid`'s style on their slot, when they have one and a slot is drawn.
    void PaintPeer(lua_State* state, std::int32_t uid) const;

    /// A link to `peer` was just established: forget its old state and announce.
    void PeerEstablished(const SPeer& peer);

    /**
     * Takes a peer's `LOBMSG_PeerFeatures`.
     * @return Whether that peer's style has just been proven.
     */
    [[nodiscard]] bool Receive(const SPeer& peer, std::int32_t localUid, CMessage& message);

    /// False for a player who has not announced: a retail client never does.
    [[nodiscard]] bool PeerRunsOurEngine(std::int32_t uid) const;

    /// "rrggbb" for a proven style, empty for none. The local player's comes from their key.
    [[nodiscard]] std::string StyleOf(std::int32_t uid) const;

  private:
    struct SLobbyPeer
    {
      SPeerAnnouncement announcement;
      bool announced{false};
      bool challengeAnswered{false};
      bool awaitingProof{false};
      faf::remote::net::StyleChallenge challenge{};
      bool hasStyle{false};
      faf::remote::net::StyleColor style{};
    };

    void LoadKey();

    const CLobby& mLobby;
    std::map<std::int32_t, SLobbyPeer> mPeers;
    std::unique_ptr<faf::remote::net::StyleSigningKey> mKey;
    faf::remote::net::StyleColor mLocalStyle{};
  };
} // namespace moho
