#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

// Engine addition, dedicated server (plan WP2.2, WP2.5; design research/WP2.13-lobby-relay-design.md): the server as
// the lobby's network host. Each participant's unchanged `CLobby` joins it over the virtual connection to uid 0
// (`ESeatMessage::Lobby`); it answers as `CLobby::OnJoin` (0x007C64C0) would in a direct lobby: `Welcome` with the
// match seed as `hostedTime`, so every client launches with the same seed, or `Rejected`; then `NewPeer` both ways
// with everyone already in, naming each peer by its engine address (netlink/EngineLinks.h), which the client's relay
// connector turns back into the virtual connection to that uid. It keeps no lobby state beyond who is in: the
// lobby's logic stays in the participants' own FAF lobby. No sockets: what it returns goes out as `Lobby` frames.
//
// Messages are `CMessage`s on the wire: type, 16-bit whole size, payload; strings NUL-terminated, integers 4 bytes
// little-endian, a port 2 bytes (moho/net/ELobbyMsg.h). The Windows client reads `NewPeer`'s address as a 4-byte
// `u_long`, so it is written as exactly that here, whatever `u_long` is on the server.

namespace faf::server
{
  class CLobbyHost
  {
  public:
    /** A CLobby message for one participant. */
    struct SOutgoing
    {
      std::int32_t to = 0;
      std::vector<std::uint8_t> message;
    };

    CLobbyHost(std::string hostName, std::int32_t hostedTime);

    /** A participant of the match, by the uid its token proves and the name FAF knows it by. */
    void AddParticipant(std::int32_t uid, std::string name);

    /** A lobby message from `from` for the host; what it answers goes to `out`. */
    void OnMessage(std::int32_t from, std::span<const std::uint8_t> message, std::vector<SOutgoing>& out);
    /** `uid` has left the lobby (out of the game, or its connection gone for good). */
    void OnLeft(std::int32_t uid, std::vector<SOutgoing>& out);

    /** Participants in, in uid order. */
    [[nodiscard]] std::vector<std::int32_t> Established() const;
    [[nodiscard]] std::uint64_t Ignored() const noexcept { return mIgnored; }
    [[nodiscard]] std::uint64_t Rejected() const noexcept { return mRejected; }

    // The wire form, for tests and the probe.
    [[nodiscard]] static std::vector<std::uint8_t> Join(const std::string& name, std::int32_t uid);
    [[nodiscard]] static std::vector<std::uint8_t> Welcome(
      const std::string& hostName, std::int32_t hostUid, std::int32_t uid, const std::string& name, std::int32_t hostedTime
    );
    [[nodiscard]] static std::vector<std::uint8_t> Rejected(const std::string& reason);
    [[nodiscard]] static std::vector<std::uint8_t> NewPeer(const std::string& name, std::int32_t uid);
    [[nodiscard]] static std::vector<std::uint8_t> DeletePeer(std::int32_t uid);
    [[nodiscard]] static std::vector<std::uint8_t> EstablishedPeers(const std::vector<std::int32_t>& uids);

  private:
    struct SParticipant
    {
      std::string name;
      bool in = false;
    };

    void SendEstablished(std::vector<SOutgoing>& out) const;

    std::string mHostName;
    std::int32_t mHostedTime = 0;
    std::map<std::int32_t, SParticipant> mParticipants;
    std::uint64_t mIgnored = 0;
    std::uint64_t mRejected = 0;
  };
} // namespace faf::server
