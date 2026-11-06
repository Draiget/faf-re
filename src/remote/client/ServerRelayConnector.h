#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <vector>

#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"

// Engine addition, server mode (plan WP2.13, WP12.1; design research/WP2.13-lobby-relay-design.md): the connector a
// client's unchanged `CLobby` uses in a server game. Every connection it hands out is virtual: one per participant,
// all carried by the client's one channel to the server as `ESeatMessage::Lobby` frames, the server relaying them
// between participants with the sender written by itself (server/LobbyRelay.h). The connection to the server, the
// lobby's network host, is uid 0; a peer's is the uid the host named in `NewPeer`, at the engine address
// `netlink::EngineAddressFor` gives that uid, which this connector maps back. A frame from a participant this side
// has no connection to yet is an incoming connection: `FindNextAddress` offers its engine address and `Accept` makes
// it, as the UDP connector does for a datagram from a new address. Connection events are this side's own, as the
// UDP connection makes them: `ConnMade` first on every connection, `ConnLostEof` on all once the channel is gone.

namespace faf::remote
{
  /** The client's channel to the server, as the relay connector sees it. Not owned. */
  class IRelayChannel
  {
  public:
    virtual ~IRelayChannel() = default;
    /** Sends one whole `Lobby` frame (kind, varint uid it is for, message), reliably and in order. */
    virtual void SendLobbyFrame(std::span<const std::uint8_t> frame) = 0;
    /** The next `Lobby` frame from the server (kind, varint uid it is from, message), if any. */
    [[nodiscard]] virtual bool TakeLobbyFrame(std::vector<std::uint8_t>& frame) = 0;
    /** False once the channel is gone for good. */
    [[nodiscard]] virtual bool Up() const = 0;
  };

  class CServerRelayConnector final : public moho::INetConnector
  {
  public:
    explicit CServerRelayConnector(IRelayChannel& channel);
    ~CServerRelayConnector() override;

    void Destroy() override;
    moho::ENetProtocolType GetProtocol() override;
    u_short GetLocalPort() override;
    moho::INetConnection* Connect(u_long address, u_short port) override;
    bool FindNextAddress(u_long& outAddress, u_short& outPort) override;
    moho::INetConnection* Accept(u_long address, u_short port) override;
    void Reject(u_long address, u_short port) override;
    void Pull() override;
    void Push() override;
    void SelectEvent(HANDLE ev) override;
    moho::SSendStampWindow SnapshotSendStamps(std::int32_t since) override;

    /** The uid a connection to this address reaches: the engine address's, or 0 (the server) for any other. */
    [[nodiscard]] static std::int32_t UidForAddress(u_long address, u_short port) noexcept;

    /** Frames that came with no use: malformed, or from a uid this side has rejected. */
    [[nodiscard]] std::uint64_t DroppedFrames() const noexcept { return mDropped; }

  private:
    class CRelayConnection;
    friend class CRelayConnection;

    void Send(std::int32_t uid, const std::uint8_t* data, std::size_t size);

    IRelayChannel& mChannel;
    std::map<std::int32_t, std::unique_ptr<CRelayConnection>> mConnections;
    // Frames from participants this side hasn't accepted yet, kept in order until `Accept` or `Reject`.
    std::map<std::int32_t, std::deque<std::vector<std::uint8_t>>> mPending;
    std::vector<std::int32_t> mRejected;
    std::vector<std::uint8_t> mFrame;
    std::uint64_t mDropped = 0;
    bool mLost = false;
  };
} // namespace faf::remote
