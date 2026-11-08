#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <vector>

#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"
#include "remote/net/LobbySignals.h"

// Engine addition, server mode (plan WP2.12, WP2.13; design research/WP2.13-lobby-relay-design.md): the connector a
// client's unchanged `CLobby` uses in a server game. Every connection it hands out is virtual: one per participant,
// all carried by the client's one channel to the server as `ESeatMessage::Lobby` frames, the server relaying them
// between participants with the sender written by itself (server/LobbyRelay.h). A participant's connection is at the
// engine address `netlink::EngineAddressFor` gives its uid, which this connector maps back; the server names the
// participants in its lobby signals (remote/net/LobbySignals.h), as FAF's lobby server does over GPGNet, and the
// client's `CLobby` connects or accepts as it would through the ICE adapter. A frame from a participant this side has
// no connection to yet waits as an incoming connection: `FindNextAddress` offers its engine address, `Accept` makes it.
// Connection events are this side's own, as the UDP connection makes them: `ConnMade` first on every connection,
// `ConnLostEof` on one whose participant the server says left, and on all once the channel is gone.

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
    /** Participants whose connection ends now (the server said they left), appended to `uids`. */
    virtual void TakeGone(std::vector<std::int32_t>& uids) = 0;
    /** The connector on this channel is gone (its lobby was destroyed): a lobby started again may have a new one. */
    virtual void ConnectorGone() {}
  };

  /**
   * The `Lobby` frames from the server, in the order they came. A frame from uid 0 is a signal from the server itself;
   * it holds back every frame after it until it is taken, so a participant's first message never reaches this side's
   * lobby before the signal that tells the lobby about that participant.
   */
  class CLobbyInbox
  {
  public:
    /** A whole `Lobby` frame: kind, varint uid it is from, message. */
    void Push(std::vector<std::uint8_t> frame);
    /** The next frame from a participant, unless a signal comes first. */
    [[nodiscard]] bool TakeLobbyFrame(std::vector<std::uint8_t>& frame);
    /** The next signal, if it comes first; a malformed one is dropped. */
    [[nodiscard]] bool TakeSignal(net::SLobbySignal& signal);
    [[nodiscard]] std::uint64_t DroppedSignals() const noexcept { return mDropped; }

  private:
    [[nodiscard]] static bool IsSignal(const std::vector<std::uint8_t>& frame) noexcept;

    std::deque<std::vector<std::uint8_t>> mFrames;
    std::uint64_t mDropped = 0;
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

    /** The uid a connection to this address reaches: the engine address's, or 0 (nobody: the server signals) for any other. */
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
    std::vector<std::int32_t> mGone;
    std::vector<std::uint8_t> mFrame;
    std::uint64_t mDropped = 0;
    bool mLost = false;
  };
} // namespace faf::remote
