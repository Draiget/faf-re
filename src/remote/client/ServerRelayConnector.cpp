#include "remote/client/ServerRelayConnector.h"

#include <algorithm>
#include <string>

#include "moho/net/CMessage.h"
#include "moho/net/ELobbyMsg.h"
#include "netlink/EngineLinks.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition, server mode: see ServerRelayConnector.h.

namespace faf::remote
{
  namespace
  {
    /** A frame's message is a whole CMessage: type, the 16-bit size it says, payload. */
    [[nodiscard]] bool WholeMessage(const std::vector<std::uint8_t>& bytes) noexcept
    {
      return bytes.size() >= 3u && (static_cast<std::size_t>(bytes[1]) | (static_cast<std::size_t>(bytes[2]) << 8u)) == bytes.size();
    }
  } // namespace

  /** One participant's virtual connection; its messages are the channel's frames to and from that uid. */
  class CServerRelayConnector::CRelayConnection final : public moho::INetConnection
  {
  public:
    CRelayConnection(CServerRelayConnector& connector, const std::int32_t uid, const u_long address, const u_short port)
      : mConnector(connector)
      , mUid(uid)
      , mAddress(address)
      , mPort(port)
    {}

    u_long GetAddr() override { return mAddress; }
    u_short GetPort() override { return mPort; }
    float GetPing() override { return 0.0f; }
    float GetTime() override { return 0.0f; }

    void Write(moho::NetDataSpan* const data) override
    {
      if (!mClosed && data != nullptr && data->size() != 0u) {
        mConnector.Send(mUid, data->data(), data->size());
      }
    }

    void Close() override { mClosed = true; }

    fa::string ToString() override
    {
      const std::string text = mUid == 0 ? std::string("server") : "relay:" + std::to_string(mUid);
      return fa::string(text.c_str());
    }

    void ScheduleDestroy() override
    {
      mClosed = true;
      mDestroy = true;
    }

    /** What arrived for this side since the last pull, in order: ConnMade first, ConnLostEof last. */
    void Deliver()
    {
      if (mDestroy) {
        return;
      }
      if (!mMadeSent) {
        mMadeSent = true;
        moho::CMessage made(moho::ELobbyMsg::LOBMSG_ConnMade);
        (void)Dispatch(&made);
      }
      while (!mInbox.empty() && !mDestroy) {
        const std::vector<std::uint8_t> bytes = std::move(mInbox.front());
        mInbox.pop_front();
        // Types 200-209 are this side's own events; a peer can't make them up (CNetUDPConnection does the same).
        if (!WholeMessage(bytes)
            || (bytes[0] >= static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_ConnFailed) && bytes[0] < static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_ConnMsgEnd))) {
          ++mConnector.mDropped;
          continue;
        }
        moho::CMessage message(static_cast<moho::ELobbyMsg>(bytes[0]));
        if (bytes.size() > 3u) {
          (void)message.Append(reinterpret_cast<const char*>(bytes.data() + 3), bytes.size() - 3u);
        }
        (void)Dispatch(&message);
      }
      if ((mConnector.mLost || mGone) && !mLostSent && !mDestroy) {
        mLostSent = true;
        moho::CMessage lost(moho::ELobbyMsg::LOBMSG_ConnLostEof);
        (void)Dispatch(&lost);
      }
    }

    void Queue(std::vector<std::uint8_t> message) { mInbox.push_back(std::move(message)); }
    /** Its participant left: what it sent still arrives, then `ConnLostEof`. */
    void Gone() noexcept { mGone = true; }
    [[nodiscard]] bool Destroyed() const noexcept { return mDestroy; }

  private:
    CServerRelayConnector& mConnector;
    std::int32_t mUid;
    u_long mAddress;
    u_short mPort;
    std::deque<std::vector<std::uint8_t>> mInbox;
    bool mClosed = false;
    bool mDestroy = false;
    bool mMadeSent = false;
    bool mLostSent = false;
    bool mGone = false;
  };

  CServerRelayConnector::CServerRelayConnector(IRelayChannel& channel)
    : mChannel(channel)
  {}

  CServerRelayConnector::~CServerRelayConnector()
  {
    mChannel.ConnectorGone();
  }

  void CServerRelayConnector::Destroy()
  {
    delete this;
  }

  moho::ENetProtocolType CServerRelayConnector::GetProtocol()
  {
    // A multiplayer lobby (`CLobby::LaunchGame` tells multiplayer by a protocol). The LAN discovery `HostGame` opens
    // with one needs a lobby with no NAT-traversal provider; a server session's lobby counts as having one.
    return moho::ENetProtocolType::kUdp;
  }

  u_short CServerRelayConnector::GetLocalPort()
  {
    return 0;
  }

  std::int32_t CServerRelayConnector::UidForAddress(const u_long address, const u_short port) noexcept
  {
    const auto host = static_cast<std::uint32_t>(address);
    if ((host & 0xF0000000u) != 0xF0000000u || port < 1000u || port > 1000u + 0x7Fu) {
      return 0; // a real address: the server's
    }
    return static_cast<std::int32_t>((host & 0x00FFFFFFu) | (static_cast<std::uint32_t>(port - 1000u) << 24u));
  }

  moho::INetConnection* CServerRelayConnector::Connect(const u_long address, const u_short port)
  {
    const std::int32_t uid = UidForAddress(address, port);
    auto& slot = mConnections[uid];
    if (slot == nullptr || slot->Destroyed()) {
      slot = std::make_unique<CRelayConnection>(*this, uid, address, port);
    }
    // Whatever that participant sent before this side connected is its connection's.
    if (const auto pending = mPending.find(uid); pending != mPending.end()) {
      for (std::vector<std::uint8_t>& message : pending->second) {
        slot->Queue(std::move(message));
      }
      mPending.erase(pending);
    }
    return slot.get();
  }

  bool CServerRelayConnector::FindNextAddress(u_long& outAddress, u_short& outPort)
  {
    for (const auto& [uid, messages] : mPending) {
      if (uid == 0 || messages.empty()) {
        continue;
      }
      const netlink::EngineAddress address = netlink::EngineAddressFor(uid);
      outAddress = static_cast<u_long>(address.addrHost);
      outPort = address.portHost;
      return true;
    }
    return false;
  }

  moho::INetConnection* CServerRelayConnector::Accept(const u_long address, const u_short port)
  {
    return Connect(address, port);
  }

  void CServerRelayConnector::Reject(const u_long address, const u_short port)
  {
    const std::int32_t uid = UidForAddress(address, port);
    if (const auto pending = mPending.find(uid); pending != mPending.end()) {
      mDropped += pending->second.size();
      mPending.erase(pending);
    }
    if (std::find(mRejected.begin(), mRejected.end(), uid) == mRejected.end()) {
      mRejected.push_back(uid);
    }
  }

  void CServerRelayConnector::Pull()
  {
    while (mChannel.TakeLobbyFrame(mFrame)) {
      if (mFrame.size() < 2u || mFrame[0] != static_cast<std::uint8_t>(net::ESeatMessage::Lobby)) {
        ++mDropped;
        continue;
      }
      net::ByteReader reader(mFrame.data() + 1, mFrame.size() - 1u);
      const std::uint64_t from = reader.Varint();
      const std::size_t at = 1u + net::VarintSize(from);
      if (!reader.Ok() || from > 0x7FFFFFFFu || at >= mFrame.size()) {
        ++mDropped;
        continue;
      }
      const auto uid = static_cast<std::int32_t>(from);
      std::vector<std::uint8_t> message(mFrame.begin() + static_cast<std::ptrdiff_t>(at), mFrame.end());
      if (const auto found = mConnections.find(uid); found != mConnections.end() && !found->second->Destroyed()) {
        found->second->Queue(std::move(message));
      } else if (std::find(mRejected.begin(), mRejected.end(), uid) != mRejected.end()) {
        ++mDropped;
      } else {
        mPending[uid].push_back(std::move(message));
      }
    }
    mLost = mLost || !mChannel.Up();
    mGone.clear();
    mChannel.TakeGone(mGone);
    for (const std::int32_t uid : mGone) {
      if (const auto found = mConnections.find(uid); found != mConnections.end()) {
        found->second->Gone();
      }
      if (const auto pending = mPending.find(uid); pending != mPending.end()) {
        mDropped += pending->second.size();
        mPending.erase(pending);
      }
    }

    // A connection may close itself while it delivers (`CLobby` drops a rejected peer's): it goes after the pass.
    for (auto& [uid, connection] : mConnections) {
      connection->Deliver();
    }
    std::erase_if(mConnections, [](const auto& entry) { return entry.second->Destroyed(); });
  }

  void CServerRelayConnector::Push() {}

  bool CLobbyInbox::IsSignal(const std::vector<std::uint8_t>& frame) noexcept
  {
    return frame.size() >= 2u && frame[1] == 0u; // varint uid 0: one byte
  }

  void CLobbyInbox::Push(std::vector<std::uint8_t> frame)
  {
    mFrames.push_back(std::move(frame));
  }

  bool CLobbyInbox::TakeLobbyFrame(std::vector<std::uint8_t>& frame)
  {
    if (mFrames.empty() || IsSignal(mFrames.front())) {
      return false;
    }
    frame = std::move(mFrames.front());
    mFrames.pop_front();
    return true;
  }

  bool CLobbyInbox::TakeSignal(net::SLobbySignal& signal)
  {
    while (!mFrames.empty() && IsSignal(mFrames.front())) {
      const std::vector<std::uint8_t> frame = std::move(mFrames.front());
      mFrames.pop_front();
      if (net::DecodeLobbySignal(std::span<const std::uint8_t>(frame).subspan(2), signal)) {
        return true;
      }
      ++mDropped;
    }
    return false;
  }

  void CServerRelayConnector::SelectEvent(HANDLE ev)
  {
    (void)ev; // `CLobby` pulls every frame; the channel wakes nothing
  }

  moho::SSendStampWindow CServerRelayConnector::SnapshotSendStamps(const std::int32_t since)
  {
    (void)since;
    return {0u, 0u}; // as CNetNullConnector: no send stamps
  }

  void CServerRelayConnector::Send(const std::int32_t uid, const std::uint8_t* const data, const std::size_t size)
  {
    std::vector<std::uint8_t> frame;
    net::ByteWriter writer(frame);
    writer.Byte(static_cast<std::uint8_t>(net::ESeatMessage::Lobby));
    writer.Varint(static_cast<std::uint64_t>(uid));
    writer.Bytes(data, size);
    mChannel.SendLobbyFrame(frame);
  }
} // namespace faf::remote
