#include "server/LobbyHost.h"

#include <utility>

#include "moho/net/ELobbyMsg.h"
#include "netlink/EngineLinks.h"

// Engine addition, dedicated server: see LobbyHost.h.

namespace faf::server
{
  namespace
  {
    using moho::ELobbyMsg;

    /** A CLobby message being written: type, two size bytes filled in at the end, payload. */
    class CWire
    {
    public:
      explicit CWire(const ELobbyMsg type)
      {
        mBytes = {static_cast<std::uint8_t>(type), 0u, 0u};
      }
      CWire& String(const std::string& text)
      {
        mBytes.insert(mBytes.end(), text.begin(), text.end());
        mBytes.push_back(0u);
        return *this;
      }
      CWire& Int32(const std::int32_t value)
      {
        const auto bits = static_cast<std::uint32_t>(value);
        for (int i = 0; i < 4; ++i) {
          mBytes.push_back(static_cast<std::uint8_t>(bits >> (8 * i)));
        }
        return *this;
      }
      CWire& UInt16(const std::uint16_t value)
      {
        mBytes.push_back(static_cast<std::uint8_t>(value));
        mBytes.push_back(static_cast<std::uint8_t>(value >> 8));
        return *this;
      }
      [[nodiscard]] std::vector<std::uint8_t> Done()
      {
        mBytes[1] = static_cast<std::uint8_t>(mBytes.size());
        mBytes[2] = static_cast<std::uint8_t>(mBytes.size() >> 8);
        return std::move(mBytes);
      }

    private:
      std::vector<std::uint8_t> mBytes;
    };

    /** Reads a message's payload; once it runs out it stays failed. */
    class CWireReader
    {
    public:
      explicit CWireReader(const std::span<const std::uint8_t> payload)
        : mPayload(payload)
      {}
      std::string String()
      {
        std::string text;
        while (mPos < mPayload.size() && mPayload[mPos] != 0u) {
          text.push_back(static_cast<char>(mPayload[mPos++]));
        }
        mOk = mOk && mPos < mPayload.size();
        ++mPos;
        return text;
      }
      std::int32_t Int32()
      {
        if (mPos + 4u > mPayload.size()) {
          mOk = false;
          return 0;
        }
        std::uint32_t bits = 0;
        for (std::size_t i = 0; i < 4u; ++i) {
          bits |= static_cast<std::uint32_t>(mPayload[mPos + i]) << (8u * i);
        }
        mPos += 4u;
        return static_cast<std::int32_t>(bits);
      }
      [[nodiscard]] bool Ok() const noexcept { return mOk; }

    private:
      std::span<const std::uint8_t> mPayload;
      std::size_t mPos = 0;
      bool mOk = true;
    };
  } // namespace

  CLobbyHost::CLobbyHost(std::string hostName, const std::int32_t hostedTime)
    : mHostName(std::move(hostName))
    , mHostedTime(hostedTime)
  {}

  void CLobbyHost::AddParticipant(const std::int32_t uid, std::string name)
  {
    mParticipants[uid].name = std::move(name);
  }

  std::vector<std::int32_t> CLobbyHost::Established() const
  {
    std::vector<std::int32_t> in;
    for (const auto& [uid, participant] : mParticipants) {
      if (participant.in) {
        in.push_back(uid);
      }
    }
    return in;
  }

  void CLobbyHost::SendEstablished(std::vector<SOutgoing>& out) const
  {
    // As `CLobby::PushTask` sends its own list when it changes: everyone in, to everyone in.
    const std::vector<std::int32_t> in = Established();
    const std::vector<std::uint8_t> message = EstablishedPeers(in);
    for (const std::int32_t uid : in) {
      out.push_back(SOutgoing{uid, message});
    }
  }

  void CLobbyHost::OnMessage(const std::int32_t from, const std::span<const std::uint8_t> message, std::vector<SOutgoing>& out)
  {
    // A whole CMessage: type, the size it says, payload.
    if (message.size() < 3u || (static_cast<std::size_t>(message[1]) | (static_cast<std::size_t>(message[2]) << 8u)) != message.size()) {
      ++mIgnored;
      return;
    }
    const auto found = mParticipants.find(from);
    if (found == mParticipants.end() || static_cast<ELobbyMsg>(message[0]) != ELobbyMsg::LOBMSG_Join) {
      // Peer announcements, established-peer lists and script data sent to the host: nothing for a host with no
      // lobby of its own to do (launch interception, plan WP2.14, reads script data later).
      ++mIgnored;
      return;
    }
    CWireReader reader(message.subspan(3));
    (void)reader.String(); // the name the client asks for: FAF's goes out instead
    const std::int32_t requested = reader.Int32();
    if (!reader.Ok()) {
      ++mIgnored;
      return;
    }
    // Plan WP2.5: the uid its token proved, and no other; a client with another one would adopt it in `OnWelcome`
    // and its lobby would name the wrong player.
    if (requested != from) {
      ++mRejected;
      out.push_back(SOutgoing{from, Rejected("WrongUid")});
      return;
    }
    SParticipant& participant = found->second;
    out.push_back(SOutgoing{from, Welcome(mHostName, 0, from, participant.name, mHostedTime)});
    const bool returning = std::exchange(participant.in, true);
    for (const auto& [uid, other] : mParticipants) {
      if (uid == from || !other.in) {
        continue;
      }
      // `CLobby::OnJoin` with `mHasNAT`: each learns of the other; the lower uid takes the higher's connection.
      out.push_back(SOutgoing{from, NewPeer(other.name, uid)});
      if (!returning) {
        out.push_back(SOutgoing{uid, NewPeer(participant.name, from)});
      }
    }
    SendEstablished(out);
  }

  void CLobbyHost::OnLeft(const std::int32_t uid, std::vector<SOutgoing>& out)
  {
    const auto found = mParticipants.find(uid);
    if (found == mParticipants.end() || !found->second.in) {
      return;
    }
    found->second.in = false;
    // `CLobby::PeerDisconnected` (0x007C77F0) as host: the peer's uid to everyone left.
    const std::vector<std::uint8_t> message = DeletePeer(uid);
    for (const std::int32_t other : Established()) {
      out.push_back(SOutgoing{other, message});
    }
    SendEstablished(out);
  }

  std::vector<std::uint8_t> CLobbyHost::Join(const std::string& name, const std::int32_t uid)
  {
    return CWire(ELobbyMsg::LOBMSG_Join).String(name).Int32(uid).Done();
  }

  std::vector<std::uint8_t> CLobbyHost::Welcome(
    const std::string& hostName, const std::int32_t hostUid, const std::int32_t uid, const std::string& name, const std::int32_t hostedTime
  )
  {
    return CWire(ELobbyMsg::LOBMSG_Welcome).String(hostName).Int32(hostUid).Int32(uid).String(name).Int32(hostedTime).Done();
  }

  std::vector<std::uint8_t> CLobbyHost::Rejected(const std::string& reason)
  {
    return CWire(ELobbyMsg::LOBMSG_Rejected).String(reason).Done();
  }

  std::vector<std::uint8_t> CLobbyHost::NewPeer(const std::string& name, const std::int32_t uid)
  {
    const netlink::EngineAddress address = netlink::EngineAddressFor(uid);
    return CWire(ELobbyMsg::LOBMSG_NewPeer)
      .String(name)
      .Int32(static_cast<std::int32_t>(address.addrHost))
      .UInt16(address.portHost)
      .Int32(uid)
      .Done();
  }

  std::vector<std::uint8_t> CLobbyHost::DeletePeer(const std::int32_t uid)
  {
    return CWire(ELobbyMsg::LOBMSG_DeletePeer).Int32(uid).Done();
  }

  std::vector<std::uint8_t> CLobbyHost::EstablishedPeers(const std::vector<std::int32_t>& uids)
  {
    CWire wire(ELobbyMsg::LOBMSG_EstablishedPeers);
    for (const std::int32_t uid : uids) {
      wire.Int32(uid);
    }
    return wire.Int32(-1).Done();
  }
} // namespace faf::server
