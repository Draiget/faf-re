#include "SPeer.h"

#include <charconv>

#include "CMessageStream.h"
#include "ELobbyMsg.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "lua/LuaObject.h"

namespace moho
{
  /**
   * Address: 0x007C05C0 (FUN_007C05C0)
   *
   * msvc8::string const &,int,unsigned long,unsigned short,INetConnection *,ENetworkPlayerState
   *
   * What it does:
   * Initializes peer identity/address fields and sentinel ids used by command/client mapping paths.
   */
  SPeer::SPeer(
    const msvc8::string& playerName_,
    const int32_t uid_,
    const u_long address_,
    const u_short port_,
    INetConnection* connection_,
    const ENetworkPlayerState state_
  )
    : playerName(playerName_)
    , uid(uid_)
    , address(address_)
    , port(port_)
    , state(state_)
    , v2(0.0f)
    , peerConnection(connection_)
    , establishedUids()
    , mCmdSource(0xFFu)
    , mClientInd(-1)
  {}

  /**
   * Address: 0x007C1340 (FUN_007C1340)
   *
   * What it does:
   * Unlinks the peer node before member destruction, matching binary list-detach behavior.
   */
  SPeer::~SPeer()
  {
    ListUnlink();
  }

  /**
   * Address: 0x007C0690 (FUN_007C0690)
   *
   * What it does:
   * Formats this peer into `"name" [host:port, uid=n]`.
   */
  msvc8::string SPeer::ToString() const
  {
    const auto hostname = NET_GetHostName(address);
    return gpg::STR_Printf("\"%s\" [%s:%d, uid=%d]", playerName.c_str(), hostname.c_str(), port, uid);
  }

  /**
   * Address: 0x007C2950 (FUN_007C2950)
   *
   * LuaPlus::LuaState *,SPeer const *
   *
   * What it does:
   * Builds the Lua peer descriptor including command-link/ping metadata.
   */
  LuaPlus::LuaObject SPeer::ToLua(
    LuaPlus::LuaState* state,
    const SPeer* peer
  )
  {
    LuaPlus::LuaObject out;
    out.AssignNewTable(state, 0, 0);
    out.SetString("name", peer->playerName.c_str());

    char idBuf[kPlayerUidBufSize]{};
    std::to_chars(idBuf, idBuf + kPlayerUidBufSize, peer->uid);
    out.SetString("id", idBuf);

    msvc8::string peerStatus;
    ENetworkPlayerStateToStr(peer->state, peerStatus);
    out.SetString("status", peerStatus.c_str());

    out.SetNumber("ping", peer->peerConnection->GetPing());
    out.SetNumber("quiet", peer->peerConnection->GetTime());

    LuaPlus::LuaObject establishedPeersTable;
    establishedPeersTable.AssignNewTable(state, 0, 0);
    int index = 1;
    for (const int32_t establishedUid : peer->establishedUids) {
      std::to_chars(idBuf, idBuf + kPlayerUidBufSize, establishedUid);
      establishedPeersTable.SetString(index++, idBuf);
    }

    out.SetObject("establishedPeers", &establishedPeersTable);
    return out;
  }

  /**
   * Address: 0x007C8070 (FUN_007C8070)
   *
   * INetConnection *
   *
   * What it does:
   * Serializes this peer as `LOBMSG_NewPeer` and writes it to `connection`.
   */
  void SPeer::SendInfoTo(
    INetConnection* connection
  ) const
  {
    const auto connectionStr = connection->ToString();
    const auto peerStr = ToString();
    gpg::Logf("LOBBY: sending info on peer %s to %s", peerStr.c_str(), connectionStr.c_str());

    CMessage msg(ELobbyMsg::LOBMSG_NewPeer);
    CMessageStream stream(msg, CMessageStream::Access::kReadWrite);
    stream.Write(playerName);
    stream.Write(address);
    stream.Write(port);
    stream.Write(uid);
    connection->Write(stream);
  }

  /**
   * Address: 0x007C1320 (FUN_007C1320)
   *
   * What it does:
   * Runs `SPeer` destruction for one heap object and releases the same
   * storage via global `operator delete`.
   */
  SPeer* DestroyAndDeletePeer(
    SPeer* const peer
  )
  {
    peer->~SPeer();
    ::operator delete(peer);
    return peer;
  }
} // namespace moho
