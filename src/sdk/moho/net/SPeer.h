#pragma once

#include <cstdint>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/Set.h"
#include "lua/LuaObject.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class INetConnection;

  constexpr auto kPlayerUidBufSize = 16;

  // Binary symbols in current FA read-clones resolve this layout as `Moho::SNetPeer`.
  class SPeer : public TDatListItem<SPeer, void>
  {
  public:
    msvc8::string playerName;
    int32_t uid{0};
    u_long address{0};
    u_short port{0};
    ENetworkPlayerState state{ENetworkPlayerState::kUnknown};
    float v2{0.0f}; // Constructor-initialized at +0x34; semantics unresolved in current evidence.
    INetConnection* peerConnection{nullptr};
    msvc8::set<int32_t> establishedUids;
    uint32_t mCmdSource{0xFFu};
    int32_t mClientInd{-1};

    /**
     * Address: 0x007C05C0 (FUN_007C05C0)
     *
     * What it does:
     * Initializes a peer record and sets default command-source/client index sentinels.
     */
    SPeer(
      const msvc8::string& playerName,
      int32_t uid,
      u_long address,
      u_short port,
      INetConnection* connection,
      ENetworkPlayerState state
    );

    /**
     * Address: 0x007C1340 (FUN_007C1340)
     *
     * What it does:
     * Destroys peer-owned containers/strings and restores detached list-link state.
     */
    ~SPeer();

    /**
     * Address: 0x007C0690 (FUN_007C0690)
     *
     * What it does:
     * Formats a human-readable peer endpoint string.
     */
    [[nodiscard]]
    msvc8::string ToString() const;

    /**
     * Address: 0x007C2950 (FUN_007C2950)
     *
     * Note:
     * For `thiscall` MSVC require this to be in ECX register, so this is not SPeer member function.
     *
     * What it does:
     * Builds a Lua table for peer replication/debug views.
     */
    static LuaPlus::LuaObject ToLua(LuaPlus::LuaState* state, const SPeer* peer);

    /**
     * Address: 0x007C8070 (FUN_007C8070)
     *
     * What it does:
     * Sends `LOBMSG_NewPeer` payload for this peer over the provided connection.
     */
    void SendInfoTo(INetConnection* connection) const;
  };

  static_assert(sizeof(SPeer) == 0x50, "SPeer size must be 0x50");

  /**
   * Address: 0x007C1320 (FUN_007C1320)
   *
   * What it does:
   * Executes one scalar-delete lane for `SPeer` by running destructor logic
   * and freeing the same object storage.
   */
  SPeer* DestroyAndDeletePeer(SPeer* peer);
} // namespace moho
