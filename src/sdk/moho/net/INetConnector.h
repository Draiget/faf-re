#pragma once

#include "Common.h"
#include "platform/Platform.h"

namespace moho
{
  class INetConnection;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E03CB0
   * COL:  0x00E6081C
   */
  class INetConnector
  {
  public:
    /**
     * Address: 0x0047EAE0 (FUN_0047EAE0)
     * Address: 0x10079090 (sub_10079090)
     * Slot: 0
     *
     * What it does:
     * Deleting-destructor thunk for the interface base.
     */
    virtual ~INetConnector();

    /**
     * Address: 0x00A82547
     * Slot: 1
     * Demangled: _purecall
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 2
     * Demangled: _purecall
     */
    virtual ENetProtocolType GetProtocol() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 3
     * Demangled: _purecall
     */
    virtual u_short GetLocalPort() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 4
     * Demangled: _purecall
     */
    virtual INetConnection* Connect(u_long address, u_short port) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 5
     * Demangled: _purecall
     */
    virtual bool FindNextAddress(u_long& outAddress, u_short& outPort) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 6
     * Demangled: _purecall
     */
    virtual INetConnection* Accept(u_long address, u_short port) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 7
     * Demangled: _purecall
     */
    virtual void Reject(u_long address, u_short port) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 8
     * Demangled: _purecall
     */
    virtual void Pull() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 9
     * Demangled: _purecall
     */
    virtual void Push() = 0;

    /**
     * Address: 0x00A82547
     * Slot: 10
     * Demangled: _purecall
     */
    virtual void SelectEvent(HANDLE ev) = 0;

    /**
     * Address: 0x0047EAD0 (FUN_0047EAD0)
     * Address: 0x10079080 (sub_10079080)
     * Slot: 11
     *
     * What it does:
     * Default no-op debug hook for connectors that do not override it.
     */
    virtual void Debug();

    /**
     * Address: 0x00A82547
     * Slot: 12
     * Demangled: _purecall
     */
    virtual SSendStampView SnapshotSendStamps(int32_t since) = 0;
  };

  static_assert(sizeof(INetConnector) == 0x4, "INetConnector size must be 0x4");
} // namespace moho
