#pragma once

#include <cstdint>

#include "INetConnector.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E03CE8
   * COL:     0x00E607D0
   *
   * What it does:
   * Null-object connector implementation used when lobby protocol is `kNone`.
   */
  class CNetNullConnector final : public INetConnector
  {
  public:
    /**
     * Address: 0x0047EC40 (FUN_0047EC40)
     *
     * What it does:
     * Constructor lane that installs the CNetNullConnector vtable.
     */
    CNetNullConnector();

    /**
     * Address: 0x0047EC50 (FUN_0047EC50, ??1CNetNullConnector@Moho@@QAE@XZ)
     *
     * What it does:
     * Runs deleting-destructor behavior and restores base connector vtable.
     */
    ~CNetNullConnector() override;

    /**
     * Address: 0x0047EB20 (FUN_0047EB20)
     *
     * What it does:
     * Deletes this connector instance.
     */
    void Destroy() override;

    /**
     * Address: 0x0047EB30 (FUN_0047EB30)
     *
     * What it does:
     * Returns `ENetProtocolType::kNone`.
     */
    ENetProtocolType GetProtocol() override;

    /**
     * Address: 0x0047EB40 (FUN_0047EB40)
     *
     * What it does:
     * Returns local port `0`.
     */
    u_short GetLocalPort() override;

    /**
     * Address: 0x0047EB50 (FUN_0047EB50)
     *
     * What it does:
     * No-op connect path; always returns null.
     */
    INetConnection* Connect(u_long address, u_short port) override;

    /**
     * Address: 0x0047EB60 (FUN_0047EB60, emit `Func2`)
     *
     * What it does:
     * Null connector has no pending peers; always returns false.
     */
    bool FindNextAddress(u_long& outAddress, u_short& outPort) override;

    /**
     * Address: 0x0047EB70 (FUN_0047EB70)
     *
     * What it does:
     * No-op accept path; always returns null.
     */
    INetConnection* Accept(u_long address, u_short port) override;

    /**
     * Address: 0x0047EB80 (FUN_0047EB80)
     *
     * What it does:
     * No-op reject path.
     */
    void Reject(u_long address, u_short port) override;

    /**
     * Address: 0x0047EB90 (FUN_0047EB90)
     */
    void Pull() override;

    /**
     * Address: 0x0047EBA0 (FUN_0047EBA0)
     */
    void Push() override;

    /**
     * Address: 0x0047EBB0 (FUN_0047EBB0)
     */
    void SelectEvent(HANDLE ev) override;

    /**
     * Address: 0x0047EBC0 (FUN_0047EBC0, emit `Func3`)
     *
     * What it does:
     * Returns an empty send-stamp snapshot (`items` empty, duration/end = 0).
     */
    SSendStampView SnapshotSendStamps(int32_t since) override;
  };

  static_assert(sizeof(CNetNullConnector) == 0x4, "CNetNullConnector size must be 0x4");
} // namespace moho
