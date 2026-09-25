#pragma once

#include <cstdint>

#include "gpg/core/streams/MemBufferStream.h"

namespace moho
{
  class CClientBase;
  struct SClientBottleneckInfo;

  /**
   * VFTABLE: 0x00E4A91C
   * COL:     0x00E9CDCC
   *
   * What the client manager tells the user interface about. Every slot has a
   * no-op default; `CWldUiInterface` below is the implementation the game
   * installs. The argument lists are the binary's: each default body is a bare
   * `ret N`, which fixes the stack bytes each slot takes.
   */
  class IClientMgrUIInterface
  {
  public:
    /**
     * Address: 0x0088B6C0 (FUN_0088B6C0)
     * Address: 0x0088BB90 (FUN_0088BB90)
     *
     * What it does:
     * Restores `??_7IClientMgrUIInterface@Moho@@6B@` in the one instance there
     * is, `sCWldUiInterface` - the two out-of-line emissions of this
     * destructor for that object.
     */
    ~IClientMgrUIInterface();

    /**
     * Address: 0x0088B6D0 (Moho::IClientMgrUIInterface::NoteDisconnect)
     * Slot: 0
     *
     * What it does:
     * Notifies UI that `client` has transitioned to disconnected state.
     */
    virtual void NoteDisconnect(const CClientBase* client);

    /**
     * Address: 0x0088B6E0 (Moho::IClientMgrUIInterface::Func2)
     * Slot: 1
     *
     * What it does:
     * Notifies UI about an eject request from `requester` against `target`.
     */
    virtual void NoteEjectRequest(const CClientBase* requester, const CClientBase* target);

    /**
     * Address: 0x0088B6F0 (Moho::IClientMgrUIInterface::ReceiveChat)
     * Slot: 2
     *
     * What it does:
     * Delivers chat payload bytes received from `sender`. The payload is taken
     * by reference: the default body is `ret 8`, two dwords.
     */
    virtual void ReceiveChat(const CClientBase* sender, const gpg::MemBuffer<const char>& data);

    /**
     * Address: 0x0088B700 (Moho::IClientMgrUIInterface::NoteGameSpeedChange)
     * Slot: 3
     *
     * What it does:
     * Notifies UI that game speed arbitration selected `gameSpeed`, requested by
     * `client` (`ret 8`; `CClientBase::ApplyIncomingGameSpeedRequest` pushes the
     * rate and then itself at 0x0053E844/0x0053E84A).
     */
    virtual void NoteGameSpeedChanged(const CClientBase* client, std::int32_t gameSpeed);

    /**
     * Address: 0x0088B710 (Moho::IClientMgrUIInterface::ReportBottleneck)
     * Slot: 4
     *
     * What it does:
     * Notifies UI of the client that is holding the game back (`ret 4`).
     */
    virtual void ReportBottleneck(const SClientBottleneckInfo& info);

    /**
     * Address: 0x0088B720 (Moho::IClientMgrUIInterface::ReportBottleneckCleared)
     * Slot: 5
     */
    virtual void ReportBottleneckCleared();
  };

  /**
   * VFTABLE: 0x00E4A938 (`??_7CWldUiInterface@Moho@@6B@`, 6 slots)
   *
   * The game's user-interface side of the client manager: posts disconnect
   * notices, chat and game-speed changes to the main thread and forwards
   * bottleneck reports to GPGNet. `func_DoPreload` installs the one instance,
   * `sCWldUiInterface`, on the session's client manager.
   */
  class CWldUiInterface final : public IClientMgrUIInterface
  {
  public:
    /**
     * Address: 0x0088B810 (FUN_0088B810, Moho::CWldUiInterface::NoteDisconnect)
     * Slot: 0
     */
    void NoteDisconnect(const CClientBase* client) override;

    /**
     * Address: 0x0088B870 (FUN_0088B870, Moho::CWldUiInterface::Func2)
     * Slot: 1
     *
     * What it does:
     * Nothing: the override is a bare `ret 8`, separate from the base's.
     */
    void NoteEjectRequest(const CClientBase* requester, const CClientBase* target) override;

    /**
     * Address: 0x0088B880 (FUN_0088B880, Moho::CWldUiInterface::ReceiveChat)
     * Slot: 2
     */
    void ReceiveChat(const CClientBase* sender, const gpg::MemBuffer<const char>& data) override;

    /**
     * Address: 0x0088B960 (FUN_0088B960, Moho::CWldUiInterface::NoteGameSpeedChanged)
     * Slot: 3
     */
    void NoteGameSpeedChanged(const CClientBase* client, std::int32_t gameSpeed) override;

    /**
     * Address: 0x0088B9B0 (FUN_0088B9B0, Moho::CWldUiInterface::ReportBottleneck)
     * Slot: 4
     */
    void ReportBottleneck(const SClientBottleneckInfo& info) override;

    /**
     * Address: 0x0088B9C0 (FUN_0088B9C0, Moho::CWldUiInterface::ReportBottleneckCleared)
     * Slot: 5
     */
    void ReportBottleneckCleared() override;
  };

  /**
   * The installed user-interface side of the client manager (0x00F5B6E0).
   * `func_DoPreload` (`FUN_0088BEE0`) hands its address to
   * `IClientManager::SetUIInterface`.
   */
  extern CWldUiInterface sCWldUiInterface;
} // namespace moho
