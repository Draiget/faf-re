#pragma once

#include "gpg/core/streams/MemBufferStream.h"

namespace moho
{
  class CClientBase;

  /**
   * VFTABLE: 0x00E4A91C
   * COL:     0x00E9CDCC
   */
  class IClientMgrUIInterface
  {
  public:
    /**
     * Address: 0x0088B6D0 (Moho::IClientMgrUIInterface::NoteDisconnect)
     * Slot: 0
     *
     * What it does:
     * Notifies UI that `client` has transitioned to disconnected state.
     */
    virtual void NoteDisconnect(const CClientBase* client) = 0;

    /**
     * Address: 0x0088B6E0 (Moho::IClientMgrUIInterface::Func2)
     * Slot: 1
     *
     * What it does:
     * Notifies UI about an eject request from `requester` against `target`.
     */
    virtual void NoteEjectRequest(const CClientBase* requester, const CClientBase* target) = 0;

    /**
     * Address: 0x0088B6F0 (Moho::IClientMgrUIInterface::ReceiveChat)
     * Slot: 2
     *
     * What it does:
     * Delivers chat payload bytes received from `sender`.
     */
    virtual void ReceiveChat(const CClientBase* sender, gpg::MemBuffer<const char> data) = 0;

    /**
     * Address: 0x0088B700 (Moho::IClientMgrUIInterface::NoteGameSpeedChange)
     * Slot: 3
     *
     * What it does:
     * Notifies UI that game speed arbitration selected a new active speed.
     */
    virtual void NoteGameSpeedChanged() = 0;

    /**
     * Address: 0x0088B710 (Moho::IClientMgrUIInterface::ReportBottleneck)
     * Slot: 4
     */
    virtual void ReportBottleneck() = 0;

    /**
     * Address: 0x0088B720 (Moho::IClientMgrUIInterface::ReportBottleneckCleared)
     * Slot: 5
     */
    virtual void ReportBottleneckCleared() = 0;
  };
} // namespace moho
