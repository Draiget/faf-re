#pragma once

#include <cstddef>

#include "moho/containers/TDatList.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  enum ECommandEvent : int;
  enum EUnitCommandQueueStatus : int;

  class Broadcaster : public TDatList<Broadcaster, void>
  {
  public:
    /**
     * Address: 0x006E94A0 (FUN_006E94A0,
     * ?BroadcastEvent@?$Broadcaster@W4ECommandEvent@Moho@@@Moho@@IAEXW4ECommandEvent@2@@Z)
     *
     * What it does:
     * Broadcasts one command event to all linked listeners while preserving
     * iteration safety when listeners relink/unlink during callback.
     */
    void BroadcastEvent(ECommandEvent event);

    /**
     * Address: 0x006F8070 (FUN_006F8070,
     * ?BroadcastEvent@?$Broadcaster@W4EUnitCommandQueueStatus@Moho@@@Moho@@IAEXW4EUnitCommandQueueStatus@2@@Z)
     *
     * What it does:
     * Broadcasts one queue-status event to all linked listeners while
     * preserving iteration safety when listeners relink/unlink during callback.
     */
    void BroadcastEvent(EUnitCommandQueueStatus event);
  };

  static_assert(offsetof(Broadcaster, mPrev) == 0x00, "Broadcaster::mPrev offset must be 0x00");
  static_assert(offsetof(Broadcaster, mNext) == 0x04, "Broadcaster::mNext offset must be 0x04");
  static_assert(sizeof(Broadcaster) == 0x08, "Broadcaster size must be 0x08");

  template <class TEvent>
  class BroadcasterEventTag : public Broadcaster
  {};

  static_assert(
    sizeof(BroadcasterEventTag<ECommandEvent>) == sizeof(Broadcaster),
    "BroadcasterEventTag<ECommandEvent> size must match Broadcaster"
  );

  /**
   * Address: 0x006F9210 (FUN_006F9210, sub_6F9210)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Broadcaster< EUnitCommandQueueStatus >` event-link family.
   */
  gpg::RType* register_Broadcaster_EUnitCommandQueueStatus_RType();

  /**
   * Address: 0x006F9270 (FUN_006F9270, sub_6F9270)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Listener< EUnitCommandQueueStatus >` event-link family.
   */
  gpg::RType* register_Listener_EUnitCommandQueueStatus_RType();

  /**
   * Address: 0x00BD95D0 (FUN_00BD95D0, sub_BD95D0)
   *
   * What it does:
   * Runs broadcaster status-type registration and queues its shutdown cleanup
   * through `atexit`.
   */
  int register_Broadcaster_EUnitCommandQueueStatus_RType_AtExit();

  /**
   * Address: 0x006EBDF0 (FUN_006EBDF0, sub_6EBDF0)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Broadcaster< ECommandEvent >` event-link family.
   */
  gpg::RType* register_Broadcaster_ECommandEvent_RType();

  /**
   * Address: 0x005F4A70 (FUN_005F4A70, register_Listener_ECommandEvent_RType)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Listener< ECommandEvent >` event-link family.
   */
  gpg::RType* register_Listener_ECommandEvent_RType();

  /**
   * Address: 0x00BD8FD0 (FUN_00BD8FD0, sub_BD8FD0)
   *
   * What it does:
   * Runs broadcaster command-event type registration and queues shutdown
   * cleanup via `atexit`.
   */
  int register_Broadcaster_ECommandEvent_RType_AtExit();

  /**
   * Address: 0x00BD95F0 (FUN_00BD95F0, sub_BD95F0)
   *
   * What it does:
   * Runs listener status-type registration and queues its shutdown cleanup
   * through `atexit`.
   */
  int register_Listener_EUnitCommandQueueStatus_RType_AtExit();
} // namespace moho
