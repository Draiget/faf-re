#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Client-control/replay control message ids on the shared CMessage byte channel.
   *
   * Binary evidence:
   * - FA 0x0053BF30, MohoEngine 0x101297E0 (CClientBase::Process switch)
   * - FA 0x0053D900 (CReplayClient::Process)
   */
  enum class EClientMsg : uint8_t
  {
    /** Client beat ACK (`clientIndex`, `queuedBeat`). */
    CLIMSG_Ack = 50,

    /** Remote latest dispatched beat update. */
    CLIMSG_Dispatched = 51,

    /** Remote latest available beat update. */
    CLIMSG_Available = 52,

    /** Ready notification. */
    CLIMSG_Ready = 53,

    /** Eject request (`requesterIndex`, `afterBeat`). */
    CLIMSG_Eject = 54,

    /** Chat relay payload bytes. */
    CLIMSG_ReceiveChat = 55,

    /** Adjustable sim-speed update. */
    CLIMSG_AdjustSimSpeed = 56,

    /** Generic int parameter from client manager. */
    CLIMSG_IntParam = 57,
  };
} // namespace moho
