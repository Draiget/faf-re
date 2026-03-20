#pragma once

#include "CClientBase.h"
#include "IMessageReceiver.h"

namespace moho
{
  class INetConnection;

  /**
   * VFTABLE (IClient):          0x00E16CF4
   * VFTABLE (IMessageReceiver): 0x00E16D38
   * COL:                        0x00E6AD78
   */
  class CNetClient : public CClientBase, public IMessageReceiver
  {
  public:
    /**
     * Address: 0x0053BB60 (FUN_0053BB60)
     * Address: 0x10129420 (sub_10129420)
     *
     * What it does:
     * Builds a network-backed client and registers its receiver ranges
     * on the underlying net-connection dispatcher.
     */
    CNetClient(
      int32_t index,
      CClientManagerImpl* manager,
      const char* name,
      LaunchInfoBase* launchInfo,
      BVIntSet& commandSources,
      uint32_t sourceId,
      INetConnection* connection
    );

    /**
     * Address: 0x0053BC20 (FUN_0053BC20)
     * Address: 0x101294E0 (sub_101294E0)
     * Slot: 13 (IClient path)
     */
    ~CNetClient() override;

    /**
     * Address: 0x0053DC30 (FUN_0053DC30)
     * Address: 0x1012AFF0 (sub_1012AFF0)
     * Slot: 2
     *
     * What it does:
     * Returns transport ping metric, or `0.0f` when no connection is bound.
     */
    float GetStatusMetricA() override;

    /**
     * Address: 0x0053DCC0 (FUN_0053DCC0)
     * Address: 0x1012B080 (sub_1012B080)
     * Slot: 3
     *
     * What it does:
     * Returns transport elapsed-time metric, or `-1.0f` when disconnected.
     */
    float GetStatusMetricB() override;

    /**
     * Address: 0x0053DD60 (FUN_0053DD60)
     * Address: 0x1012B120 (sub_1012B120)
     * Slot: 7
     *
     * What it does:
     * Sends one message to the bound connection while recording outbound
     * send-stamp stats.
     */
    void Process(CMessage& msg) override;

    /**
     * Address: 0x0053DE20 (FUN_0053DE20)
     * Address: 0x1012B1D0 (sub_1012B1D0)
     * Slot: 14
     *
     * What it does:
     * Schedules underlying connection teardown and clears local pointer.
     */
    void Open() override;

    /**
     * Address: 0x0053DE50 (FUN_0053DE50)
     * Address: 0x1012B200 (sub_1012B200)
     * Slot: 15
     *
     * What it does:
     * Dumps net-client header line, then delegates to base debug dump.
     */
    void Debug() override;

    /**
     * Address: 0x0053DE70 (FUN_0053DE70)
     * Address: 0x1012B220 (sub_1012B220)
     * Slot: 0 (IMessageReceiver path)
     *
     * What it does:
     * Receives inbound network message traffic, stamps it as inbound,
     * and forwards into shared client-base message processing.
     */
    void ReceiveMessage(CMessage* message, CMessageDispatcher* dispatcher) override;

  public:
    INetConnection* mConnection{nullptr}; // 0x0E4
  };

  static_assert(sizeof(CNetClient) == 0xE8, "CNetClient size must be 0xE8");
} // namespace moho
