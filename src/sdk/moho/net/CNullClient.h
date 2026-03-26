#pragma once

#include "CClientBase.h"

namespace moho
{
  class CClientManagerImpl;

  /**
   * VFTABLE: 0x00E16C1C
   * COL:     0x00E6AE88
   */
  class CNullClient : public CClientBase
  {
  public:
    /**
     * Address: <synthetic host-build wrapper>
     *
     * Binary evidence:
     * - 0x0053E330 (FUN_0053E330, CClientManagerImpl::CreateCNullClient)
     *
     * What it does:
     * Wraps `CClientBase` construction for null-client objects; in FA the
     * derived constructor sequence is inlined in manager creation.
     */
    CNullClient(
      int32_t index,
      CClientManagerImpl* manager,
      const char* name,
      int32_t ownerId,
      BVIntSet& commandSources,
      uint32_t sourceId
    );

    /**
     * Address: 0x0053B9A0 (FUN_0053B9A0)
     * Slot: 13
     *
     * What it does:
     * Scalar-deleting virtual teardown entry for null clients.
     */
    ~CNullClient() override;

    /**
     * Address: 0x0053B970 (FUN_0053B970)
     * Slot: 2
     *
     * What it does:
     * Returns constant `0.0f` for null clients.
     */
    float GetStatusMetricA() override;

    /**
     * Address: 0x0053B980 (FUN_0053B980)
     * Slot: 3
     *
     * What it does:
     * Returns constant `0.0f` for null clients.
     */
    float GetStatusMetricB() override;

    /**
     * Address: 0x0053B990 (FUN_0053B990)
     * Slot: 7
     *
     * What it does:
     * Intentionally ignores outgoing message payloads.
     */
    void Process(CMessage& msg) override;

    /**
     * Address: 0x0053D170 (FUN_0053D170)
     * Slot: 15
     *
     * What it does:
     * Logs null-client banner then delegates to `CClientBase::Debug()`.
     */
    void Debug() override;
  };

  static_assert(sizeof(CNullClient) == 0xD8, "CNullClient size must be 0xD8");
} // namespace moho
