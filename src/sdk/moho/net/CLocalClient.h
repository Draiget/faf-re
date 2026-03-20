#pragma once

#include "CClientBase.h"

namespace moho
{
  class CClientManagerImpl;

  /**
   * VFTABLE: 0x00E16C64
   * COL:     0x00E6AE38
   */
  class CLocalClient : public CClientBase
  {
  public:
    /**
     * Address: <synthetic host-build wrapper>
     *
     * Binary evidence:
     * - 0x0053E180 (FUN_0053E180, CClientManagerImpl::CreateLocalClient)
     * - 0x1012B540 (sub_1012B540, MohoEngine CreateLocalClient equivalent)
     *
     * What it does:
     * Wraps `CClientBase` construction for local client objects; in FA/Moho the
     * derived-constructor sequence is inlined inside `CreateLocalClient`.
     */
    CLocalClient(
      int32_t index,
      CClientManagerImpl* manager,
      const char* name,
      LaunchInfoBase* launchInfo,
      BVIntSet& commandSources,
      uint32_t sourceId
    );

    /**
     * Address: 0x0053BA00 (FUN_0053BA00)
     * Address: 0x10129280 (sub_10129280)
     * Slot: 2
     *
     * float ()
     *
     * IDA signature (FA):
     * double sub_53BA00();
     *
     * IDA signature (MohoEngine):
     * double sub_10129280();
     *
     * What it does:
     * Returns constant `0.0f` for local clients.
     */
    float GetStatusMetricA() override;

    /**
     * Address: 0x0053BA10 (FUN_0053BA10)
     * Address: 0x10129290 (sub_10129290)
     * Slot: 3
     *
     * float ()
     *
     * IDA signature (FA):
     * double Moho::CLocalClient::Func3();
     *
     * IDA signature (MohoEngine):
     * double sub_10129290();
     *
     * What it does:
     * Returns constant `0.0f` for local clients.
     */
    float GetStatusMetricB() override;

    /**
     * Address: 0x0053D190 (FUN_0053D190)
     * Address: 0x1012A920 (sub_1012A920)
     * Slot: 7
     *
     * CMessage &
     *
     * IDA signature (FA):
     * void __thiscall Moho::CLocalClient::Process(Moho::CLocalClient *this, struct_NetworkStruct2 *a2);
     *
     * IDA signature (MohoEngine):
     * void __thiscall sub_1012A920(_DWORD *this, int a2);
     *
     * What it does:
     * Takes manager lock, runs shared base incoming-message processing, and
     * signals current manager event when marshaller has no bound manager.
     */
    void Process(CMessage& msg) override;

    /**
     * Address: 0x0053D220 (FUN_0053D220)
     * Address: 0x1012A9B0 (sub_1012A9B0)
     * Slot: 15
     *
     * void ()
     *
     * IDA signature (FA):
     * int __thiscall sub_53D220(void *this, int a2);
     *
     * IDA signature (MohoEngine):
     * int __thiscall sub_1012A9B0(const char *this, int a2);
     *
     * What it does:
     * Logs local client banner then forwards to `CClientBase::Debug()`.
     */
    void Debug() override;
  };
  static_assert(sizeof(CLocalClient) == 0xD8, "CLocalClient size must be 0xD8");
} // namespace moho
